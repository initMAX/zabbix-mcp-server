#
# Zabbix MCP Server
# Copyright (C) 2026 initMAX s.r.o.
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License as published by the Free
# Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
# details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#

"""Centralised redaction for audit log payloads.

The audit log is meant for incident review, not secret storage. Per
issue #49 reviewer (musaabhasan) feedback: denied requests should still
be logged so reviewers see attempted misuse, but the **arguments** of
those requests must be stripped of credentials, tokens, and other
secrets - only resource references survive.

This module is the single boundary that enforces that policy. Every
``write_audit(...)`` call routes its ``details`` payload through
``redact()`` before the line hits the audit log. Adding a new
sensitive field type is one edit here, not a sweep through 30+
``write_audit`` call sites.

Three redaction layers:

1. **Key denylist** (case-insensitive, substring match against the key
   name): drops entire field. Catches ``password``, ``secret``,
   ``api_key``, ``client_secret``, ``code_verifier``, ``refresh_token``,
   ``access_token``, ``raw_token``, ``private_key``, ``frontend_password``,
   ``zbx_session``, ...
2. **Token-pattern allow-with-prefix-only**: a few legitimate audit
   fields hold token *hashes* (``token_hash``, ``client_secret_hash``,
   etc.). Those are kept because they are SHA-256 digests, not the
   secrets themselves. Pre-existing rotation tracking relies on the
   prefix; we keep the first 16 chars so the field stays useful for
   correlation but drop the full hex.
3. **Long-string truncation**: any string longer than 512 chars is
   truncated with a ``... [truncated, N more chars]`` marker. Keeps the
   audit log readable when an LLM accidentally pastes a large blob into
   a tool argument.

The redactor is **defensive**: unknown keys pass through unchanged. The
denylist is the only source of truth for what gets dropped, and it is
checked against substring of lower-cased key name to catch typos and
camelCase variants (``apiKey``, ``API_KEY``, ``api_key``).
"""

from __future__ import annotations

from typing import Any

# Substrings (case-insensitive). If a key name contains ANY of these,
# the value is replaced with the redaction marker. Order does not matter.
#
# When extending this list, prefer specific substrings over generic ones
# (e.g. ``api_key`` rather than ``key``) - generic names like ``key``
# would also match legitimate fields like ``hostkey``, ``itemkey``,
# ``key_`` (Zabbix item key field). The audit log loses information
# every time the redactor is too aggressive, so be specific.
_REDACT_KEY_SUBSTRINGS = frozenset({
    # Generic auth credentials
    "password",
    "passwd",
    "secret",
    "api_key",
    "apikey",
    "code_verifier",
    "verifier",
    "refresh_token",
    "access_token",
    "auth_token",
    "raw_token",
    "bearer",   # HTTP Bearer tokens (Authorization headers, etc.)
    "private_key",
    "privkey",
    "frontend_password",
    # Session-scoped secrets
    "zbx_session",
    "session_cookie",
    "cookie",   # Set-Cookie / Cookie headers carry session ids
    "csrf",     # CSRF tokens are session-scoped secrets
    "pkce",
    # MFA / OTP secrets
    "mfa_code",
    "totp",
    "otp_code",
    "totp_secret",
    # Crypto primitives that should never appear in plaintext audit
    "signature",
    "nonce",
    # Zabbix-specific credentials
    "tls_psk",        # PSK identity + secret on host interface
    "psk_identity",
    "snmp_community", # SNMP v1/v2c community string is auth
    "community",      # bare 'community' field on SNMP interface
    "bind_password",  # LDAP bind credential
    "smtp_password",  # mediatype SMTP auth
    "smtp_secret",
    "webhook_secret", # webhook signing secret
    "webhook_token",
    # Database / ODBC connection strings (often embed creds)
    "connect_string",
    "connection_string",
    "dsn",
})

# Keys that ARE allowed to carry secret-like values because they
# already hold a hashed/derived form (not the raw secret). These match
# the key name EXACTLY (case-insensitive) and bypass the substring
# denylist above. Add only after verifying the value is actually a
# digest, not the raw secret.
_HASH_KEYS_EXACT = frozenset({
    "token_hash",
    "password_hash",
    "client_secret_hash",
    "secret_hash",
    "oauth_token_hash",
    "refresh_token_hash",
})

# Maximum length of any string value before truncation marker is added.
_STRING_TRUNCATE_AT = 512

# Marker used when a value is dropped.
_REDACTION_MARKER = "[REDACTED]"


def redact(value: Any, *, key: str | None = None) -> Any:
    """Return a redacted copy of ``value`` safe for the audit log.

    ``key`` is the field name the value was found under (when called
    recursively by the dict / list path). Top-level dict / list calls
    pass ``key=None`` and the caller's keys are walked.

    Behaviour:
    - dict: recurse into each (k, v); apply key-denylist on k
    - list / tuple: recurse element-wise (key context preserved)
    - str: truncate if > ``_STRING_TRUNCATE_AT`` chars
    - everything else: pass through

    Idempotent - calling ``redact(redact(x))`` returns the same shape.
    """
    # Key-driven redaction takes precedence.
    if key is not None:
        kl = key.lower()
        # Hash-bearing keys bypass the substring denylist.
        if kl in _HASH_KEYS_EXACT:
            # Drop the secret-looking suffix. Keep the first 16 chars
            # for correlation (sha256 prefix is enough to identify the
            # token across rotation events).
            if isinstance(value, str) and len(value) > 24:
                return value[:16] + "..."
            return value
        if any(s in kl for s in _REDACT_KEY_SUBSTRINGS):
            return _REDACTION_MARKER

    if isinstance(value, dict):
        return {k: redact(v, key=k) for k, v in value.items()}
    if isinstance(value, list):
        # Lists carry their parent key context (e.g. allowed_ips=[...]).
        return [redact(v, key=key) for v in value]
    if isinstance(value, tuple):
        return tuple(redact(v, key=key) for v in value)
    if isinstance(value, str):
        if len(value) > _STRING_TRUNCATE_AT:
            return value[:_STRING_TRUNCATE_AT] + f"... [truncated, {len(value) - _STRING_TRUNCATE_AT} more chars]"
        return value
    return value
