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

"""Multi-token authentication for MCP clients.

Reads token definitions from config.toml [tokens.*] sections.
Each token has: name, token_hash, scopes, read_only, allowed_ips, expires_at.
"""

import contextvars
import hashlib
import hmac
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from typing import Any

from mcp.server.auth.provider import AccessToken

logger = logging.getLogger("zabbix_mcp.token_store")

# Context variable to hold the current token info during a request
current_token_info: contextvars.ContextVar[Any] = contextvars.ContextVar("current_token_info", default=None)
# Context variable to hold client IP for token IP allowlist checks
current_client_ip: contextvars.ContextVar[str | None] = contextvars.ContextVar("current_client_ip", default=None)


# Single source of truth for the v1.31 scope parser - shared with
# zabbix_mcp.server (tools/list filter). Re-exported under the
# leading-underscore module-private names so the rest of this file
# keeps using the same identifiers it had pre-extraction.
from zabbix_mcp.scope_grammar import (
    BUNDLED_PLUGIN_ID as _BUNDLED_PLUGIN_ID,
    parse_token_scopes as _parse_token_scopes,
)


def check_token_authorization(
    server_name: str,
    *,
    tool_prefix: str = "",
    tool_prefixes: list[str] | tuple[str, ...] | None = None,
    tool_name: str | None = None,
    is_write: bool = False,
) -> str | None:
    """Check current token's authorization for a server + tool + write operation.

    *tool_prefix* is the single-prefix form (legacy); *tool_prefixes* is a
    list of prefixes that must ALL be authorized - used by composite
    "view" tools (host_status_get etc.) that internally fan out to
    several Zabbix endpoints (host.get + problem.get + item.get + ...).
    Without the multi-prefix check a token scoped to only "host" could
    pull problems and items via the composite tool that it could not
    pull via problem_get / item_get directly.

    *tool_name* is the canonical tool name (e.g. "host_get") and lets the
    new v1.31 scope grammar match per-tool grants of the form
    ``"tool:host_get"``. When omitted the per-tool path is skipped.

    Returns an error message string if denied, or None if allowed.
    """
    token = current_token_info.get()
    if token is None:
        return None  # No token auth active (e.g. stdio mode)

    # Check allowed_servers
    if token.allowed_servers and "*" not in token.allowed_servers:
        if server_name not in token.allowed_servers:
            return f"Token '{token.name}' is not authorized for server '{server_name}'. Allowed: {', '.join(token.allowed_servers)}"

    # Check scopes (if not wildcard)
    scopes = list(token.scopes or [])
    if scopes and "*" in scopes:
        # Pure wildcard - read_only token still blocks writes (v1.30 semantics).
        if is_write and token.read_only:
            return f"Token '{token.name}' is read-only. Write operations are not allowed."
        return None

    if not scopes:
        # No scopes at all -> v1.30 behaviour: full access capped by read_only flag.
        if is_write and token.read_only:
            return f"Token '{token.name}' is read-only. Write operations are not allowed."
        return None

    # Parse v1.31 grammar.
    parsed = _parse_token_scopes(scopes)
    bundled = _BUNDLED_PLUGIN_ID

    # Per-tool explicit grant (v1.31): bypass everything else.
    if tool_name and tool_name in parsed["tools"]:
        return None

    # Per-plugin grants (v1.31). Bundled tools live under plugin id "zabbix";
    # external plugins land under their own id once the loader ships.
    if bundled in parsed["plugins_full"]:
        return None
    if is_write and bundled in parsed["plugins_write"]:
        return None
    if not is_write and bundled in parsed["plugins_read"]:
        return None
    if not is_write and bundled in parsed["plugins_write"]:
        # write grant subsumes read access
        return None

    # Legacy (v1.30) prefix / group scope. Per-token read_only still applies
    # to legacy tokens for backwards compat.
    if is_write and token.read_only:
        return f"Token '{token.name}' is read-only. Write operations are not allowed."

    if not parsed["legacy"]:
        # All scopes were v1.31 forms and none matched - block.
        return _scope_denied_message(token, parsed, tool_prefix, tool_prefixes, tool_name)

    from zabbix_mcp.config import _expand_tool_groups
    allowed_prefixes = set(_expand_tool_groups(parsed["legacy"]))

    if tool_prefixes:
        missing = [p for p in tool_prefixes if p not in allowed_prefixes]
        if missing:
            return (
                f"Token '{token.name}' scope does not include {missing!r} "
                f"(this tool combines data from {sorted(set(tool_prefixes))!r}). "
                f"Allowed scopes: {', '.join(scopes)}"
            )
    elif tool_prefix and tool_prefix not in allowed_prefixes:
        return _scope_denied_message(token, parsed, tool_prefix, tool_prefixes, tool_name)

    return None


def _scope_denied_message(token, parsed, tool_prefix, tool_prefixes, tool_name) -> str:
    """Build a single denial message that mentions whichever scope shape applies."""
    bits = []
    if tool_name:
        bits.append(f"tool '{tool_name}'")
    if tool_prefix:
        bits.append(f"prefix '{tool_prefix}'")
    if tool_prefixes:
        bits.append(f"prefixes {sorted(set(tool_prefixes))!r}")
    needed = " / ".join(bits) or "this tool"
    return (
        f"Token '{token.name}' scope does not allow {needed}. "
        f"Granted scopes: {', '.join(token.scopes or []) or '(none)'}."
    )


@dataclass
class TokenInfo:
    """Parsed token definition from config."""

    id: str  # config key (e.g. "ci_pipeline")
    name: str  # display name
    token_hash: str  # "sha256:hexdigest"
    token_prefix: str = ""  # first 12 chars of hash for display
    scopes: list[str] = field(default_factory=lambda: ["*"])  # ["monitoring", "alerts"] or ["*"]
    read_only: bool = True
    allowed_ips: list[str] | None = None  # CIDR ranges
    allowed_servers: list[str] = field(default_factory=lambda: ["*"])  # ["production"] or ["*"] for all
    expires_at: str | None = None  # ISO 8601
    is_legacy: bool = False
    revoked: bool = False
    # Allow this token to call tools with raw_json=true, which strips the
    # [System: ...] prompt-injection mitigation preamble from responses.
    # Default off because the preamble is a defense-in-depth measure for
    # LLM clients - operators must explicitly opt a token in for use by
    # programmatic / non-LLM consumers (Python scripts, n8n workflows).
    allow_raw_json: bool = False
    # Runtime stats (in-memory only, not persisted)
    last_used_at: str | None = None
    last_used_ip: str | None = None
    use_count: int = 0

    @property
    def is_expired(self) -> bool:
        """Whether this token's expires_at is in the past.

        Used by the admin portal token list to render an Expired
        badge instead of Active. Returns False when expires_at is
        unset or unparseable - the runtime auth check
        (is_authorized) is the canonical place we reject expired
        tokens; this is just a UX hint for the operator.
        """
        if not self.expires_at:
            return False
        try:
            return datetime.fromisoformat(self.expires_at) < datetime.now()
        except (ValueError, TypeError):
            return False


class TokenStore:
    """In-memory token store loaded from config.

    Supports hot-reload: call load_from_config() to update tokens
    without restart.
    """

    def __init__(self) -> None:
        self._tokens: dict[str, TokenInfo] = {}  # hash -> TokenInfo
        self._by_id: dict[str, TokenInfo] = {}  # id -> TokenInfo

    def load_from_config(self, tokens_config: dict[str, dict]) -> None:
        """Load/reload tokens from the [tokens.*] config sections.

        tokens_config is like:
        {
            "ci_pipeline": {"name": "CI", "token_hash": "sha256:abc...", ...},
            "claude": {"name": "Claude", "token_hash": "sha256:def...", ...},
        }

        Preserves runtime stats (use_count, last_used) for existing tokens.
        """
        new_tokens: dict[str, TokenInfo] = {}
        new_by_id: dict[str, TokenInfo] = {}

        for token_id, cfg in tokens_config.items():
            token_hash = cfg.get("token_hash", "")
            if not token_hash:
                logger.warning("Token '%s' has no token_hash, skipping", token_id)
                continue

            # Parse allowed_ips: accept string (newline/comma separated) or list
            raw_ips = cfg.get("allowed_ips")
            allowed_ips = None
            if raw_ips:
                if isinstance(raw_ips, str):
                    allowed_ips = [
                        s.strip() for s in raw_ips.replace(",", "\n").split("\n")
                        if s.strip()
                    ]
                elif isinstance(raw_ips, list):
                    allowed_ips = raw_ips

            hash_value = token_hash.split(":", 1)[1] if ":" in token_hash else token_hash
            # Last-4 suffix instead of first-12 prefix - reported
            # 2026-05-04 as a "this column is too wide" issue on
            # /tokens. Last 4 hex chars are still enough to tell
            # tokens apart at a glance, and the leading "..." flips
            # the visual cue so the eye reads the part that varies.
            token_prefix = "..." + hash_value[-4:]

            # allow_raw_json must be a real bool; reject string ``"true"`` /
            # ``"false"`` etc. that an operator might typo into config.toml.
            # bool("false") is True so a quiet bool() cast would silently
            # opt-in - default to False on anything that is not exactly
            # True or False, with a warning so the operator notices.
            raw_arj = cfg.get("allow_raw_json", False)
            if isinstance(raw_arj, bool):
                allow_raw_json_val = raw_arj
            else:
                logger.warning(
                    "Token '%s' has non-boolean allow_raw_json=%r in config; "
                    "treating as False (use plain `true` / `false`)",
                    token_id, raw_arj,
                )
                allow_raw_json_val = False

            info = TokenInfo(
                id=token_id,
                name=cfg.get("name", token_id),
                token_hash=token_hash,
                token_prefix=token_prefix,
                scopes=cfg.get("scopes", ["*"]),
                read_only=cfg.get("read_only", True),
                allowed_ips=allowed_ips,
                allowed_servers=cfg.get("allowed_servers", ["*"]),
                expires_at=cfg.get("expires_at"),
                is_legacy=cfg.get("is_legacy", False),
                revoked=not cfg.get("is_active", True),
                allow_raw_json=allow_raw_json_val,
            )

            # Preserve runtime stats from existing token
            existing = self._by_id.get(token_id)
            if existing is not None and existing.token_hash == token_hash:
                info.last_used_at = existing.last_used_at
                info.last_used_ip = existing.last_used_ip
                info.use_count = existing.use_count

            new_tokens[token_hash] = info
            new_by_id[token_id] = info

        self._tokens = new_tokens
        self._by_id = new_by_id
        logger.info("Loaded %d tokens from config", len(new_tokens))

    def load_legacy_token(self, auth_token: str) -> None:
        """Import a legacy auth_token (raw value) as a token entry.

        Called during migration when [tokens] section doesn't exist yet.
        """
        hex_hash = hashlib.sha256(auth_token.encode()).hexdigest()
        token_hash = f"sha256:{hex_hash}"
        # Match the suffix-style display used by load_from_config -
        # legacy entries were the only place still showing the
        # leading-prefix pattern.
        prefix = "..." + hex_hash[-4:]
        info = TokenInfo(
            id="_legacy",
            name="Legacy Token",
            token_hash=token_hash,
            token_prefix=prefix,
            scopes=["*"],
            read_only=False,
            is_legacy=True,
        )
        self._tokens[token_hash] = info
        self._by_id["_legacy"] = info
        logger.info("Loaded legacy auth token")

    def verify(self, raw_token: str, client_ip: str | None = None) -> TokenInfo | None:
        """Verify a bearer token. Returns TokenInfo if valid, None if invalid.

        Checks:
        1. Hash matches a known token
        2. Token is not expired
        3. Client IP is in allowed_ips (if configured)

        Updates runtime stats on success.
        Uses constant-time comparison via hmac.compare_digest on hashes.
        """
        computed_hash = f"sha256:{hashlib.sha256(raw_token.encode()).hexdigest()}"

        # Look up by hash in dict (O(1) lookup, no timing leak on key presence)
        info = self._tokens.get(computed_hash)
        if info is None:
            return None

        # Constant-time comparison as an extra safety layer
        if not hmac.compare_digest(computed_hash, info.token_hash):
            return None

        # Check revoked
        if info.revoked:
            logger.warning("Token '%s' is revoked", info.id)
            return None

        # Check expiration
        if info.expires_at:
            try:
                expires = datetime.fromisoformat(info.expires_at)
                if expires.tzinfo is None:
                    expires = expires.replace(tzinfo=timezone.utc)
                if datetime.now(timezone.utc) > expires:
                    logger.warning("Token '%s' has expired (at %s)", info.id, info.expires_at)
                    return None
            except ValueError:
                logger.warning("Token '%s' has invalid expires_at: %s", info.id, info.expires_at)

        # Check allowed IPs
        if info.allowed_ips and client_ip:
            try:
                addr = ip_address(client_ip)
                allowed = False
                for cidr in info.allowed_ips:
                    try:
                        if addr in ip_network(cidr, strict=False):
                            allowed = True
                            break
                    except ValueError:
                        logger.warning("Invalid CIDR in token '%s': %s", info.id, cidr)
                if not allowed:
                    logger.warning(
                        "Token '%s' rejected: IP %s not in allowed_ips", info.id, client_ip
                    )
                    return None
            except ValueError:
                logger.warning("Invalid client IP for token check: %s", client_ip)

        # Update runtime stats
        info.use_count += 1
        info.last_used_at = datetime.now(timezone.utc).isoformat()
        if client_ip:
            info.last_used_ip = client_ip

        return info

    def list_tokens(self) -> list[TokenInfo]:
        """Return all tokens (for admin UI)."""
        return list(self._by_id.values())

    def get_token(self, token_id: str) -> TokenInfo | None:
        """Get a token by its config ID."""
        return self._by_id.get(token_id)

    @property
    def token_count(self) -> int:
        """Number of active tokens."""
        return len(self._by_id)

    @staticmethod
    def generate_token() -> tuple[str, str]:
        """Generate a new token. Returns (raw_token, hash_string).

        Format: zmcp_ + 64 hex chars (32 bytes)
        Hash: sha256:<hexdigest>

        The raw token is shown once to the user. Only the hash is stored.
        """
        import secrets

        raw = "zmcp_" + secrets.token_hex(32)
        hash_str = f"sha256:{hashlib.sha256(raw.encode()).hexdigest()}"
        return raw, hash_str


class MultiTokenVerifier:
    """MCP auth verifier using TokenStore.

    Replaces the old single-token _BearerTokenVerifier.
    Implements the same interface: async verify_token(token) -> AccessToken | None
    """

    def __init__(self, token_store: TokenStore) -> None:
        self._store = token_store

    async def verify_token(self, token: str) -> AccessToken | None:
        """Verify a bearer token for MCP authentication.

        Returns AccessToken with scopes from the token definition.
        """
        # Read client IP from context (set by ASGI middleware)
        client_ip = current_client_ip.get()
        info = self._store.verify(token, client_ip=client_ip)
        if info is None:
            return None
        # Store token info in context for server restriction checks in tool handlers
        current_token_info.set(info)
        return AccessToken(
            token=token,
            client_id=info.name,
            scopes=info.scopes,
            expires_at=int(time.time()) + 86400,
        )
