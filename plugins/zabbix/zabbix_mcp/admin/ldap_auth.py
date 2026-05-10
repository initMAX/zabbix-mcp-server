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

"""LDAP / Active Directory authentication for the admin portal (issue #46).

Lazy import of the ``ldap3`` library so a build that does not need
LDAP boots without the dependency on disk. When the operator wires
up ``[admin.ldap].enabled = true``, the login form falls back to the
LDAP path when local-scrypt auth says "no such user" - **never the
other way round**, so a directory outage does not lock a local-only
admin out of the portal.

Authentication flow:

1. Service binds with ``bind_dn`` / ``bind_password`` (or anonymously)
   and searches under ``base_dn`` for the user that matches
   ``user_search_filter`` substituted with the entered username.
   The filter is parameterised with ``{username}`` which is
   LDAP-escaped before substitution to defeat injection.
2. The returned entry's DN is used for the actual auth bind with
   the user-supplied password.
3. Group membership is resolved by a second search with
   ``group_search_filter`` substituted with ``{user_dn}``; the
   returned group DNs are matched against ``group_to_role`` (first
   match wins, ``admin > operator > viewer > auditor`` precedence).
4. The local ``[admin.users.X]`` config is updated in-memory only
   (no config.toml write - LDAP-provisioned users live for the
   session, not the disk).

Operators on Active Directory: use ``sAMAccountName`` in the user
filter. On OpenLDAP / 389-DS: use ``uid``. Examples in
``docs/LDAP.md``.
"""

from __future__ import annotations

import logging
import ssl
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger("zabbix_mcp.admin.ldap")


@dataclass
class LdapAuthResult:
    """Outcome of an LDAP bind attempt."""

    ok: bool
    user_dn: str = ""
    email: str = ""
    full_name: str = ""
    groups: list[str] | None = None
    role: str = ""
    reason: str = ""


# Role precedence so a user in multiple groups gets the strongest mapped role.
_ROLE_RANK = {"admin": 4, "operator": 3, "viewer": 2, "auditor": 1, "": 0}


def _escape_filter(value: str) -> str:
    """Escape an LDAP filter value per RFC 4515 §3.

    Refuses control characters at all. Returns the escaped string
    suitable for substitution into a filter template.
    """
    out: list[str] = []
    for ch in value:
        cp = ord(ch)
        if cp < 0x20 or cp == 0x7F:
            raise ValueError(f"Control character {hex(cp)} in LDAP filter value")
        if ch == "\\":
            out.append(r"\5c")
        elif ch == "*":
            out.append(r"\2a")
        elif ch == "(":
            out.append(r"\28")
        elif ch == ")":
            out.append(r"\29")
        elif ch == "\x00":
            out.append(r"\00")
        else:
            out.append(ch)
    return "".join(out)


def authenticate(cfg: Any, username: str, password: str) -> LdapAuthResult:
    """Run the LDAP bind flow described in the module docstring.

    ``cfg`` is an :class:`AdminLdapConfig` instance. Returns an
    :class:`LdapAuthResult` populated with the directory's email +
    full name + resolved role on success, or ``ok=False`` with a
    short reason on failure.

    The reason field is operator-readable; never echo it back to the
    end user verbatim (it can leak directory schema). The admin
    login page should show a generic "invalid credentials" message
    and log the detailed reason to ``audit.log`` instead.
    """
    if not cfg.enabled:
        return LdapAuthResult(ok=False, reason="LDAP disabled in config")
    if not cfg.server or not cfg.base_dn:
        return LdapAuthResult(ok=False, reason="LDAP not configured (server/base_dn missing)")
    if not username or not password:
        return LdapAuthResult(ok=False, reason="empty credentials")

    try:
        from ldap3 import Server, Connection, Tls, SUBTREE, SIMPLE, ALL
        from ldap3.core.exceptions import LDAPException
    except ImportError:
        logger.warning(
            "ldap3 library not installed; LDAP authentication is disabled. "
            "Install with: pip install ldap3"
        )
        return LdapAuthResult(ok=False, reason="ldap3 library missing")

    # Build the TLS context. start_tls upgrades a cleartext bind to
    # TLS after the initial connect; ldaps:// is bind-time TLS. CA
    # cert path overrides the system trust when given.
    if cfg.ca_cert:
        tls = Tls(ca_certs_file=cfg.ca_cert, validate=ssl.CERT_REQUIRED)
    else:
        tls = Tls(validate=ssl.CERT_REQUIRED)

    server = Server(cfg.server, tls=tls, get_info=ALL, connect_timeout=cfg.timeout_seconds)

    # Service bind (search account or anonymous).
    try:
        if cfg.bind_dn:
            conn = Connection(
                server, user=cfg.bind_dn, password=cfg.bind_password,
                authentication=SIMPLE, auto_bind=True,
                receive_timeout=cfg.timeout_seconds,
            )
        else:
            conn = Connection(
                server, auto_bind=True,
                receive_timeout=cfg.timeout_seconds,
            )
        if cfg.start_tls and not server.ssl:
            conn.start_tls()
    except LDAPException as e:
        logger.warning("LDAP service bind failed: %s", e)
        return LdapAuthResult(ok=False, reason=f"service bind failed: {e}")

    # User lookup.
    try:
        safe_user = _escape_filter(username)
        user_filter = cfg.user_search_filter.replace("{username}", safe_user)
        conn.search(
            search_base=cfg.base_dn,
            search_filter=user_filter,
            search_scope=SUBTREE,
            attributes=["mail", "displayName", "cn", "givenName", "sn"],
            size_limit=2,
        )
    except (LDAPException, ValueError) as e:
        conn.unbind()
        logger.warning("LDAP user search failed for %r: %s", username, e)
        return LdapAuthResult(ok=False, reason=f"user search failed: {e}")
    if len(conn.entries) == 0:
        conn.unbind()
        return LdapAuthResult(ok=False, reason="user not found in directory")
    if len(conn.entries) > 1:
        conn.unbind()
        return LdapAuthResult(ok=False, reason=f"ambiguous user search (got {len(conn.entries)} matches)")
    user_entry = conn.entries[0]
    user_dn = str(user_entry.entry_dn)
    email = str(getattr(user_entry, "mail", "") or "")
    full_name = (
        str(getattr(user_entry, "displayName", "") or "")
        or str(getattr(user_entry, "cn", "") or "")
        or username
    )

    # Group lookup with the service bind connection (the user DN is
    # known but the password-authn step is still pending).
    groups: list[str] = []
    if cfg.group_to_role:
        try:
            group_filter = cfg.group_search_filter.replace("{user_dn}", user_dn)
            conn.search(
                search_base=cfg.base_dn,
                search_filter=group_filter,
                search_scope=SUBTREE,
                attributes=["cn"],
                size_limit=50,
            )
            for entry in conn.entries:
                groups.append(str(entry.entry_dn))
        except LDAPException as e:
            logger.warning("LDAP group search failed for %r: %s", user_dn, e)

    conn.unbind()

    # Auth bind with the user's actual password.
    try:
        user_conn = Connection(
            server, user=user_dn, password=password,
            authentication=SIMPLE, auto_bind=True,
            receive_timeout=cfg.timeout_seconds,
        )
        if cfg.start_tls and not server.ssl:
            user_conn.start_tls()
        user_conn.unbind()
    except LDAPException as e:
        logger.warning("LDAP user bind failed for %r: %s", user_dn, e)
        return LdapAuthResult(ok=False, reason="invalid credentials")

    # Map first-match-wins group DN to admin role, falling back to
    # default_role when nothing matched.
    role = ""
    for group_dn in groups:
        mapped = cfg.group_to_role.get(group_dn)
        if mapped and _ROLE_RANK.get(mapped, 0) > _ROLE_RANK.get(role, 0):
            role = mapped
    if not role:
        role = cfg.default_role
    if not role:
        return LdapAuthResult(
            ok=False, user_dn=user_dn, email=email, full_name=full_name,
            groups=groups,
            reason="user not in any mapped group and no default_role configured",
        )

    return LdapAuthResult(
        ok=True, user_dn=user_dn, email=email, full_name=full_name,
        groups=groups, role=role,
    )
