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

"""Admin portal views for OAuth registered clients.

The embedded OAuth 2.1 authorization server keeps a record of every
client that ever called ``POST /register`` (RFC 7591 dynamic client
registration) in ``[oauth_clients.<id>]`` config sections so the
operator has a clear, auditable view of "who can ask my operators
to log in".  The pages here let the operator:

* see the registered clients,
* drill into one to inspect its redirect URIs / scopes / registration
  time / live token count,
* revoke a client (deletes the config entry and revokes any
  outstanding access / refresh tokens it holds).

When ``[oauth].enabled = false`` the page still loads but renders
an empty-state explainer that points at ``docs/OAUTH.md`` -- there is
no error, just no data.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

from zabbix_mcp.admin.audit_writer import write_audit
from zabbix_mcp.admin.config_writer import (
    load_config_document,
    remove_config_table,
    TOMLKIT_AVAILABLE,
)

logger = logging.getLogger("zabbix_mcp.admin")


def _ts_human(ts: int | None) -> str:
    """Render a Unix epoch as ``YYYY-MM-DD HH:MM UTC`` for the table."""
    if not ts:
        return ""
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except (ValueError, TypeError, OSError):
        return ""


def _list_registered_clients(admin_app) -> list[dict]:
    """Read [oauth_clients.*] from config.toml and join with live token counts."""
    if not TOMLKIT_AVAILABLE:
        return []
    try:
        doc = load_config_document(admin_app.config_path)
    except Exception as exc:
        logger.warning("oauth_clients: cannot load config: %s", exc)
        return []

    raw = doc.get("oauth_clients", {}) or {}
    provider = admin_app.oauth_provider

    rows: list[dict] = []
    for cid, body in raw.items():
        body = dict(body)
        ru = body.get("redirect_uris") or []
        if isinstance(ru, str):
            ru = [ru]

        access_count = 0
        refresh_count = 0
        if provider is not None:
            try:
                access_count = sum(
                    1 for at in provider._access_tokens.values()
                    if str(getattr(at, "client_id", "")) == cid
                )
                refresh_count = sum(
                    1 for rt in provider._refresh_tokens.values()
                    if str(getattr(rt, "client_id", "")) == cid
                )
            except Exception:
                pass

        rows.append({
            "id": cid,
            "name": body.get("client_name") or cid,
            "redirect_uris": [str(u) for u in ru],
            "scope": body.get("scope") or "",
            "grant_types": body.get("grant_types") or [],
            "token_endpoint_auth_method": body.get("token_endpoint_auth_method") or "none",
            "client_id_issued_at": body.get("client_id_issued_at"),
            "issued_human": _ts_human(body.get("client_id_issued_at")),
            "active_access_tokens": access_count,
            "active_refresh_tokens": refresh_count,
            "allowed_ips": list(body.get("allowed_ips") or []),
            "access_token_ttl_seconds": body.get("access_token_ttl_seconds") or "",
            "refresh_token_ttl_seconds": body.get("refresh_token_ttl_seconds") or "",
        })
    rows.sort(key=lambda r: r["client_id_issued_at"] or 0, reverse=True)
    return rows


async def oauth_clients_list(request: Request) -> Response:
    """GET /oauth-clients -- list all registered OAuth clients."""
    admin_app = request.app.state.admin_app
    session = admin_app.require_auth(request)
    if not session:
        return RedirectResponse("/login", status_code=303)

    oauth_enabled = bool(getattr(admin_app.config.oauth, "enabled", False))
    clients = _list_registered_clients(admin_app)

    return admin_app.render("oauth_clients/list.html", request, {
        "active": "oauth-clients",
        "page_title": "OAuth Clients",
        "oauth_enabled": oauth_enabled,
        "clients": clients,
        "public_url": (getattr(admin_app.config.server, "public_url", "") or "").rstrip("/"),
        "can_revoke": session.role in ("admin", "operator"),
        "can_enable": session.role == "admin",
    })


_SCOPE_DESCRIPTIONS: dict[str, str] = {
    "*":               "Full access to every tool (read + write).",
    "monitoring":      "Read live state: hosts, problems, items, triggers, history, graphs.",
    "data_collection": "Read templates, value maps, dashboards.",
    "alerts":          "Read action definitions, alerts, media types, scripts.",
    "users":           "Read or modify Zabbix users, groups, roles, MFA. High privilege.",
    "administration":  "Read or modify housekeeping, proxies, audit log, server settings. High privilege.",
    "extensions":      "Server-side analytics: graph_render, anomaly_detect, capacity_forecast, problem_active_get, report_generate, health_check.",
}


def _scope_catalog(active_scopes: list[str]) -> list[dict]:
    """Build the per-scope checkbox catalog for the detail page."""
    from zabbix_mcp.config import TOOL_GROUPS
    rows: list[dict] = []
    active_set = set(active_scopes or [])
    for sid in ["*"] + list(TOOL_GROUPS.keys()):
        rows.append({
            "id": sid,
            "label": "Full access (all tools)" if sid == "*" else sid.replace("_", " ").title(),
            "description": _SCOPE_DESCRIPTIONS.get(sid, "Tool group."),
            "checked": sid in active_set,
            "is_wildcard": sid == "*",
        })
    return rows


async def oauth_client_detail(request: Request) -> Response:
    """GET /oauth-clients/<id> -- single registered client."""
    admin_app = request.app.state.admin_app
    session = admin_app.require_auth(request)
    if not session:
        return RedirectResponse("/login", status_code=303)

    client_id = request.path_params.get("client_id", "")
    rows = _list_registered_clients(admin_app)
    client = next((r for r in rows if r["id"] == client_id), None)
    if client is None:
        return admin_app.flash_redirect(
            "/oauth-clients", "OAuth client not found.", flash_type="warning",
        )

    active_scopes = (client["scope"] or "").split() or ["*"]
    cfg_oauth = admin_app.config.oauth
    return admin_app.render("oauth_clients/detail.html", request, {
        "active": "oauth-clients",
        "page_title": f"OAuth Client: {client['name']}",
        "client": client,
        "scope_catalog": _scope_catalog(active_scopes),
        "default_access_ttl": cfg_oauth.access_token_ttl_seconds,
        "default_refresh_ttl": cfg_oauth.refresh_token_ttl_seconds,
        "can_edit": session.role in ("admin", "operator"),
        "can_revoke": session.role in ("admin", "operator"),
    })


async def oauth_client_scope_update(request: Request) -> Response:
    """POST /oauth-clients/<id>/scope -- replace the client's scope grant."""
    admin_app = request.app.state.admin_app
    session = admin_app.require_auth(request)
    if not session:
        return RedirectResponse("/login", status_code=303)
    if session.role not in ("admin", "operator"):
        return admin_app.flash_redirect(
            f"/oauth-clients/{request.path_params.get('client_id', '')}",
            "You do not have permission to edit OAuth client scopes.",
            flash_type="danger",
        )

    client_id = request.path_params.get("client_id", "")
    if not TOMLKIT_AVAILABLE:
        return admin_app.flash_redirect(
            "/oauth-clients",
            "Config writer unavailable; cannot edit OAuth client scopes.",
            flash_type="danger",
        )

    form = await request.form()
    scopes = [s for s in form.getlist("scope") if s]
    if not scopes:
        return admin_app.flash_redirect(
            f"/oauth-clients/{client_id}",
            "Pick at least one scope (or revoke the client to remove it entirely).",
            flash_type="warning",
        )

    # Mutate the in-memory provider client so the next /authorize from
    # this client uses the new scope. Updating just config.toml without
    # this would require a full server restart.
    provider = admin_app.oauth_provider
    if provider is not None:
        ci = provider._clients.get(client_id)
        if ci is not None:
            ci.scope = " ".join(scopes)

    # Persist to config so the change survives restart.
    try:
        from zabbix_mcp.admin.config_writer import (
            load_config_document, save_config_document,
        )
        doc = load_config_document(admin_app.config_path)
        section = doc.get("oauth_clients", {})
        if client_id in section:
            section[client_id]["scope"] = " ".join(scopes)
            save_config_document(admin_app.config_path, doc)
    except Exception as exc:
        logger.warning("Could not persist scope change for %s: %s", client_id, exc)
        return admin_app.flash_redirect(
            f"/oauth-clients/{client_id}",
            f"Failed to write scope change to config: {exc}",
            flash_type="danger",
        )

    write_audit(
        action="oauth_client.scope_update",
        user=session.user,
        target_type="oauth_client",
        target_id=client_id,
        details={"new_scope": " ".join(scopes)},
        ip=request.client.host if request.client else "",
    )
    return admin_app.flash_redirect(
        f"/oauth-clients/{client_id}",
        f"Scope updated to: {' '.join(scopes)}.",
        flash_type="success",
    )


async def oauth_client_settings_update(request: Request) -> Response:
    """POST /oauth-clients/<id>/settings -- update TTL + IP allowlist."""
    admin_app = request.app.state.admin_app
    session = admin_app.require_auth(request)
    if not session:
        return RedirectResponse("/login", status_code=303)
    if session.role not in ("admin", "operator"):
        return admin_app.flash_redirect(
            f"/oauth-clients/{request.path_params.get('client_id', '')}",
            "You do not have permission to edit OAuth client settings.",
            flash_type="danger",
        )

    client_id = request.path_params.get("client_id", "")
    if not TOMLKIT_AVAILABLE:
        return admin_app.flash_redirect(
            "/oauth-clients",
            "Config writer unavailable; cannot edit OAuth client settings.",
            flash_type="danger",
        )

    form = await request.form()

    # Validate IP allowlist - one CIDR / IP per line, blanks ignored.
    raw_ips = str(form.get("allowed_ips", "") or "").strip()
    allowed_ips: list[str] = []
    if raw_ips:
        from ipaddress import ip_network
        for line in raw_ips.splitlines():
            entry = line.strip()
            if not entry:
                continue
            try:
                ip_network(entry, strict=False)
            except ValueError as exc:
                return admin_app.flash_redirect(
                    f"/oauth-clients/{client_id}",
                    f"Invalid IP / CIDR: '{entry}' ({exc})",
                    flash_type="danger",
                )
            allowed_ips.append(entry)

    # Validate TTLs - blank means \"use [oauth] default\".
    def _ttl(field: str, lower: int, upper: int) -> int | None:
        v = str(form.get(field, "") or "").strip()
        if not v:
            return None
        try:
            n = int(v)
        except ValueError:
            return -1
        if n < lower or n > upper:
            return -1
        return n

    access_ttl = _ttl("access_token_ttl_seconds", 60, 30 * 24 * 3600)
    if access_ttl == -1:
        return admin_app.flash_redirect(
            f"/oauth-clients/{client_id}",
            "Access-token TTL must be an integer between 60 and 2592000 (30 days).",
            flash_type="danger",
        )
    refresh_ttl = _ttl("refresh_token_ttl_seconds", 60, 365 * 24 * 3600)
    if refresh_ttl == -1:
        return admin_app.flash_redirect(
            f"/oauth-clients/{client_id}",
            "Refresh-token TTL must be an integer between 60 and 31536000 (365 days).",
            flash_type="danger",
        )

    # Apply to live provider so the next /token from this client uses
    # the new bounds without a server restart.
    provider = admin_app.oauth_provider
    if provider is not None:
        ci = provider._clients.get(client_id)
        if ci is not None:
            object.__setattr__(ci, "_allowed_ips", list(allowed_ips))
            if access_ttl is None:
                if hasattr(ci, "_access_ttl"):
                    object.__delattr__(ci, "_access_ttl")
            else:
                object.__setattr__(ci, "_access_ttl", access_ttl)
            if refresh_ttl is None:
                if hasattr(ci, "_refresh_ttl"):
                    object.__delattr__(ci, "_refresh_ttl")
            else:
                object.__setattr__(ci, "_refresh_ttl", refresh_ttl)

    # Persist to config.toml for restart survival.
    try:
        from zabbix_mcp.admin.config_writer import (
            load_config_document, save_config_document,
        )
        import tomlkit
        doc = load_config_document(admin_app.config_path)
        section = doc.get("oauth_clients", {})
        if client_id in section:
            row = section[client_id]
            row["allowed_ips"] = tomlkit.array(str(allowed_ips))
            for key, val in (
                ("access_token_ttl_seconds", access_ttl),
                ("refresh_token_ttl_seconds", refresh_ttl),
            ):
                if val is None:
                    if key in row:
                        del row[key]
                else:
                    row[key] = val
            save_config_document(admin_app.config_path, doc)
    except Exception as exc:
        logger.warning("Could not persist settings for %s: %s", client_id, exc)
        return admin_app.flash_redirect(
            f"/oauth-clients/{client_id}",
            f"Failed to write settings to config: {exc}",
            flash_type="danger",
        )

    write_audit(
        action="oauth_client.settings_update",
        user=session.user,
        target_type="oauth_client",
        target_id=client_id,
        details={
            "allowed_ips": allowed_ips,
            "access_token_ttl_seconds": access_ttl,
            "refresh_token_ttl_seconds": refresh_ttl,
        },
        ip=request.client.host if request.client else "",
    )
    return admin_app.flash_redirect(
        f"/oauth-clients/{client_id}",
        "Client settings updated.",
        flash_type="success",
    )


async def oauth_enable(request: Request) -> Response:
    """POST /oauth-clients/enable -- one-click switch to flip
    [oauth].enabled on plus set [server].public_url, used when the
    operator lands on the empty-state page and would otherwise have
    to hand-edit config.toml. Validates that public_url is HTTPS
    because OAuth over HTTP is not interoperable - ChatGPT custom
    apps and Claude Desktop both refuse plain-HTTP discovery URLs.
    """
    admin_app = request.app.state.admin_app
    session = admin_app.require_auth(request)
    if not session:
        return RedirectResponse("/login", status_code=303)
    if session.role != "admin":
        return admin_app.flash_redirect(
            "/oauth-clients",
            "Only the admin role can change OAuth settings.",
            flash_type="danger",
        )
    if not TOMLKIT_AVAILABLE:
        return admin_app.flash_redirect(
            "/oauth-clients",
            "Cannot edit config: tomlkit not installed.",
            flash_type="danger",
        )

    form = await request.form()
    public_url = str(form.get("public_url", "") or "").strip().rstrip("/")
    dynamic_reg = "dynamic_registration_enabled" in form

    # MUST be HTTPS with a DNS name - OAuth discovery over HTTP fails
    # on every modern MCP client (ChatGPT, Claude Desktop, MCP Inspector
    # all reject cleartext metadata) and public CAs (Let's Encrypt etc.)
    # do not issue TLS certs for raw IPs, so an IP-based URL would also
    # fail at cert verification. Localhost gets a pass for dev / smoke.
    from urllib.parse import urlparse
    import ipaddress
    if not public_url:
        return admin_app.flash_redirect(
            "/oauth-clients",
            "public_url is required - set it to the externally-reachable URL clients will use to reach this server.",
            flash_type="danger",
        )
    parsed = urlparse(public_url)
    if not parsed.hostname:
        return admin_app.flash_redirect(
            "/oauth-clients",
            "public_url has no hostname. Use the form 'https://mcp.example.com' or 'https://mcp.example.com:8080'.",
            flash_type="danger",
        )
    is_localhost = parsed.hostname in ("localhost", "127.0.0.1", "::1")
    if parsed.scheme != "https" and not is_localhost:
        return admin_app.flash_redirect(
            "/oauth-clients",
            f"public_url must use https:// (got {parsed.scheme!r}). OAuth over plain HTTP is rejected by every modern MCP client. Use the install.sh request-tls subcommand for an automatic Let's Encrypt cert, or terminate TLS in a reverse proxy and point public_url at the proxy URL.",
            flash_type="danger",
        )
    # Reject raw IPs - CA-issued certs for IPs are not generally
    # available, and ChatGPT / Claude Desktop refuse self-signed.
    try:
        ipaddress.ip_address(parsed.hostname.strip("[]"))
        is_ip = True
    except ValueError:
        is_ip = False
    if is_ip and not is_localhost:
        return admin_app.flash_redirect(
            "/oauth-clients",
            f"public_url must be a DNS name, not an IP address ({parsed.hostname!r}). Public CAs do not issue TLS certs for raw IPs, so ChatGPT and Claude Desktop will reject the cert chain. Point a DNS name at this host (e.g. mcp.your-domain.tld) and use that.",
            flash_type="danger",
        )
    # Bare hostname (no TLD) cannot get a public cert either.
    if not is_localhost and "." not in parsed.hostname:
        return admin_app.flash_redirect(
            "/oauth-clients",
            f"public_url must be a fully-qualified DNS name like 'mcp.example.com', not the bare hostname {parsed.hostname!r}.",
            flash_type="danger",
        )

    try:
        from zabbix_mcp.admin.config_writer import (
            load_config_document, save_config_document,
        )
        import tomlkit
        doc = load_config_document(admin_app.config_path)

        # [server].public_url
        srv = doc.get("server")
        if srv is None:
            srv = tomlkit.table()
            doc["server"] = srv
        srv["public_url"] = public_url

        # [oauth].enabled = true (+ optional dynamic_registration_enabled)
        oauth = doc.get("oauth")
        if oauth is None:
            oauth = tomlkit.table()
            doc["oauth"] = oauth
        oauth["enabled"] = True
        oauth["dynamic_registration_enabled"] = dynamic_reg

        save_config_document(admin_app.config_path, doc)
    except Exception as exc:
        logger.exception("oauth_enable: failed to write config")
        return admin_app.flash_redirect(
            "/oauth-clients",
            f"Could not save config: {exc}",
            flash_type="danger",
        )

    write_audit(
        "oauth.enable",
        user=session.user,
        details={"public_url": public_url, "dynamic_registration_enabled": dynamic_reg},
        ip=request.client.host if request.client else "unknown",
    )

    # The provider boots from config at startup, so the change only
    # takes effect after the operator restarts the service. Surface
    # that explicitly instead of pretending it just works.
    admin_app.restart_needed = True
    return admin_app.flash_redirect(
        "/oauth-clients",
        f"OAuth enabled. Restart the server to activate: sudo systemctl restart zabbix-mcp-server (or click the 'Restart needed' badge in the header).",
        flash_type="success",
    )


async def oauth_client_revoke(request: Request) -> Response:
    """POST /oauth-clients/<id>/revoke -- delete the registration and
    revoke every access / refresh token the client currently holds."""
    admin_app = request.app.state.admin_app
    session = admin_app.require_auth(request)
    if not session:
        return RedirectResponse("/login", status_code=303)
    if session.role not in ("admin", "operator"):
        return admin_app.flash_redirect(
            "/oauth-clients",
            "You do not have permission to revoke OAuth clients.",
            flash_type="danger",
        )

    client_id = request.path_params.get("client_id", "")
    if not TOMLKIT_AVAILABLE:
        return admin_app.flash_redirect(
            "/oauth-clients",
            "Config writer unavailable; cannot revoke OAuth clients.",
            flash_type="danger",
        )

    # 1. Drop the config entry so re-registration cannot resurrect it
    #    silently.  remove_config_table is idempotent on missing keys.
    try:
        remove_config_table(admin_app.config_path, "oauth_clients", client_id)
    except Exception as exc:
        logger.warning("oauth_clients: could not remove [oauth_clients.%s]: %s", client_id, exc)
        return admin_app.flash_redirect(
            "/oauth-clients",
            f"Failed to remove OAuth client config: {exc}",
            flash_type="danger",
        )

    # 2. Forget the client and every token it holds in the live
    #    provider so the next call from that client is rejected.
    provider = admin_app.oauth_provider
    revoked_at = 0
    revoked_rt = 0
    if provider is not None:
        try:
            provider._clients.pop(client_id, None)
            for tok, at in list(provider._access_tokens.items()):
                if str(getattr(at, "client_id", "")) == client_id:
                    provider._access_tokens.pop(tok, None)
                    provider._access_to_refresh.pop(tok, None)
                    revoked_at += 1
            for tok, rt in list(provider._refresh_tokens.items()):
                if str(getattr(rt, "client_id", "")) == client_id:
                    provider._refresh_tokens.pop(tok, None)
                    revoked_rt += 1
        except Exception as exc:
            logger.warning("oauth_clients: in-memory revoke partial for %s: %s", client_id, exc)

    write_audit(
        action="oauth_client.revoke",
        user=session.user,
        target_type="oauth_client",
        target_id=client_id,
        details={"access_tokens": revoked_at, "refresh_tokens": revoked_rt},
        ip=request.client.host if request.client else "",
    )
    return admin_app.flash_redirect(
        "/oauth-clients",
        f"OAuth client '{client_id}' revoked. {revoked_at} access token(s) and {revoked_rt} refresh token(s) invalidated.",
        flash_type="success",
    )
