#
# Zabbix MCP Server
# Copyright (C) 2026 initMAX s.r.o.
#

"""MCP Token CRUD views — create, list, edit, revoke, delete."""

from __future__ import annotations

import logging

from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

from zabbix_mcp.admin.config_writer import (
    add_config_table,
    load_config_document,
    remove_config_table,
    update_config_section,
    TOMLKIT_AVAILABLE,
)
from zabbix_mcp.admin.audit_writer import write_audit
from zabbix_mcp.config import TOOL_GROUPS
from zabbix_mcp.token_store import TokenStore

logger = logging.getLogger("zabbix_mcp.admin")


def _safe_return_to(raw: str) -> str:
    """Validate a `return_to` redirect target.

    Only accepts a single-slash absolute path pointing at the Client
    Wizard (``/wizard`` or ``/wizard?...``). Everything else - empty
    strings, absolute URLs, ``//host`` protocol-relative URLs,
    ``javascript:`` and other dangerous schemes, and paths that
    do not start with ``/wizard`` - maps to ``""`` so the caller
    falls back to the default post-create view.

    Without this guard, an attacker could craft
    ``/tokens/create?return_to=https://evil/steal`` (or
    ``javascript:fetch(...)``) and leak the freshly-minted raw token
    via the URL fragment the success page appends to the "Continue"
    link (see tokens/create.html).
    """
    if not raw:
        return ""
    # Reject schemes and host-based URLs outright.
    if ":" in raw.split("/", 1)[0]:
        return ""
    # Reject protocol-relative URLs (//evil.example/x) - still absolute.
    if raw.startswith("//") or not raw.startswith("/"):
        return ""
    # No CR/LF in case this flows into a header later.
    if "\n" in raw or "\r" in raw:
        return ""
    # Only /wizard is a legitimate return target today.
    path_only = raw.split("?", 1)[0].split("#", 1)[0]
    if path_only != "/wizard":
        return ""
    return raw


# All known tool groups
_ALL_GROUPS = list(TOOL_GROUPS.keys())

# Build tool data for templates (groups with their child tool prefixes)
_TOOL_DATA = []
_GROUP_DESCRIPTIONS = {
    "monitoring": "Hosts, problems, triggers, items, events, history, trends, SLA, dashboards, maps",
    "data_collection": "Templates, template groups, dashboards, value maps, configuration",
    "alerts": "Actions, media types, alert history, script execution",
    "users": "Users, user groups, roles, tokens, authentication",
    "administration": "Settings, proxies, housekeeping, audit log, connectors, modules",
    "extensions": "Graph render, anomaly detection, capacity forecast, PDF reports, raw API call, action approval",
}
for _gname, _gtools in TOOL_GROUPS.items():
    _TOOL_DATA.append({
        "name": _gname,
        "type": "group",
        "desc": _GROUP_DESCRIPTIONS.get(_gname, _gname),
        "tools": list(_gtools),
    })


def _get_global_context(admin_app) -> dict:
    """Read global disabled_tools and allowed_hosts from config for token templates."""
    disabled_tools: list[str] = []
    global_allowed_hosts: list[str] = []
    if TOMLKIT_AVAILABLE:
        try:
            doc = load_config_document(admin_app.config_path)
            server_cfg = doc.get("server", {})
            raw_disabled = server_cfg.get("disabled_tools", [])
            if isinstance(raw_disabled, list):
                disabled_tools = list(raw_disabled)
            raw_hosts = server_cfg.get("allowed_hosts", [])
            if isinstance(raw_hosts, list):
                global_allowed_hosts = list(raw_hosts)
        except Exception:
            pass
    # Expand groups into individual tool prefixes for the full disabled set
    from zabbix_mcp.config import _expand_tool_groups
    expanded_disabled = _expand_tool_groups(disabled_tools) if disabled_tools else []
    # Get available Zabbix server names
    zabbix_servers: list[str] = []
    if TOMLKIT_AVAILABLE:
        try:
            if 'doc' not in dir():
                doc = load_config_document(admin_app.config_path)
            zabbix_section = doc.get("zabbix", {})
            zabbix_servers = list(zabbix_section.keys())
        except Exception:
            pass
    # Also include runtime servers
    if hasattr(admin_app, 'client_manager'):
        for s in admin_app.client_manager.server_names:
            if s not in zabbix_servers:
                zabbix_servers.append(s)

    return {
        "disabled_groups": [g for g in disabled_tools if g in _ALL_GROUPS],
        "disabled_tools_list": disabled_tools,
        "expanded_disabled": expanded_disabled,
        "global_allowed_hosts": global_allowed_hosts,
        "tool_data": _TOOL_DATA,
        "zabbix_servers": zabbix_servers,
    }


async def token_list(request: Request) -> Response:
    admin_app = request.app.state.admin_app
    session = admin_app.require_auth(request)
    if not session:
        return RedirectResponse("/login", status_code=303)

    tokens = admin_app.token_store.list_tokens()
    return admin_app.render("tokens/list.html", request, {
        "active": "tokens",
        "tokens": tokens,
    })


async def token_create(request: Request) -> Response:
    admin_app = request.app.state.admin_app
    session = admin_app.require_auth(request)
    if not session:
        return RedirectResponse("/login", status_code=303)
    if session.role == "viewer":
        return admin_app.render("tokens/list.html", request, {
            "active": "tokens",
            "tokens": admin_app.token_store.list_tokens(),
            "flash_message": "Insufficient permissions.",
            "flash_type": "danger",
        })

    # Capture return_to so the form (and any error re-renders) can pass
    # it through. Used by the Client Wizard chain: /tokens/create?return_to=/wizard...
    # Only same-origin paths starting with `/wizard` are allowed; anything
    # else (absolute URLs, `javascript:`, other routes) is silently dropped
    # to prevent open-redirect + token-leak via URL fragment.
    return_to = _safe_return_to(request.query_params.get("return_to") or "")

    if request.method == "GET":
        ctx = {"active": "tokens", "return_to": return_to}
        ctx.update(_get_global_context(admin_app))
        return admin_app.render("tokens/create.html", request, ctx)

    # POST — create token
    form = await request.form()
    # Form may carry return_to as a hidden field too (POST clears query string).
    # Re-validate the form copy: never trust it, since the hidden input was
    # rendered into HTML that the browser may have had replaced by an XSS
    # in another tab sharing the same origin.
    return_to = _safe_return_to(str(form.get("return_to", return_to) or return_to))
    name = str(form.get("name", "")).strip()
    if not name:
        return admin_app.render("tokens/create.html", request, {
            "active": "tokens",
            "return_to": return_to,
            "error": "Name is required.",
        })

    # Parse scopes from hidden input (comma-separated) or checkboxes
    scopes_raw = str(form.get("scopes", "")).strip()
    if scopes_raw:
        scopes = [s.strip() for s in scopes_raw.split(",") if s.strip()]
    else:
        scopes = form.getlist("scopes")
    if not scopes:
        scopes = ["*"]

    read_only = "read_only" in form
    allowed_ips_raw = str(form.get("ip_allowlist", "")).strip()
    allowed_ips = [ip.strip() for ip in allowed_ips_raw.split("\n") if ip.strip()] if allowed_ips_raw else None
    expires_at = str(form.get("expires_at", "")).strip() or None

    # Parse allowed_servers
    servers_raw = str(form.get("allowed_servers", "*")).strip()
    allowed_servers = [s.strip() for s in servers_raw.split(",") if s.strip()] if servers_raw else ["*"]

    # Generate token
    raw_token, token_hash = TokenStore.generate_token()

    # Create a safe config key from the name
    import re
    token_id = re.sub(r"[^a-z0-9_]", "_", name.lower())[:50]
    if not token_id or not token_id[0].isalpha():
        token_id = "t_" + token_id

    # Check for ID collision with existing tokens
    existing_token = admin_app.token_store.get_token(token_id)
    if existing_token is not None:
        ctx = {"active": "tokens", "return_to": return_to, "error": f"A token with ID '{token_id}' already exists. Choose a different name."}
        ctx.update(_get_global_context(admin_app))
        return admin_app.render("tokens/create.html", request, ctx)

    # Write to config.toml
    from datetime import datetime, timezone
    token_data = {
        "name": name,
        "token_hash": token_hash,
        "scopes": list(scopes),
        "read_only": read_only,
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    token_data["allowed_servers"] = allowed_servers
    if allowed_ips:
        token_data["allowed_ips"] = allowed_ips
    if expires_at:
        token_data["expires_at"] = expires_at

    try:
        add_config_table(admin_app.config_path, "tokens", token_id, token_data)
        # Reload token store
        _reload_tokens(admin_app)
        admin_app.restart_needed = True
        logger.info("Token '%s' created by %s", name, session.user)
        client_ip = request.client.host if request.client else ""
        write_audit("token_create", user=session.user, target_type="token", target_id=token_id, ip=client_ip)
    except Exception as e:
        logger.error("Failed to create token: %s", e)
        return admin_app.render("tokens/create.html", request, {
            "active": "tokens",
            "return_to": return_to,
            "error": f"Failed to save: {e}",
        })

    # If the operator started from the wizard, build a continue link
    # back to it with the new token id appended.
    continue_to = ""
    if return_to:
        sep = "&" if "?" in return_to else "?"
        continue_to = f"{return_to}{sep}token={token_id}"

    # Show the raw token ONCE
    return admin_app.render("tokens/create.html", request, {
        "active": "tokens",
        "created_token": raw_token,
        "token_name": name,
        "token_id": token_id,
        "return_to": return_to,
        "continue_to": continue_to,
    })


async def token_detail(request: Request) -> Response:
    admin_app = request.app.state.admin_app
    session = admin_app.require_auth(request)
    if not session:
        return RedirectResponse("/login", status_code=303)

    token_id = request.path_params["token_id"]
    token = admin_app.token_store.get_token(token_id)
    if not token:
        return RedirectResponse("/tokens", status_code=303)

    if request.method == "POST" and session.role != "viewer":
        form = await request.form()
        updates = {}
        name = str(form.get("name", "")).strip()
        if name:
            updates["name"] = name

        scopes_raw = str(form.get("scopes", "")).strip()
        if scopes_raw:
            scopes = [s.strip() for s in scopes_raw.split(",") if s.strip()]
        else:
            scopes = form.getlist("scopes")
        if scopes:
            updates["scopes"] = list(scopes)

        read_only = "read_only" in form
        updates["read_only"] = read_only

        allowed_ips_raw = str(form.get("ip_allowlist", "")).strip()
        if allowed_ips_raw:
            updates["allowed_ips"] = [ip.strip() for ip in allowed_ips_raw.split("\n") if ip.strip()]
        else:
            updates["allowed_ips"] = []

        expires_at = str(form.get("expires_at", "")).strip()
        if expires_at:
            updates["expires_at"] = expires_at

        servers_raw = str(form.get("allowed_servers", "*")).strip()
        updates["allowed_servers"] = [s.strip() for s in servers_raw.split(",") if s.strip()] if servers_raw else ["*"]

        try:
            # Read current, merge updates
            doc = load_config_document(admin_app.config_path)
            tokens_section = doc.get("tokens", {})
            if token_id in tokens_section:
                # Detect if any non-name field actually changed
                current = dict(tokens_section[token_id])
                changed_restart = False
                for k, v in updates.items():
                    if k == "name":
                        continue
                    old_val = str(current.get(k, ""))
                    new_val = str(v)
                    if old_val != new_val:
                        changed_restart = True
                        break

                for k, v in updates.items():
                    tokens_section[token_id][k] = v
                from zabbix_mcp.admin.config_writer import save_config_document
                save_config_document(admin_app.config_path, doc)
                _reload_tokens(admin_app)
                logger.info("Token '%s' updated by %s", token_id, session.user)
                client_ip = request.client.host if request.client else ""
                write_audit("token_edit", user=session.user, target_type="token", target_id=token_id, ip=client_ip)

                if changed_restart:
                    admin_app.restart_needed = True
                    return admin_app.flash_redirect(f"/tokens/{token_id}", "Token updated. Restart required to apply changes.")
                return admin_app.flash_redirect(f"/tokens/{token_id}", "Token updated.")
            else:
                return admin_app.flash_redirect(f"/tokens/{token_id}", "Token not found in config.", "danger")
        except Exception as e:
            logger.error("Failed to update token: %s", e)
            return admin_app.flash_redirect(f"/tokens/{token_id}", f"Failed to save: {e}", "danger")

    ctx = {
        "active": "tokens",
        "token": token,
        "token_id": token_id,
    }
    ctx.update(_get_global_context(admin_app))
    return admin_app.render("tokens/detail.html", request, ctx)


async def token_revoke(request: Request) -> Response:
    admin_app = request.app.state.admin_app
    session = admin_app.require_auth(request)
    if not session or session.role == "viewer":
        return RedirectResponse("/tokens", status_code=303)

    token_id = request.path_params["token_id"]
    try:
        doc = load_config_document(admin_app.config_path)
        tokens_section = doc.get("tokens", {})
        if token_id in tokens_section:
            current = tokens_section[token_id].get("is_active", True)
            tokens_section[token_id]["is_active"] = not current
            from zabbix_mcp.admin.config_writer import save_config_document
            save_config_document(admin_app.config_path, doc)
            _reload_tokens(admin_app)
            action = "revoked" if current else "activated"
            logger.info("Token '%s' %s by %s", token_id, action, session.user)
            client_ip = request.client.host if request.client else ""
            write_audit(f"token_{action}", user=session.user, target_type="token", target_id=token_id, ip=client_ip)
            admin_app.restart_needed = True
            return admin_app.flash_redirect("/tokens", f"Token {action}. Restart required.")
    except Exception as e:
        logger.error("Failed to revoke token: %s", e)
        return admin_app.flash_redirect("/tokens", f"Failed: {e}", "danger")

    return RedirectResponse("/tokens", status_code=303)


async def token_delete(request: Request) -> Response:
    admin_app = request.app.state.admin_app
    session = admin_app.require_auth(request)
    if not session or session.role != "admin":
        return RedirectResponse("/tokens", status_code=303)

    token_id = request.path_params["token_id"]
    try:
        remove_config_table(admin_app.config_path, "tokens", token_id)
        _reload_tokens(admin_app)
        logger.info("Token '%s' deleted by %s", token_id, session.user)
        client_ip = request.client.host if request.client else ""
        write_audit("token_delete", user=session.user, target_type="token", target_id=token_id, ip=client_ip)
        admin_app.restart_needed = True
        return admin_app.flash_redirect("/tokens", f"Token '{token_id}' deleted. Restart required.")
    except Exception as e:
        logger.error("Failed to delete token: %s", e)
        return admin_app.flash_redirect("/tokens", f"Failed to delete token: {e}", "danger")


def _reload_tokens(admin_app) -> None:
    """Reload tokens from config.toml into the token store."""
    try:
        doc = load_config_document(admin_app.config_path)
        tokens_raw = doc.get("tokens", {})
        tokens_config = {k: dict(v) for k, v in tokens_raw.items()}
        admin_app.token_store.load_from_config(tokens_config)
    except Exception as e:
        logger.error("Failed to reload tokens: %s", e)
