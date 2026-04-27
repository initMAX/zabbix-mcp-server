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
    # Re-render context that preserves what the operator already typed
    # so a validation failure does not wipe the whole form.
    def _err(msg: str) -> Response:
        ctx = {
            "active": "tokens",
            "return_to": return_to,
            "error": msg,
            "form_name": name,
            "form_ip_allowlist": str(form.get("ip_allowlist", "") or ""),
            "form_expires_at": str(form.get("expires_at", "") or ""),
            "form_read_only": "read_only" in form,
            "form_scopes": str(form.get("scopes", "") or ""),
            "form_allowed_servers": str(form.get("allowed_servers", "") or ""),
        }
        ctx.update(_get_global_context(admin_app))
        return admin_app.render("tokens/create.html", request, ctx)

    if not name:
        return _err("Name is required.")
    # Cap token name at 100 chars - prevents the token list table
    # layout breaking on extreme input (reported 2026-04-17 with a
    # 5000-char name that pushed the Delete button off-screen).
    if len(name) > 100:
        return _err(f"Token name must be 100 characters or fewer (you entered {len(name)}).")

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
    # Validate every IP / CIDR before write so a typo cannot park a
    # malformed string in config.toml and surface as a 500 at every
    # token-auth check later.
    if allowed_ips:
        from ipaddress import ip_network as _ipnet
        # IPv4 and IPv6 both supported; '2001:db8::/32' or '10.0.0.0/8'
        # work either way. Normalize via str(ip_network()) so
        # 192.168.1.1, 192.168.1.1/32 and 192.168.001.001 collapse to
        # the same canonical form for duplicate detection.
        seen: dict[str, str] = {}
        for ip in allowed_ips:
            try:
                norm = str(_ipnet(ip, strict=False))
            except ValueError:
                return _err(f"IP allowlist entry '{ip}' is not a valid IPv4 / IPv6 address or CIDR range.")
            if norm in seen:
                return _err(f"Duplicate IP allowlist entry: '{ip}' is the same as '{seen[norm]}'.")
            seen[norm] = ip
    expires_at = str(form.get("expires_at", "")).strip() or None
    if expires_at:
        # Accept the same ISO 8601 form the token store consumes
        # (YYYY-MM-DD or full timestamp). Reject everything else
        # so we don't have to deal with parse errors later.
        from datetime import datetime as _dt
        ok = False
        for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S"):
            try:
                _dt.strptime(expires_at, fmt)
                ok = True
                break
            except ValueError:
                continue
        if not ok:
            return _err(f"Expiry date '{expires_at}' is not a recognized format. Use YYYY-MM-DD or YYYY-MM-DD HH:MM:SS.")

    # Parse allowed_servers and validate each entry refers to a real
    # configured Zabbix server (or is the wildcard '*'). Without this
    # check a typo silently locks the token out of every server at
    # call time with no UI hint where the mismatch is.
    servers_raw = str(form.get("allowed_servers", "*")).strip()
    allowed_servers = [s.strip() for s in servers_raw.split(",") if s.strip()] if servers_raw else ["*"]
    known_servers = set(admin_app.client_manager.server_names)
    for sname in allowed_servers:
        if sname == "*":
            continue
        if sname not in known_servers:
            return _err(
                f"Allowed server '{sname}' is not a configured Zabbix server. "
                f"Known: {', '.join(sorted(known_servers)) or '(none)'}."
            )

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
        return _err(f"A token with ID '{token_id}' already exists. Choose a different name.")

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

        # Concurrent-edit guard: GET embedded the config.toml mtime in
        # a hidden _cfg_mtime field. If another admin saved the same
        # file between GET and POST, refuse this submit so we don't
        # silently overwrite their change.
        from zabbix_mcp.admin.config_writer import config_mtime
        submitted_mtime = str(form.get("_cfg_mtime", "") or "")
        if submitted_mtime and submitted_mtime != config_mtime(admin_app.config_path):
            return admin_app.flash_redirect(
                f"/tokens/{token_id}",
                "Another admin saved this config while you were editing. Reload to see the latest values, then re-apply your change.",
                "danger",
            )

        updates = {}
        name = str(form.get("name", "")).strip()
        if name:
            if len(name) > 100:
                return admin_app.flash_redirect(
                    f"/tokens/{token_id}",
                    f"Token name must be 100 characters or fewer (you entered {len(name)}).",
                    "danger",
                )
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
            ips = [ip.strip() for ip in allowed_ips_raw.split("\n") if ip.strip()]
            seen_ips: dict[str, str] = {}
            for ip in ips:
                try:
                    norm = str(_ipnet(ip, strict=False))
                except ValueError:
                    return admin_app.flash_redirect(
                        f"/tokens/{token_id}",
                        f"IP allowlist entry '{ip}' is not a valid IPv4 / IPv6 address or CIDR range.",
                        "danger",
                    )
                if norm in seen_ips:
                    return admin_app.flash_redirect(
                        f"/tokens/{token_id}",
                        f"Duplicate IP allowlist entry: '{ip}' is the same as '{seen_ips[norm]}'.",
                        "danger",
                    )
                seen_ips[norm] = ip
            updates["allowed_ips"] = ips
        else:
            updates["allowed_ips"] = []

        expires_at = str(form.get("expires_at", "")).strip()
        if expires_at:
            # Mirror the create-path expiry-format check so the edit
            # path doesn't silently accept gibberish dates.
            ok = False
            for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S",
                        "%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
                try:
                    from datetime import datetime
                    datetime.strptime(expires_at, fmt)
                    ok = True
                    break
                except ValueError:
                    continue
            if not ok:
                return admin_app.flash_redirect(
                    f"/tokens/{token_id}",
                    f"Expiry date '{expires_at}' is not a recognized format. Use YYYY-MM-DD or YYYY-MM-DD HH:MM:SS.",
                    "danger",
                )
            updates["expires_at"] = expires_at

        servers_raw = str(form.get("allowed_servers", "*")).strip()
        servers_list = [s.strip() for s in servers_raw.split(",") if s.strip()] if servers_raw else ["*"]
        known_servers = set(admin_app.client_manager.server_names)
        for sname in servers_list:
            if sname == "*":
                continue
            if sname not in known_servers:
                return admin_app.flash_redirect(
                    f"/tokens/{token_id}",
                    f"Allowed server '{sname}' is not a configured Zabbix server. Known: {', '.join(sorted(known_servers)) or '(none)'}.",
                    "danger",
                )
        updates["allowed_servers"] = servers_list

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

    from zabbix_mcp.admin.config_writer import config_mtime
    ctx = {
        "active": "tokens",
        "token": token,
        "token_id": token_id,
        "config_mtime": config_mtime(admin_app.config_path),
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


async def token_bulk_delete(request: Request) -> Response:
    """Delete multiple tokens in one shot (Bug 27).

    The list page renders one checkbox per token; the operator picks
    a set, types `DELETE N` to confirm, and we receive `ids=t1&ids=t2&...`
    All ids are removed from config.toml in a single tomlkit save so
    the file never sits in a half-deleted state. One audit row per
    token id (so it shows up in the per-token audit history search).
    """
    admin_app = request.app.state.admin_app
    session = admin_app.require_auth(request)
    if not session or session.role != "admin":
        return RedirectResponse("/tokens", status_code=303)

    form = await request.form()
    ids = [str(s).strip() for s in form.getlist("ids") if str(s).strip()]
    if not ids:
        return admin_app.flash_redirect("/tokens", "No tokens selected.", "danger")

    try:
        from zabbix_mcp.admin.config_writer import save_config_document
        doc = load_config_document(admin_app.config_path)
        tokens_section = doc.get("tokens")
        if tokens_section is None:
            return admin_app.flash_redirect("/tokens", "No tokens section in config.", "danger")
        deleted: list[str] = []
        missing: list[str] = []
        for tid in ids:
            if tid in tokens_section:
                del tokens_section[tid]
                deleted.append(tid)
            else:
                missing.append(tid)
        save_config_document(admin_app.config_path, doc)
        _reload_tokens(admin_app)
        client_ip = request.client.host if request.client else ""
        for tid in deleted:
            write_audit("token_delete", user=session.user, target_type="token", target_id=tid, ip=client_ip)
        logger.info("Bulk-deleted %d token(s) by %s: %s", len(deleted), session.user, deleted)
        admin_app.restart_needed = True
        msg = f"Deleted {len(deleted)} token(s). Restart required."
        if missing:
            msg += f" Skipped (not found): {', '.join(missing)}."
        return admin_app.flash_redirect("/tokens", msg)
    except Exception as e:
        logger.error("Bulk-delete tokens failed: %s", e)
        return admin_app.flash_redirect("/tokens", f"Bulk-delete failed: {e}", "danger")


def _reload_tokens(admin_app) -> None:
    """Reload tokens from config.toml into the token store."""
    try:
        doc = load_config_document(admin_app.config_path)
        tokens_raw = doc.get("tokens", {})
        tokens_config = {k: dict(v) for k, v in tokens_raw.items()}
        admin_app.token_store.load_from_config(tokens_config)
    except Exception as e:
        logger.error("Failed to reload tokens: %s", e)
