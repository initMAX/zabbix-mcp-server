#
# Zabbix MCP Server
# Copyright (C) 2026 initMAX s.r.o.
#

"""Zabbix server views — status, create, edit, delete, test connection."""

from __future__ import annotations

import asyncio
import logging
import re

from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response

from zabbix_mcp.admin.audit_writer import write_audit
from zabbix_mcp.admin.config_writer import (
    add_config_table,
    load_config_document,
    remove_config_table,
    save_config_document,
    TOMLKIT_AVAILABLE,
)

logger = logging.getLogger("zabbix_mcp.admin")

# Default HTTP timeout matches Zabbix PHP frontend's max_execution_time so
# expensive exports / long history.get ranges can complete. Match the
# default in ZabbixServerConfig.request_timeout.
_DEFAULT_TIMEOUT = 300
_MIN_TIMEOUT = 5
_MAX_TIMEOUT = 3600  # 1 hour; anything longer blocks the MCP thread pool too long.


def _parse_timeout(raw) -> int:
    """Coerce a form value into a safe timeout seconds integer.

    Falls back to the default on empty / non-numeric / out-of-range
    input rather than raising, so a bad form submission cannot crash
    the edit handler before it can re-render the page.
    """
    try:
        v = int(str(raw).strip()) if raw not in (None, "") else _DEFAULT_TIMEOUT
    except (TypeError, ValueError):
        return _DEFAULT_TIMEOUT
    if v < _MIN_TIMEOUT:
        return _MIN_TIMEOUT
    if v > _MAX_TIMEOUT:
        return _MAX_TIMEOUT
    return v


def _render_servers_list(request: Request, admin_app, extra: dict | None = None) -> Response:
    """Render the /servers page. Shared by `servers_view` (GET) and
    `server_create` so that a validation failure on Add Server can
    re-render the same page with `add_form_open=True` plus the form
    values the operator already typed - instead of `flash_redirect`
    which wipes the form (especially the API token, which the user
    would have to retype from scratch)."""
    client_manager = admin_app.client_manager
    servers = []
    drift_detected = False

    # Read config to get latest saved values (may differ from live)
    config_zabbix = {}
    try:
        doc = load_config_document(admin_app.config_path)
        config_zabbix = {k: dict(v) for k, v in doc.get("zabbix", {}).items()}
    except Exception:
        pass

    # Show only servers that exist in the *config* — that's the source of
    # truth the user just edited. Stale live entries (ones that exist in
    # the running ClientManager but no longer in config — deleted or
    # renamed away) are hidden, since the user already removed them; we
    # only need to remind them via the global "restart needed" banner.
    for name in sorted(config_zabbix.keys()):
        cfg = config_zabbix[name]
        live_config = None
        try:
            live_config = client_manager.get_server_config(name)
        except Exception:
            pass

        # Use config URL (latest saved), fall back to live
        url = cfg.get("url", live_config.url if live_config else "")
        read_only = cfg.get("read_only", live_config.read_only if live_config else True)
        verify_ssl = cfg.get("verify_ssl", live_config.verify_ssl if live_config else True)

        # Don't check live status here — it blocks page load.
        # Status will be loaded async via HTMX /servers/{name}/test
        config_changed = False
        if name not in client_manager.server_names:
            # In config but not live — newly added (or renamed in),
            # not yet active.
            config_changed = True
            drift_detected = True
        elif live_config and cfg.get("url") and cfg["url"] != live_config.url:
            config_changed = True
            drift_detected = True

        servers.append({
            "name": name,
            "url": url,
            "read_only": read_only,
            "verify_ssl": verify_ssl,
            "config_changed": config_changed,
            "is_live": name in client_manager.server_names,
        })

    # Drift also covers the inverse case: live servers that no longer
    # exist in config (deleted or renamed away). They are hidden from
    # the card list above, but the banner must still appear so the user
    # knows a restart is needed to apply the deletion.
    for name in client_manager.server_names:
        if name not in config_zabbix:
            drift_detected = True

    # Persist drift into the global state so the banner stays consistent
    # across all pages (it would otherwise only show after an explicit
    # save in this process). Never clear the flag here — only the restart
    # endpoint may clear it.
    if drift_detected:
        admin_app.restart_needed = True

    ctx = {
        "active": "servers",
        "servers": servers,
    }
    if extra:
        ctx.update(extra)
    return admin_app.render("servers.html", request, ctx)


async def servers_view(request: Request) -> Response:
    admin_app = request.app.state.admin_app
    session = admin_app.require_auth(request)
    if not session:
        return RedirectResponse("/login", status_code=303)
    return _render_servers_list(request, admin_app)


async def server_create(request: Request) -> Response:
    """Create a new Zabbix server in config.toml."""
    admin_app = request.app.state.admin_app
    session = admin_app.require_auth(request)
    if not session or session.role != "admin":
        return RedirectResponse("/servers", status_code=303)

    form = await request.form()
    name = str(form.get("name", "")).strip()
    url = str(form.get("url", "")).strip()
    api_token = str(form.get("api_token", "")).strip()
    read_only = "read_only" in form
    verify_ssl = "verify_ssl" in form
    request_timeout = _parse_timeout(form.get("request_timeout"))

    # Re-render the /servers page with the Add Server card open and
    # the typed values preserved so a typo (especially in the URL)
    # does not wipe the API token the operator just pasted.
    def _err(msg: str) -> Response:
        return _render_servers_list(request, admin_app, {
            "add_form_open": True,
            "add_form_error": msg,
            "form_name": name,
            "form_url": url,
            "form_api_token": api_token,
            "form_read_only": read_only,
            "form_verify_ssl": verify_ssl,
        })

    if not name or not re.match(r"^[a-zA-Z][a-zA-Z0-9_-]*$", name):
        return _err("Invalid server name. Must start with a letter and contain only letters, digits, dashes, and underscores.")

    if not url.startswith(("http://", "https://")):
        return _err("Invalid URL. Must start with http:// or https://.")

    # Strict hostname validation: reject malformed inputs like
    # "http://0.0.0.0.0.0.0" or "http://host with spaces" before they
    # land in config.toml. Without this, parse_config at next boot
    # would skip the broken server with a warning, but the operator
    # would have no idea why.
    try:
        from zabbix_mcp.config import _parse_zabbix_server
        _parse_zabbix_server("__validate__", {
            "url": url,
            "api_token": api_token or "x",  # token validated separately above
        })
    except Exception as exc:
        return _err(f"Invalid URL: {exc}")

    try:
        server_data = {
            "url": url,
            "api_token": api_token,
            "read_only": read_only,
            "verify_ssl": verify_ssl,
            "request_timeout": request_timeout,
        }
        add_config_table(admin_app.config_path, "zabbix", name, server_data)
        logger.info("Zabbix server '%s' added by %s", name, session.user)
        client_ip = request.client.host if request.client else ""
        write_audit("server_create", user=session.user, target_type="server", target_id=name, ip=client_ip)
        admin_app.restart_needed = True
        return admin_app.flash_redirect("/servers", f"Server '{name}' added. Restart required.")
    except Exception as e:
        logger.error("Failed to add server: %s", e)
        return _err(f"Failed to add server: {e}")


async def server_edit(request: Request) -> Response:
    """Edit a Zabbix server in config.toml."""
    admin_app = request.app.state.admin_app
    session = admin_app.require_auth(request)
    if not session or session.role != "admin":
        return RedirectResponse("/servers", status_code=303)

    server_name = request.path_params["server_name"]

    if request.method == "GET":
        # Read current server config
        try:
            doc = load_config_document(admin_app.config_path)
            zabbix = doc.get("zabbix", {})
            srv = dict(zabbix.get(server_name, {}))
        except Exception:
            srv = {}

        if not srv:
            return RedirectResponse("/servers", status_code=303)

        return admin_app.render("servers_edit.html", request, {
            "active": "servers",
            "edit_server_name": server_name,
            "server": srv,
        })

    # POST — save changes
    form = await request.form()
    new_name = str(form.get("name", "")).strip()
    url = str(form.get("url", "")).strip()
    api_token = str(form.get("api_token", "")).strip()
    read_only = "read_only" in form
    verify_ssl = "verify_ssl" in form
    request_timeout = _parse_timeout(form.get("request_timeout"))

    # Validate new name (allow keeping the same name as a no-op rename)
    if not new_name or not re.match(r"^[a-zA-Z][a-zA-Z0-9_-]*$", new_name):
        return admin_app.flash_redirect(
            f"/servers/{server_name}/edit",
            "Invalid server name. Must start with a letter and contain only letters, digits, dashes, and underscores.",
            "danger",
        )

    try:
        doc = load_config_document(admin_app.config_path)
        zabbix = doc.get("zabbix", {})
        if server_name not in zabbix:
            return admin_app.flash_redirect("/servers", f"Server '{server_name}' not found in config.", "danger")

        renamed = new_name != server_name
        if renamed and new_name in zabbix:
            return admin_app.flash_redirect(
                f"/servers/{server_name}/edit",
                f"A server named '{new_name}' already exists.",
                "danger",
            )

        # Apply field updates to the existing table first
        if url:
            zabbix[server_name]["url"] = url
        if api_token:
            zabbix[server_name]["api_token"] = api_token
        zabbix[server_name]["read_only"] = read_only
        zabbix[server_name]["verify_ssl"] = verify_ssl
        zabbix[server_name]["request_timeout"] = request_timeout

        if renamed:
            # tomlkit has no rename — copy the table data into a new entry
            # and delete the old one. Preserves all keys (including any
            # extras like ssl_cert that the form doesn't expose).
            import tomlkit
            old_table = zabbix[server_name]
            new_table = tomlkit.table()
            for k, v in dict(old_table).items():
                new_table.add(k, v)
            zabbix.add(new_name, new_table)
            del zabbix[server_name]

            # Update tokens that explicitly reference the old name in
            # allowed_servers, so the rename doesn't silently break ACLs.
            tokens_section = doc.get("tokens", {})
            updated_tokens: list[str] = []
            for token_id in list(tokens_section.keys()):
                token_table = tokens_section[token_id]
                allowed = token_table.get("allowed_servers")
                if isinstance(allowed, list) and server_name in allowed:
                    new_allowed = [new_name if s == server_name else s for s in allowed]
                    token_table["allowed_servers"] = new_allowed
                    updated_tokens.append(token_id)
            if updated_tokens:
                logger.info(
                    "Rename '%s' -> '%s': updated allowed_servers in tokens %s",
                    server_name, new_name, updated_tokens,
                )

        save_config_document(admin_app.config_path, doc)
        target_id = new_name if renamed else server_name
        action_msg = (
            f"Server renamed '{server_name}' -> '{new_name}'. Restart required."
            if renamed else
            f"Server '{server_name}' updated. Restart required."
        )
        logger.info("Zabbix server '%s' updated by %s%s",
                    server_name, session.user,
                    f" (renamed to '{new_name}')" if renamed else "")
        client_ip = request.client.host if request.client else ""
        write_audit(
            "server_rename" if renamed else "server_edit",
            user=session.user,
            target_type="server",
            target_id=target_id,
            details={"old_name": server_name, "new_name": new_name} if renamed else None,
            ip=client_ip,
        )
        admin_app.restart_needed = True
        return admin_app.flash_redirect("/servers", action_msg)
    except Exception as e:
        logger.error("Failed to update server: %s", e)
        return admin_app.flash_redirect("/servers", f"Failed to update server: {e}", "danger")


async def server_delete(request: Request) -> Response:
    """Delete a Zabbix server from config.toml."""
    admin_app = request.app.state.admin_app
    session = admin_app.require_auth(request)
    if not session or session.role != "admin":
        return RedirectResponse("/servers", status_code=303)

    server_name = request.path_params["server_name"]
    try:
        remove_config_table(admin_app.config_path, "zabbix", server_name)
        logger.info("Zabbix server '%s' deleted by %s", server_name, session.user)
        client_ip = request.client.host if request.client else ""
        write_audit("server_delete", user=session.user, target_type="server", target_id=server_name, ip=client_ip)
        admin_app.restart_needed = True
        return admin_app.flash_redirect("/servers", f"Server '{server_name}' deleted. Restart required.")
    except Exception as e:
        logger.error("Failed to delete server: %s", e)
        return admin_app.flash_redirect("/servers", f"Failed to delete server: {e}", "danger")


def _friendly_error(exc: Exception) -> str:
    """Translate raw urllib / network errors to user-facing messages.

    The previous server card "Error: Unable to connect to ...:
    <urlopen error [Errno 111] Connec" output (truncated mid-word!)
    was reported 2026-04-17 as "bad error/copy for user". This
    helper maps the common errno / SSL / HTTP cases to a short
    actionable line plus keeps the technical detail short.
    """
    msg = str(exc)
    lower = msg.lower()
    # ECONNREFUSED on Linux = errno 111, on macOS = errno 61
    if "errno 111" in lower or "errno 61" in lower or "connection refused" in lower:
        return "Connection refused. Is Zabbix running on this URL?"
    if "errno -2" in lower or "name or service not known" in lower or "nodename nor servname" in lower:
        return "Could not resolve hostname. Check the URL is correct."
    if "errno -3" in lower or "temporary failure in name resolution" in lower:
        return "DNS lookup temporarily failed. Try again or fix DNS."
    if "timed out" in lower or "timeout" in lower:
        return "Connection timed out. Check the network or raise request_timeout."
    if "ssl" in lower or "certificate" in lower:
        return "TLS handshake failed. Check the certificate or set verify_ssl = false in config.toml."
    if "401" in msg or "unauthorized" in lower:
        return "Zabbix returned 401. The API token is invalid or expired."
    if "403" in msg or "forbidden" in lower:
        return "Zabbix returned 403. The API token lacks permission for this operation."
    if "404" in msg or "not found" in lower:
        return "Zabbix returned 404. The URL points outside the Zabbix frontend."
    # Fallback: trim to a clean word boundary so we never end mid-word
    # like the original "Connec" report.
    if len(msg) > 120:
        cutoff = msg.rfind(" ", 0, 120)
        if cutoff < 60:
            cutoff = 120
        msg = msg[:cutoff].rstrip(",.;:") + "..."
    return msg


async def server_test(request: Request) -> Response:
    """Test connection to a specific Zabbix server (HTMX endpoint)."""
    admin_app = request.app.state.admin_app
    session = admin_app.require_auth(request)
    if not session:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    server_name = request.path_params["server_name"]
    client_manager = admin_app.client_manager

    from starlette.responses import HTMLResponse
    import html as _html
    try:
        result = await asyncio.to_thread(client_manager.check_connection, server_name)
        version = _html.escape(client_manager.get_version(server_name))
        if result.get("token_ok"):
            return HTMLResponse(
                f'<span class="status-dot status-dot-green"></span> Connected'
                f'<span style="margin-left:8px;">Zabbix {version}</span>'
                f'<span class="test-ok" style="margin-left:8px; color:var(--color-success); animation: fadeOut 2s forwards;">&#x2713;</span>'
            )
        else:
            return HTMLResponse(
                f'<span class="status-dot status-dot-yellow"></span> API online'
                f'<span style="margin-left:8px;">Zabbix {version}</span>'
                f'<span style="margin-left:8px; font-size:0.8em; color:var(--color-warning);">&#x26A0; Token invalid or expired</span>'
            )
    except Exception as e:
        msg = _html.escape(_friendly_error(e))
        return HTMLResponse(
            f'<span class="status-dot status-dot-red"></span> Error'
            f'<span style="margin-left:8px; font-size:0.8em; color:var(--color-danger);">{msg}</span>'
        )


async def server_restart(request: Request) -> Response:
    """Restart the MCP server by exiting the current process with status 1.

    Backwards compatible with all existing deployments — no unit/compose
    file changes required:

      - systemd Restart=on-failure (v1.16 - v1.18 unit): exit 1 is a
        failure, so the unit respawns automatically.
      - systemd Restart=always (v1.19+ unit): always respawns.
      - Docker restart: unless-stopped: PID 1 exit -> container restart.

    Why os._exit(1) and not SIGTERM? systemd treats SIGTERM as a clean
    shutdown ("success") and Restart=on-failure does NOT respawn. Exit
    code 1 covers all three deployment modes uniformly.

    Why not sudo systemctl restart? The systemd unit ships with
    NoNewPrivileges=yes which blocks sudo from elevating, even with a
    NOPASSWD sudoers entry. The old fallback (SIGTERM to PID 1) only
    works in Docker, where PID 1 == this Python process; on bare-metal
    PID 1 is systemd itself and ignores the signal.
    """
    admin_app = request.app.state.admin_app
    session = admin_app.require_auth(request)
    if not session or session.role != "admin":
        return RedirectResponse("/servers", status_code=303)

    import os
    import threading

    admin_app.restart_needed = False
    client_ip = request.client.host if request.client else ""
    write_audit("server_restart", user=session.user, ip=client_ip)
    logger.info("Restart requested by %s — exiting process to trigger respawn", session.user)

    # Exit after a short delay so the HTTP response gets flushed first.
    # os._exit bypasses Python cleanup (atexit, finally), which is fine
    # since we are about to be respawned. Logs that matter were already
    # flushed by the logger above.
    def _exit() -> None:
        import time
        time.sleep(1)
        os._exit(1)

    threading.Thread(target=_exit, daemon=True).start()
    return JSONResponse({"status": "restarting"})


async def server_test_new(request: Request) -> Response:
    """Test connection to a new Zabbix server before saving."""
    from starlette.responses import HTMLResponse
    import html as _html

    admin_app = request.app.state.admin_app
    session = admin_app.require_auth(request)
    if not session or session.role != "admin":
        return HTMLResponse("Unauthorized — admin role required", status_code=403)

    form = await request.form()
    url = str(form.get("url", "")).strip()
    api_token = str(form.get("api_token", "")).strip()
    verify_ssl = form.get("verify_ssl") == "1"

    # SECURITY: validate URL scheme and block internal/private addresses (SSRF prevention)
    if not url.startswith(("http://", "https://")):
        return HTMLResponse('<span class="text-danger">URL must start with http:// or https://</span>')

    from urllib.parse import urlparse
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    # Block obvious internal targets
    _blocked = ("localhost", "127.0.0.1", "::1", "0.0.0.0", "metadata.google", "169.254.169.254")
    if any(hostname == b or hostname.endswith("." + b) for b in _blocked):
        return HTMLResponse('<span class="text-danger">URL points to a blocked internal address</span>')

    # SECURITY: resolve hostname and block only loopback / link-local /
    # reserved (covers AWS metadata 169.254.169.254 etc). RFC1918 private
    # IP ranges (10/8, 172.16/12, 192.168/16) are explicitly ALLOWED -
    # they are exactly where Zabbix typically lives, and blocking them
    # made the entire admin portal unable to add a server in 90% of
    # real deployments (reported by tester 2026-04-17).
    import socket
    try:
        resolved_ip = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)[0][4][0]
        from ipaddress import ip_address as _ip
        addr = _ip(resolved_ip)
        if addr.is_loopback or addr.is_link_local or addr.is_reserved:
            return HTMLResponse('<span class="text-danger">URL resolves to a loopback / link-local / reserved address (blocked)</span>')
    except (socket.gaierror, ValueError):
        pass  # Let ZabbixAPI handle DNS errors

    if not url or not api_token:
        return HTMLResponse('<span class="text-danger">URL and API token are required</span>')

    try:
        from zabbix_utils import ZabbixAPI
        api = ZabbixAPI(url=url, validate_certs=verify_ssl, skip_version_check=True)
        api.login(token=api_token)
        version = _html.escape(str(api.api_version()))
        return HTMLResponse(
            f'<span class="status-dot status-dot-green"></span>'
            f'<span style="color:var(--color-success);"> Connected — Zabbix {version}</span>'
        )
    except Exception as e:
        msg = _html.escape(_friendly_error(e))
        return HTMLResponse(
            f'<span class="status-dot status-dot-red"></span>'
            f'<span style="color:var(--color-danger);"> {msg}</span>'
        )
