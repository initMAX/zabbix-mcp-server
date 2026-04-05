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


async def servers_view(request: Request) -> Response:
    admin_app = request.app.state.admin_app
    session = admin_app.require_auth(request)
    if not session:
        return RedirectResponse("/login", status_code=303)

    client_manager = admin_app.client_manager
    servers = []
    restart_needed = False

    # Read config to get latest saved values (may differ from live)
    config_zabbix = {}
    try:
        doc = load_config_document(admin_app.config_path)
        config_zabbix = {k: dict(v) for k, v in doc.get("zabbix", {}).items()}
    except Exception:
        pass

    # Build server list — prefer config values for URL etc., live status from client_manager
    all_names = set(client_manager.server_names) | set(config_zabbix.keys())

    for name in sorted(all_names):
        cfg = config_zabbix.get(name, {})
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
            config_changed = True
            restart_needed = True
        elif live_config and cfg.get("url") and cfg["url"] != live_config.url:
            config_changed = True
            restart_needed = True

        servers.append({
            "name": name,
            "url": url,
            "read_only": read_only,
            "verify_ssl": verify_ssl,
            "config_changed": config_changed,
            "is_live": name in client_manager.server_names,
        })

    # Also check if live has servers not in config (deleted)
    for name in client_manager.server_names:
        if name not in config_zabbix:
            restart_needed = True

    return admin_app.render("servers.html", request, {
        "active": "servers",
        "servers": servers,
        "restart_needed": restart_needed,
    })


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

    if not name or not re.match(r"^[a-zA-Z][a-zA-Z0-9_-]*$", name):
        return admin_app.flash_redirect("/servers", "Invalid server name. Must start with a letter and contain only letters, digits, dashes, and underscores.", "danger")

    if not url.startswith(("http://", "https://")):
        return admin_app.flash_redirect("/servers", "Invalid URL. Must start with http:// or https://.", "danger")

    try:
        server_data = {
            "url": url,
            "api_token": api_token,
            "read_only": read_only,
            "verify_ssl": verify_ssl,
        }
        add_config_table(admin_app.config_path, "zabbix", name, server_data)
        logger.info("Zabbix server '%s' added by %s", name, session.user)
        client_ip = request.client.host if request.client else ""
        write_audit("server_create", user=session.user, target_type="server", target_id=name, ip=client_ip)
        admin_app.restart_needed = True
        return admin_app.flash_redirect("/servers", f"Server '{name}' added. Restart required.")
    except Exception as e:
        logger.error("Failed to add server: %s", e)
        return admin_app.flash_redirect("/servers", f"Failed to add server: {e}", "danger")


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
    url = str(form.get("url", "")).strip()
    api_token = str(form.get("api_token", "")).strip()
    read_only = "read_only" in form
    verify_ssl = "verify_ssl" in form

    try:
        doc = load_config_document(admin_app.config_path)
        zabbix = doc.get("zabbix", {})
        if server_name in zabbix:
            if url:
                zabbix[server_name]["url"] = url
            if api_token:
                zabbix[server_name]["api_token"] = api_token
            zabbix[server_name]["read_only"] = read_only
            zabbix[server_name]["verify_ssl"] = verify_ssl
            save_config_document(admin_app.config_path, doc)
            logger.info("Zabbix server '%s' updated by %s", server_name, session.user)
            client_ip = request.client.host if request.client else ""
            write_audit("server_edit", user=session.user, target_type="server", target_id=server_name, ip=client_ip)
            admin_app.restart_needed = True
            return admin_app.flash_redirect("/servers", f"Server '{server_name}' updated. Restart required.")
        else:
            return admin_app.flash_redirect("/servers", f"Server '{server_name}' not found in config.", "danger")
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
        msg = _html.escape(str(e)[:100])
        return HTMLResponse(
            f'<span class="status-dot status-dot-red"></span> Error'
            f'<span style="margin-left:8px; font-size:0.8em; color:var(--color-danger);">{msg}</span>'
        )


async def server_restart(request: Request) -> Response:
    """Restart the MCP server service (systemctl restart)."""
    admin_app = request.app.state.admin_app
    session = admin_app.require_auth(request)
    if not session or session.role != "admin":
        return RedirectResponse("/servers", status_code=303)

    import subprocess, os, signal
    restarted = False

    # Try systemctl first (bare-metal / systemd)
    try:
        subprocess.run(
            ["systemctl", "restart", "zabbix-mcp-server"],
            check=True, capture_output=True, timeout=10,
        )
        restarted = True
    except FileNotFoundError:
        pass
    except subprocess.CalledProcessError as e:
        logger.error("systemctl restart failed: %s", e.stderr.decode() if e.stderr else e)
    except Exception as e:
        logger.error("systemctl restart failed: %s", e)

    # Fallback: Docker — send SIGTERM to PID 1, container policy will restart
    if not restarted:
        try:
            logger.info("Sending SIGTERM to PID 1 (Docker restart)...")
            admin_app.restart_needed = False
            from zabbix_mcp.admin.audit_writer import write_audit
            client_ip = request.client.host if request.client else ""
            write_audit("server_restart", user=session.user, ip=client_ip)
            # Kill PID 1 after a short delay so the response can be sent
            import threading
            def _kill():
                import time
                time.sleep(1)
                os.kill(1, signal.SIGTERM)
            threading.Thread(target=_kill, daemon=True).start()
            return JSONResponse({"status": "restarting"})
        except Exception as e:
            logger.error("Docker restart failed: %s", e)
            return JSONResponse({"status": "error", "error": str(e)}, status_code=500)

    admin_app.restart_needed = False
    logger.info("MCP server restarted by %s", session.user)
    from zabbix_mcp.admin.audit_writer import write_audit
    client_ip = request.client.host if request.client else ""
    write_audit("server_restart", user=session.user, ip=client_ip)
    return JSONResponse({"status": "restarted"})


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

    # SECURITY: resolve hostname and check if it's internal (prevents DNS rebinding / SSRF redirect bypass)
    import socket
    try:
        resolved_ip = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)[0][4][0]
        from ipaddress import ip_address as _ip
        addr = _ip(resolved_ip)
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
            return HTMLResponse('<span class="text-danger">URL resolves to a private/internal IP address</span>')
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
        msg = _html.escape(str(e)[:120])
        return HTMLResponse(
            f'<span class="status-dot status-dot-red"></span>'
            f'<span style="color:var(--color-danger);"> {msg}</span>'
        )
