#
# Zabbix MCP Server
# Copyright (C) 2026 initMAX s.r.o.
#

"""Dashboard view — overview of server status, tokens, recent activity."""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path

from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

logger = logging.getLogger("zabbix_mcp.admin")

AUDIT_LOG_PATH = Path("/var/log/zabbix-mcp/audit.log")


async def dashboard(request: Request) -> Response:
    admin_app = request.app.state.admin_app
    session = admin_app.require_auth(request)
    if not session:
        return RedirectResponse("/login", status_code=303)

    # Gather stats
    token_store = admin_app.token_store
    client_manager = admin_app.client_manager

    tokens = token_store.list_tokens()
    active_tokens = sum(1 for t in tokens if not getattr(t, "revoked", False))

    # Count admin users from config
    admin_user_count = 0
    try:
        from zabbix_mcp.admin.config_writer import load_config_document, TOMLKIT_AVAILABLE
        if TOMLKIT_AVAILABLE:
            doc = load_config_document(admin_app.config_path)
            admin_section = doc.get("admin", {})
            users_section = admin_section.get("users", {})
            admin_user_count = len(users_section)
    except Exception:
        pass

    # Zabbix server status
    servers = []
    for name in client_manager.server_names:
        srv_config = client_manager.get_server_config(name)
        try:
            version = client_manager.get_version(name)
            status = "online"
        except Exception:
            version = "unknown"
            status = "error"
        servers.append({
            "name": name,
            "url": srv_config.url,
            "status": status,
            "version": version,
            "read_only": srv_config.read_only,
        })

    # Recent audit entries
    recent_audit = []
    if AUDIT_LOG_PATH.exists():
        try:
            lines = AUDIT_LOG_PATH.read_text().strip().split("\n")
            for line in reversed(lines[-20:]):
                if line.strip():
                    try:
                        recent_audit.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        except Exception:
            pass

    return admin_app.render("dashboard.html", request, {
        "active": "dashboard",
        "stats": {
            "active_tokens": active_tokens,
            "total_tokens": len(tokens),
            "server_count": len(servers),
            "online_servers": sum(1 for s in servers if s["status"] == "online"),
            "admin_users": admin_user_count,
        },
        "servers": servers,
        "recent_audit": recent_audit[:10],
    })
