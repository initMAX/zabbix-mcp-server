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

    # Zabbix server status — include both live and config-only servers
    servers = []
    config_servers = set()
    try:
        if TOMLKIT_AVAILABLE:
            doc2 = load_config_document(admin_app.config_path)
            config_servers = set(doc2.get("zabbix", {}).keys())
    except Exception:
        pass

    # Don't check live status here — it blocks page load
    # Use cached version if available, otherwise show as "unknown"
    all_server_names = sorted(set(client_manager.server_names) | config_servers)
    for name in all_server_names:
        if name in client_manager.server_names:
            # Use cached version (no HTTP call)
            cached_version = client_manager._versions.get(name)
            if cached_version:
                status = "online"
            else:
                status = "unknown"
            # Check config drift
            try:
                live_config = client_manager.get_server_config(name)
                cfg = {}
                if name in config_servers:
                    cfg = dict(doc2.get("zabbix", {}).get(name, {}))
                if cfg.get("url") and cfg["url"] != live_config.url:
                    status = "changed"
            except Exception:
                pass
            servers.append({"name": name, "status": status})
        else:
            servers.append({"name": name, "status": "pending"})

    # Count report templates
    report_template_count = 0
    try:
        from zabbix_mcp.reporting.engine import _REPORT_TEMPLATES
        report_template_count = len(_REPORT_TEMPLATES)
        # Add custom templates from config
        if TOMLKIT_AVAILABLE:
            doc = load_config_document(admin_app.config_path)
            custom = doc.get("report_templates", {})
            report_template_count += len(custom)
    except Exception:
        pass

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

    # Tasks API stats (MCP 2025-11-25). Sourced from the BoundedInMemoryTaskStore
    # we attached to config in server.run_server(). Falls back gracefully if the
    # store is not present (admin portal can be served without the MCP server
    # half running, e.g. during install validation).
    tasks_panel: dict | None = None
    _task_store = getattr(admin_app.config, "_task_store", None)
    if _task_store is not None:
        try:
            from datetime import datetime, timezone
            _task_store._cleanup_expired()
            live = list(_task_store._tasks.values())
            now = datetime.now(timezone.utc)
            oldest_age = None
            if live:
                oldest = min(s.task.createdAt for s in live)
                oldest_age = int((now - oldest).total_seconds())
            cap = _task_store._max_live_tasks
            tasks_panel = {
                "live": len(live),
                "max": cap,
                "usage_pct": int(round(100 * len(live) / cap)) if cap else 0,
                "oldest_age_s": oldest_age,
                "default_ttl_min": _task_store._default_ttl_ms // 60_000,
                "max_ttl_h": _task_store._max_ttl_ms // 3_600_000,
            }
        except Exception:
            logger.exception("Failed to compute tasks panel stats")

    return admin_app.render("dashboard.html", request, {
        "active": "dashboard",
        "stats": {
            "active_tokens": active_tokens,
            "total_tokens": len(tokens),
            "server_count": len(servers),
            "online_servers": sum(1 for s in servers if s["status"] == "online"),
            "admin_users": admin_user_count,
            "report_templates": report_template_count,
            # Active MCP modules: today only the bundled Zabbix module ships,
            # so the count is a constant 1. When the plugin loader lands
            # soon this will count enabled [plugins.<id>] entries from
            # config.toml and the Zabbix module itself.
            "mcp_modules_active": 1,
            "mcp_modules_total": 1,
        },
        "servers": servers,
        "audit_entries": recent_audit[:10],
        "tasks_panel": tasks_panel,
    })
