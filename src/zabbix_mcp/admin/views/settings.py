#
# Zabbix MCP Server
# Copyright (C) 2026 initMAX s.r.o.
#

"""Settings view — display and edit all config.toml sections."""

from __future__ import annotations

import logging

from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

from zabbix_mcp.admin.config_writer import (
    load_config_document,
    save_config_document,
    TOMLKIT_AVAILABLE,
)

logger = logging.getLogger("zabbix_mcp.admin")

# Settings that require a server restart to take effect
RESTART_REQUIRED = {"host", "port", "transport", "tls_cert_file", "tls_key_file"}


async def settings_view(request: Request) -> Response:
    admin_app = request.app.state.admin_app
    session = admin_app.require_auth(request)
    if not session:
        return RedirectResponse("/login", status_code=303)

    # Read current config — flatten sections so template can use settings.host etc.
    settings = {}
    if TOMLKIT_AVAILABLE:
        try:
            doc = load_config_document(admin_app.config_path)
            server_cfg = dict(doc.get("server", {}))
            admin_cfg = dict(doc.get("admin", {}))
            reporting_cfg = dict(doc.get("reporting", {}))
            # Remove sensitive values
            server_cfg.pop("auth_token", None)
            # Remove users sub-table from admin display
            admin_cfg.pop("users", None)
            # Merge all into flat dict
            settings.update(server_cfg)
            settings.update(admin_cfg)
            settings.update(reporting_cfg)
        except Exception as e:
            logger.error("Failed to read config: %s", e)

    return admin_app.render("settings.html", request, {
        "active": "settings",
        "settings": settings,
        "restart_required_fields": RESTART_REQUIRED,
        "can_edit": session.role in ("admin", "operator"),
    })


async def settings_update(request: Request) -> Response:
    admin_app = request.app.state.admin_app
    session = admin_app.require_auth(request)
    if not session or session.role not in ("admin", "operator"):
        return RedirectResponse("/settings", status_code=303)

    section = request.path_params["section"]
    if section not in ("server", "admin", "reporting", "security"):
        return RedirectResponse("/settings", status_code=303)

    form = await request.form()

    try:
        doc = load_config_document(admin_app.config_path)
        config_section = doc.get(section, {})

        needs_restart = False
        for key, value in form.items():
            if key.startswith("_"):  # skip CSRF etc.
                continue

            # Type conversion
            if value == "true":
                value = True
            elif value == "false":
                value = False
            elif value.isdigit():
                value = int(value)

            # Skip empty optional values
            if value == "" and key in config_section and config_section[key] is None:
                continue

            config_section[key] = value

            if key in RESTART_REQUIRED:
                needs_restart = True

        save_config_document(admin_app.config_path, doc)
        logger.info("Settings [%s] updated by %s", section, session.user)

        # Signal hot-reload for non-restart settings
        if not needs_restart:
            from zabbix_mcp.admin.config_writer import signal_reload
            signal_reload()

    except Exception as e:
        logger.error("Failed to update settings: %s", e)

    return RedirectResponse("/settings", status_code=303)
