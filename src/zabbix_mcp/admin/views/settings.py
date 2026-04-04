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
RESTART_REQUIRED = {"host", "port", "transport", "tls_cert_file", "tls_key_file", "log_file"}

# List fields — split comma-separated into TOML arrays
LIST_KEYS = {"cors_origins", "allowed_hosts", "allowed_import_dirs", "tools", "disabled_tools"}

# Boolean fields — checkbox present = True, absent = False
BOOL_KEYS = {"compact_output", "enabled"}

# Map UI section names to actual config.toml section + allowed keys
SECTION_CONFIG = {
    "server": {
        "toml_section": "server",
        "allowed_keys": {"host", "port", "transport", "log_level", "log_file", "compact_output"},
        "min_role": "admin",
    },
    "tls_access": {
        "toml_section": "server",
        "allowed_keys": {"tls_cert_file", "tls_key_file", "cors_origins", "allowed_hosts", "allowed_import_dirs", "rate_limit"},
        "min_role": "admin",
    },
    "tools": {
        "toml_section": "server",
        "allowed_keys": {"tools", "disabled_tools"},
        "min_role": "admin",
    },
    "reporting": {
        "toml_section": "server",
        "allowed_keys": {"report_company", "report_subtitle", "report_logo"},
        "min_role": "operator",
    },
    "admin": {
        "toml_section": "admin",
        "allowed_keys": {"enabled", "port"},
        "min_role": "admin",
    },
}


async def settings_view(request: Request) -> Response:
    admin_app = request.app.state.admin_app
    session = admin_app.require_auth(request)
    if not session:
        return RedirectResponse("/login", status_code=303)

    # Read current config — keep server and admin sections separate
    settings: dict = {}
    has_legacy_token = False

    if TOMLKIT_AVAILABLE:
        try:
            doc = load_config_document(admin_app.config_path)
            server_cfg = dict(doc.get("server", {}))
            admin_cfg = dict(doc.get("admin", {}))

            # Detect legacy auth_token
            if server_cfg.get("auth_token"):
                has_legacy_token = True

            # Remove sensitive values
            server_cfg.pop("auth_token", None)
            # Remove users sub-table from admin display
            admin_cfg.pop("users", None)

            # Merge server fields directly
            settings.update(server_cfg)

            # Admin fields — prefix to avoid collision (both have "port")
            settings["admin_enabled"] = admin_cfg.get("enabled", False)
            settings["admin_port"] = admin_cfg.get("port", 9090)
        except Exception as e:
            logger.error("Failed to read config: %s", e)

    return admin_app.render("settings.html", request, {
        "active": "settings",
        "settings": settings,
        "restart_required_fields": RESTART_REQUIRED,
        "has_legacy_token": has_legacy_token,
        "can_edit": session.role in ("admin", "operator"),
    })


async def settings_update(request: Request) -> Response:
    admin_app = request.app.state.admin_app
    session = admin_app.require_auth(request)
    if not session or session.role not in ("admin", "operator"):
        return RedirectResponse("/settings", status_code=303)

    section = request.path_params["section"]
    section_cfg = SECTION_CONFIG.get(section)
    if not section_cfg:
        return RedirectResponse("/settings", status_code=303)

    # Check minimum role for this section
    if section_cfg["min_role"] == "admin" and session.role != "admin":
        logger.warning("User '%s' (role=%s) denied access to settings/%s", session.user, session.role, section)
        return RedirectResponse("/settings", status_code=303)

    config_section_name = section_cfg["toml_section"]
    allowed_keys = section_cfg["allowed_keys"]

    form = await request.form()

    try:
        doc = load_config_document(admin_app.config_path)

        if config_section_name not in doc:
            import tomlkit
            doc.add(config_section_name, tomlkit.table())

        config_section = doc[config_section_name]

        needs_restart = False

        for key in allowed_keys:
            if key in BOOL_KEYS:
                config_section[key] = key in form
            elif key in LIST_KEYS:
                raw = str(form.get(key, "")).strip()
                if raw:
                    config_section[key] = [s.strip() for s in raw.split(",") if s.strip()]
                else:
                    # Remove key if empty (use default)
                    if key in config_section:
                        del config_section[key]
            elif key in form:
                value = str(form.get(key, "")).strip()
                if value == "":
                    # Empty string — remove key to use default
                    if key in config_section:
                        del config_section[key]
                    continue
                # Type conversion
                if value.isdigit():
                    value = int(value)
                config_section[key] = value

            if key in RESTART_REQUIRED:
                needs_restart = True

        save_config_document(admin_app.config_path, doc)
        logger.info("Settings [%s] updated by %s", section, session.user)

        if not needs_restart:
            from zabbix_mcp.admin.config_writer import signal_reload
            signal_reload()

    except Exception as e:
        logger.error("Failed to update settings: %s", e)

    return RedirectResponse("/settings", status_code=303)
