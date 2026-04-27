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
BOOL_KEYS = {"compact_output", "enabled", "update_check_enabled"}

# Map UI section names to actual config.toml section + allowed keys
SECTION_CONFIG = {
    "server": {
        "toml_section": "server",
        "allowed_keys": {"host", "port", "transport", "log_level", "log_file", "compact_output", "response_max_chars", "public_url"},
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
        # `enabled` intentionally NOT exposed: disabling the admin
        # portal from inside the admin portal is a foot-gun (operator
        # locks themselves out). To disable: edit config.toml directly
        # and restart.
        "allowed_keys": {"port", "update_check_enabled"},
        "min_role": "admin",
    },
    # [admin.ai] - optional sub-table driving the "Generate with AI"
    # button on the report template editor. Leaving api_key blank in
    # the form is treated as "keep existing" so the operator does not
    # have to paste their key every save.
    "admin_ai": {
        "toml_section": "admin.ai",
        "allowed_keys": {"enabled", "provider", "api_key", "model", "api_base", "timeout", "max_tokens"},
        "min_role": "admin",
    },
}

# Keys that must not be cleared when the submitted value is empty.
# The settings UI sends "" for api_key when the operator does not want
# to rotate the stored secret; treat that as "keep current value".
SECRET_KEEP_EMPTY = {"api_key"}


def _normalize_ip_entry(entry: str) -> str:
    """Return the canonical string form of an IP / CIDR entry.

    Collapses equivalent forms so a duplicate check can catch them:
        192.168.1.1            -> 192.168.1.1/32
        192.168.001.001        -> 192.168.1.1/32
        2001:db8::1            -> 2001:db8::1/128
        2001:0db8::0001        -> 2001:db8::1/128
    Raises ValueError for invalid input - callers should already
    have validated via ip_network() before calling this.
    """
    from ipaddress import ip_network
    return str(ip_network(entry, strict=False))


def _validate_list_entry(key: str, entry: str) -> str | None:
    """Per-list-key value sanity check. Returns an error string when
    the entry is malformed, None when OK.

    Catches bad input at form submit instead of letting it land in
    config.toml and bricking the next boot. Token IP Restriction
    already validates each line; this brings the global / settings
    parallel of that validation up to the same bar.

    Note: this is a per-entry check. Cross-entry checks (duplicate
    detection) live in the LIST_KEYS save loop because they need to
    see all entries together.
    """
    if key == "allowed_hosts":
        # Global IP allowlist - same shape as token allowed_ips.
        # Both IPv4 and IPv6 (with and without CIDR suffix) accepted.
        try:
            _normalize_ip_entry(entry)
        except (ValueError, TypeError):
            return f"'{entry}' is not a valid IPv4 / IPv6 address or CIDR range."
        return None
    if key == "cors_origins":
        # Browser CORS Origin header - must be scheme://host[:port],
        # no trailing path, no wildcards beyond '*'.
        if entry == "*":
            return None
        if not entry.startswith(("http://", "https://")):
            return f"CORS origin '{entry}' must start with http:// or https://"
        from urllib.parse import urlsplit
        try:
            parts = urlsplit(entry)
        except ValueError:
            return f"CORS origin '{entry}' is not a valid URL."
        if not parts.netloc:
            return f"CORS origin '{entry}' is missing a host."
        if parts.path not in ("", "/"):
            return f"CORS origin '{entry}' must not include a path - drop everything after the host[:port]."
        if parts.query or parts.fragment:
            return f"CORS origin '{entry}' must not include query / fragment - just scheme://host[:port]."
        return None
    if key == "allowed_import_dirs":
        # Filesystem path. Reject null bytes (Linux abuse) and
        # Windows-style backslashes that would break os.path checks.
        if "\x00" in entry:
            return f"Import directory '{entry}' contains a null byte."
        if not entry.startswith("/"):
            return f"Import directory '{entry}' must be an absolute path (start with /)."
        return None
    if key in ("tools", "disabled_tools"):
        # Tool group names + tool names. Whitelist against the
        # known catalog so a typo (e.g. 'monitorng') does not
        # silently disable nothing.
        from zabbix_mcp.config import TOOL_GROUPS, _expand_tool_groups
        all_groups = set(TOOL_GROUPS.keys())
        all_tools = set(_expand_tool_groups(list(TOOL_GROUPS.keys())))
        if entry not in all_groups and entry not in all_tools:
            return f"'{entry}' is not a known tool or tool group."
        return None
    return None

# Integer fields with explicit bounds. Without these, an operator can
# accidentally submit `timeout = 0` (request blocks until the AI
# provider gives up - minutes per call) or `max_tokens = 999999999`
# (one report exhausts the model's budget for a month). Caps land
# at safe-but-generous values and reject silently-broken extremes.
INT_BOUNDS = {
    "port":             (1, 65535),
    "rate_limit":       (0, 100000),
    "response_max_chars": (1024, 1_000_000),
    "timeout":          (5, 600),
    "max_tokens":       (256, 200_000),
}


from zabbix_mcp.admin.config_writer import config_mtime as _config_mtime  # re-export under old name


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
            settings["update_check_enabled"] = admin_cfg.get("update_check_enabled", True)

            # [admin.ai] sub-table. We expose the provider, model,
            # and enabled flag verbatim, but never the raw api_key -
            # instead we just report whether one is configured so the
            # UI can display "Key configured" without leaking it.
            ai_cfg = dict(admin_cfg.get("ai", {})) if isinstance(admin_cfg.get("ai"), dict) else {}
            # Default True matches AdminAIConfig.enabled so legacy
            # configs without the flag continue to show the feature as
            # enabled in the UI.
            settings["ai_enabled"] = bool(ai_cfg.get("enabled", True))
            settings["ai_provider"] = ai_cfg.get("provider", "")
            settings["ai_model"] = ai_cfg.get("model", "")
            settings["ai_api_base"] = ai_cfg.get("api_base", "")
            settings["ai_api_key_configured"] = bool(ai_cfg.get("api_key"))
            settings["ai_timeout"] = int(ai_cfg.get("timeout") or 180)
            settings["ai_max_tokens"] = int(ai_cfg.get("max_tokens") or 8000)
        except Exception as e:
            logger.error("Failed to read config: %s", e)

    return admin_app.render("settings.html", request, {
        "active": "settings",
        "settings": settings,
        "restart_required_fields": RESTART_REQUIRED,
        "has_legacy_token": has_legacy_token,
        "can_edit": session.role in ("admin", "operator"),
        "config_mtime": _config_mtime(admin_app.config_path),
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

    # Concurrent edit detection: the GET render embedded the
    # config.toml mtime into a hidden field. If another admin has
    # saved between then and now, refuse this submit so we don't
    # silently overwrite their change. Reported 2026-04-27.
    submitted_mtime = str(form.get("_cfg_mtime", "") or "")
    if submitted_mtime and submitted_mtime != _config_mtime(admin_app.config_path):
        return admin_app.flash_redirect(
            "/settings",
            "Another admin saved settings while you were editing. Reload to see the latest values, then re-apply your change.",
            "danger",
        )

    # Field-level validation: catch bad input before it lands in
    # config.toml and bricks the next server start.
    if "public_url" in allowed_keys and "public_url" in form:
        public_url_raw = str(form.get("public_url", "") or "").strip()
        if public_url_raw:
            try:
                from zabbix_mcp.config import _validate_public_url
                # Pass current tls_cert_file so https/http requirement
                # is enforced consistently with config.py validation.
                tls = getattr(admin_app.config.server, "tls_cert_file", None)
                _validate_public_url(public_url_raw, tls)
            except Exception as exc:
                return admin_app.flash_redirect(
                    "/settings", f"Public URL is invalid: {exc}", "danger"
                )

    try:
        doc = load_config_document(admin_app.config_path)
        import tomlkit

        # Snapshot the serialized TOML BEFORE any writes so we can
        # diff against the post-write version. If the operator hits
        # Save without actually changing anything (or reverts a
        # change), the dump is identical and we skip the
        # restart_needed flag entirely - reported 2026-04-17 as
        # "even with no changes - still pops out 'restart required'".
        # Per-field comparison was unreliable because of tomlkit
        # types vs Python types and config-default-vs-explicit edge
        # cases. File-content diff is bulletproof.
        try:
            old_dump = tomlkit.dumps(doc)
        except Exception:
            old_dump = None

        # Support dotted section names (e.g. "admin.ai" for nested
        # TOML sub-tables) by walking the path and creating missing
        # tables as we go.
        parts = config_section_name.split(".")
        config_section = doc
        for i, part in enumerate(parts):
            if part not in config_section:
                config_section.add(part, tomlkit.table())
            config_section = config_section[part]

        for key in allowed_keys:
            if key in BOOL_KEYS:
                config_section[key] = key in form
            elif key in LIST_KEYS:
                raw = str(form.get(key, "")).strip()
                if raw:
                    # Tools list comes from the drag-and-drop bubbles
                    # which use newline separators; everything else
                    # comes from comma-separated text inputs.
                    sep = "\n" if "\n" in raw else ","
                    parsed = [s.strip() for s in raw.split(sep) if s.strip()]
                    for entry in parsed:
                        err = _validate_list_entry(key, entry)
                        if err:
                            return admin_app.flash_redirect("/settings", err, "danger")
                    # Duplicate detection. For IP-typed keys we
                    # normalize first so 192.168.1.1 and 192.168.1.1/32
                    # collapse to the same canonical form (and IPv6
                    # variants like 2001:0db8::1 vs 2001:db8::1).
                    seen: dict[str, str] = {}
                    deduped: list[str] = []
                    for entry in parsed:
                        if key == "allowed_hosts":
                            try:
                                key_norm = _normalize_ip_entry(entry)
                            except ValueError:
                                key_norm = entry  # validator above would have caught it
                        else:
                            key_norm = entry
                        if key_norm in seen:
                            return admin_app.flash_redirect(
                                "/settings",
                                f"Duplicate entry: '{entry}' is the same as '{seen[key_norm]}'.",
                                "danger",
                            )
                        seen[key_norm] = entry
                        deduped.append(entry)
                    config_section[key] = deduped
                elif key in config_section:
                    del config_section[key]
            elif key in form:
                value = str(form.get(key, "")).strip()
                if value == "":
                    # Secrets like api_key: blank form value means
                    # "don't touch the stored value" so the operator
                    # does not have to re-paste the key on every save.
                    if key in SECRET_KEEP_EMPTY:
                        continue
                    if key in config_section:
                        del config_section[key]
                    continue
                if value.isdigit():
                    value = int(value)
                    bounds = INT_BOUNDS.get(key)
                    if bounds is not None:
                        lo, hi = bounds
                        if value < lo or value > hi:
                            return admin_app.flash_redirect(
                                "/settings",
                                f"Value for '{key}' is out of range. Must be between {lo} and {hi}.",
                                "danger",
                            )
                config_section[key] = value
            else:
                continue

        # File-content diff: only flag restart if the serialized TOML
        # actually differs from before. Replaces the previous
        # per-field old_cmp/new_cmp string comparison which had false
        # positives for boolean and list types coming from tomlkit.
        try:
            new_dump = tomlkit.dumps(doc)
        except Exception:
            new_dump = None
        needs_restart = (old_dump is None or new_dump is None or old_dump != new_dump)

        save_config_document(admin_app.config_path, doc)
        logger.info("Settings [%s] updated by %s", section, session.user)
        from zabbix_mcp.admin.audit_writer import write_audit
        client_ip = request.client.host if request.client else ""
        write_audit("settings_update", user=session.user, target_type="settings", target_id=section, ip=client_ip)

        if needs_restart:
            admin_app.restart_needed = True

        msg = "Settings saved."
        if needs_restart:
            msg += " Restart required to apply changes."
        return admin_app.flash_redirect("/settings", msg)

    except Exception as e:
        logger.error("Failed to update settings: %s", e)
        return admin_app.flash_redirect("/settings", f"Failed to save settings: {e}", "danger")
