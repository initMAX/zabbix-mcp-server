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
LIST_KEYS = {"cors_origins", "allowed_hosts", "allowed_origins", "allowed_import_dirs", "tools", "disabled_tools", "trusted_proxies", "default_scopes"}

# Boolean fields — checkbox present = True, absent = False
BOOL_KEYS = {"compact_output", "enabled", "update_check_enabled", "log_portal_operations", "log_mcp_actions", "log_background_events", "housekeeping_enabled", "dynamic_registration_enabled", "start_tls"}

# Secret fields - blank form value means "keep existing" rather than
# "clear". Mirrors api_key handling for [admin.ai].
SECRET_KEEP_EMPTY_EXTRA = {"bind_password", "graph_client_secret", "x509_certificate"}

# Map UI section names to actual config.toml section + allowed keys
SECTION_CONFIG = {
    "server": {
        "toml_section": "server",
        "allowed_keys": {"host", "port", "transport", "log_level", "log_file", "compact_output", "response_max_chars", "tool_prefix", "public_url"},
        "min_role": "admin",
    },
    "tls_access": {
        "toml_section": "server",
        "allowed_keys": {"tls_cert_file", "tls_key_file", "cors_origins", "allowed_hosts", "allowed_origins", "allowed_import_dirs", "rate_limit"},
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
    # [audit] - the four user-visible knobs from the Settings -> Audit
    # log panel. Mirror the Zabbix admin-panel UX 1:1 (same field
    # names, same defaults, same Reset defaults semantics).
    "audit": {
        "toml_section": "audit",
        "allowed_keys": {"enabled", "log_portal_operations", "log_mcp_actions", "log_background_events", "housekeeping_enabled", "data_storage_period", "max_file_size_mb"},
        "min_role": "admin",
    },
    # [audit.forward] - external SIEM / syslog forwarder. Optional.
    # The settings page persists the destination + protocol config;
    # the runtime forwarder daemon lands in a follow-up commit.
    "audit_forward": {
        "toml_section": "audit.forward",
        "allowed_keys": {"enabled", "host", "port", "protocol", "ca_cert", "queue_size"},
        "min_role": "admin",
    },
    # [oauth] - full editor for the embedded OAuth 2.1 server. The
    # OAuth Clients page has a first-time enable form (sets `enabled`
    # + `public_url`); this section is the long-term config surface
    # for everything else (TTLs, default scopes, DCR profile).
    "oauth": {
        "toml_section": "oauth",
        "allowed_keys": {
            "enabled", "dynamic_registration_enabled", "default_scopes",
            "auth_code_ttl_seconds", "access_token_ttl_seconds",
            "refresh_token_ttl_seconds", "dcr_profile",
            "dcr_conservative_access_ttl_seconds",
        },
        "min_role": "admin",
    },
    # [server].trusted_proxies - reverse-proxy IP allowlist that the
    # ASGI middleware trusts when reading X-Forwarded-For. Lives under
    # [server] but exposed as its own UI section so operators can find
    # it without digging through the dense TLS / Network panel.
    "trusted_proxies": {
        "toml_section": "server",
        "allowed_keys": {"trusted_proxies"},
        "min_role": "admin",
    },
    # [admin.saml] - SAML SSO config editor (issue #46).
    "admin_saml": {
        "toml_section": "admin.saml",
        "allowed_keys": {
            "enabled", "display_name", "idp_entity_id", "idp_sso_url",
            "idp_slo_url", "x509_certificate",
            "email_attribute", "first_name_attribute", "last_name_attribute",
            "photo_url_attribute", "default_role",
            "graph_client_id", "graph_client_secret", "graph_tenant_id",
        },
        "min_role": "admin",
    },
    # [admin.ldap] - LDAP / AD config editor (issue #46).
    "admin_ldap": {
        "toml_section": "admin.ldap",
        "allowed_keys": {
            "enabled", "display_name", "server", "start_tls", "timeout_seconds",
            "bind_dn", "bind_password", "base_dn",
            "user_search_filter", "group_search_filter", "default_role",
            "ca_cert",
        },
        "min_role": "admin",
    },
}

# Keys that must not be cleared when the submitted value is empty.
# The settings UI sends "" for api_key when the operator does not want
# to rotate the stored secret; treat that as "keep current value".
SECRET_KEEP_EMPTY = {"api_key"} | SECRET_KEEP_EMPTY_EXTRA


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
    if key in ("allowed_hosts", "trusted_proxies"):
        # IP allowlist / trusted-proxy CIDRs - same shape. Both IPv4
        # and IPv6, with or without explicit CIDR suffix.
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
    if key == "allowed_origins":
        # MCP 2025-11-25 DNS-rebinding allowlist. Same shape as cors_origins
        # except FastMCP's TransportSecurityMiddleware ALSO accepts the
        # ``host:*`` port-wildcard suffix (e.g. ``https://app.example.com:*``)
        # to cover varying client ports without listing each one.
        if not entry.startswith(("http://", "https://")):
            return f"Origin '{entry}' must start with http:// or https://"
        from urllib.parse import urlsplit
        # Strip optional ``:*`` port-wildcard before URL parsing - urlsplit
        # rejects '*' as a port. The wildcard is FastMCP-internal syntax.
        probe = entry[:-2] if entry.endswith(":*") else entry
        try:
            parts = urlsplit(probe)
        except ValueError:
            return f"Origin '{entry}' is not a valid URL."
        if not parts.hostname:
            return f"Origin '{entry}' is missing a host."
        if parts.path not in ("", "/"):
            return f"Origin '{entry}' must not include a path - drop everything after the host[:port]."
        if parts.query or parts.fragment:
            return f"Origin '{entry}' must not include query / fragment - just scheme://host[:port]."
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
    # OAuth TTLs (seconds). Lower bounds intentionally non-zero so the
    # operator cannot accidentally configure a useless 0-second TTL.
    "auth_code_ttl_seconds":              (60, 3600),         # 1 min - 1h
    "access_token_ttl_seconds":           (300, 86400),       # 5 min - 24h
    "refresh_token_ttl_seconds":          (3600, 31536000),   # 1h - 1y
    "dcr_conservative_access_ttl_seconds": (300, 86400),
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

            # [audit] section. Surface the four user-visible knobs +
            # the rotation size, sourced from runtime state so the form
            # reflects what the audit writer is actually applying right
            # now (not stale config.toml content if the operator just
            # toggled something).
            try:
                from zabbix_mcp.admin.audit_writer import get_runtime_state
                _aw_state = get_runtime_state()
            except Exception:
                _aw_state = {
                    "enabled": True,
                    "log_portal_operations": True,
                    "log_mcp_actions": True,
                    "log_background_events": True,
                    "housekeeping_enabled": True, "retention_seconds": 31 * 86400,
                    "max_file_size_bytes": 50 * 1024 * 1024,
                }
            audit_cfg = dict(doc.get("audit", {})) if isinstance(doc.get("audit"), dict) else {}
            settings["audit_enabled"] = bool(_aw_state["enabled"])
            settings["audit_log_portal_operations"] = bool(_aw_state["log_portal_operations"])
            settings["audit_log_mcp_actions"] = bool(_aw_state["log_mcp_actions"])
            settings["audit_log_background_events"] = bool(_aw_state["log_background_events"])
            settings["audit_housekeeping_enabled"] = bool(_aw_state["housekeeping_enabled"])
            settings["audit_data_storage_period"] = (
                str(audit_cfg.get("data_storage_period") or "31d")
            )
            settings["audit_max_file_size_mb"] = int(_aw_state["max_file_size_bytes"]) // (1024 * 1024)

            # [audit.forward] - external forwarder destination. Read
            # straight from the doc; the runtime forwarder daemon
            # picks these values up at next reload.
            forward_cfg = dict(audit_cfg.get("forward", {})) if isinstance(audit_cfg.get("forward"), dict) else {}
            settings["audit_forward_enabled"] = bool(forward_cfg.get("enabled", False))
            settings["audit_forward_host"] = str(forward_cfg.get("host") or "")
            settings["audit_forward_port"] = int(forward_cfg.get("port") or 514)
            settings["audit_forward_protocol"] = str(forward_cfg.get("protocol") or "rfc5424_udp")
            settings["audit_forward_ca_cert"] = str(forward_cfg.get("ca_cert") or "")
            settings["audit_forward_queue_size"] = int(forward_cfg.get("queue_size") or 10000)
            try:
                from zabbix_mcp.admin import audit_forwarder as _afw
                _fwd_state = _afw.get_runtime_state()
            except Exception:
                _fwd_state = {
                    "connection_state": "stopped", "queue_depth": 0,
                    "messages_sent": 0, "messages_failed": 0,
                    "messages_dropped_queue_full": 0,
                    "last_success_at": None, "last_error": "",
                }
            settings["audit_forward_status"] = _fwd_state

            # [oauth] - read all knobs from the doc so the form
            # round-trips operator edits exactly. Defaults match
            # OAuthConfig.
            oauth_cfg = dict(doc.get("oauth", {})) if isinstance(doc.get("oauth"), dict) else {}
            settings["oauth_enabled"] = bool(oauth_cfg.get("enabled", False))
            settings["oauth_dynamic_registration_enabled"] = bool(oauth_cfg.get("dynamic_registration_enabled", True))
            ds = oauth_cfg.get("default_scopes", ["*"])
            if isinstance(ds, str):
                ds = [ds]
            settings["oauth_default_scopes"] = list(ds) if ds else ["*"]
            settings["oauth_auth_code_ttl_seconds"] = int(oauth_cfg.get("auth_code_ttl_seconds") or 600)
            settings["oauth_access_token_ttl_seconds"] = int(oauth_cfg.get("access_token_ttl_seconds") or 3600)
            settings["oauth_refresh_token_ttl_seconds"] = int(oauth_cfg.get("refresh_token_ttl_seconds") or 30 * 24 * 3600)
            settings["oauth_dcr_profile"] = str(oauth_cfg.get("dcr_profile", "conservative") or "conservative")
            settings["oauth_dcr_conservative_access_ttl_seconds"] = int(oauth_cfg.get("dcr_conservative_access_ttl_seconds") or 1800)

            # [server].trusted_proxies - CIDR allowlist for X-Forwarded-For.
            tp = server_cfg.get("trusted_proxies", [])
            if isinstance(tp, str):
                tp = [tp]
            settings["trusted_proxies"] = list(tp) if tp else []

            # [admin.saml] - SAML SSO config editor (issue #46).
            saml_cfg = dict(admin_cfg.get("saml", {})) if isinstance(admin_cfg.get("saml"), dict) else {}
            settings["saml_enabled"] = bool(saml_cfg.get("enabled", False))
            settings["saml_display_name"] = str(saml_cfg.get("display_name", "Sign in with SAML") or "Sign in with SAML")
            settings["saml_idp_entity_id"] = str(saml_cfg.get("idp_entity_id", "") or "")
            settings["saml_idp_sso_url"] = str(saml_cfg.get("idp_sso_url", "") or "")
            settings["saml_idp_slo_url"] = str(saml_cfg.get("idp_slo_url", "") or "")
            settings["saml_x509_certificate_configured"] = bool(saml_cfg.get("x509_certificate"))
            settings["saml_email_attribute"] = str(saml_cfg.get("email_attribute") or "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress")
            settings["saml_first_name_attribute"] = str(saml_cfg.get("first_name_attribute") or "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname")
            settings["saml_last_name_attribute"] = str(saml_cfg.get("last_name_attribute") or "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname")
            settings["saml_photo_url_attribute"] = str(saml_cfg.get("photo_url_attribute", "") or "")
            settings["saml_default_role"] = str(saml_cfg.get("default_role", "viewer") or "viewer")
            settings["saml_graph_client_id"] = str(saml_cfg.get("graph_client_id", "") or "")
            settings["saml_graph_client_secret_configured"] = bool(saml_cfg.get("graph_client_secret"))
            settings["saml_graph_tenant_id"] = str(saml_cfg.get("graph_tenant_id", "") or "")

            # [admin.ldap] - LDAP / AD config editor (issue #46).
            ldap_cfg = dict(admin_cfg.get("ldap", {})) if isinstance(admin_cfg.get("ldap"), dict) else {}
            settings["ldap_enabled"] = bool(ldap_cfg.get("enabled", False))
            settings["ldap_display_name"] = str(ldap_cfg.get("display_name", "Sign in with LDAP") or "Sign in with LDAP")
            settings["ldap_server"] = str(ldap_cfg.get("server", "") or "")
            settings["ldap_start_tls"] = bool(ldap_cfg.get("start_tls", True))
            settings["ldap_timeout_seconds"] = int(ldap_cfg.get("timeout_seconds") or 5)
            settings["ldap_bind_dn"] = str(ldap_cfg.get("bind_dn", "") or "")
            settings["ldap_bind_password_configured"] = bool(ldap_cfg.get("bind_password"))
            settings["ldap_base_dn"] = str(ldap_cfg.get("base_dn", "") or "")
            settings["ldap_user_search_filter"] = str(ldap_cfg.get("user_search_filter") or "(&(objectClass=person)(sAMAccountName={username}))")
            settings["ldap_group_search_filter"] = str(ldap_cfg.get("group_search_filter") or "(member={user_dn})")
            settings["ldap_default_role"] = str(ldap_cfg.get("default_role", "") or "")
            settings["ldap_ca_cert"] = str(ldap_cfg.get("ca_cert", "") or "")
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

    # [oauth] pre-save validation: dcr_profile enum + TTL bounds
    # come from INT_BOUNDS via the generic int handler. Default scopes
    # checkboxes - submitted as repeated form values per scope.
    if section == "oauth":
        prof = str(form.get("dcr_profile", "") or "").strip().lower()
        if prof and prof not in ("conservative", "permissive"):
            return admin_app.flash_redirect(
                "/settings",
                "DCR profile must be 'conservative' or 'permissive'.",
                "danger",
            )

    # [audit.forward] pre-save validation: protocol enum + port range
    # + queue size bounds.
    if section == "audit_forward":
        valid_protocols = {
            "rfc5424_udp", "rfc5424_tcp", "rfc5424_tls",
            "cef_udp", "cef_tcp", "cef_tls",
            "leef_udp", "leef_tcp", "leef_tls",
            "json_tcp", "json_tls",
        }
        protocol_raw = str(form.get("protocol", "") or "").strip().lower()
        if protocol_raw and protocol_raw not in valid_protocols:
            return admin_app.flash_redirect(
                "/settings",
                f"Forwarder protocol must be one of {sorted(valid_protocols)}",
                "danger",
            )
        port_raw = str(form.get("port", "") or "").strip()
        if port_raw:
            if not port_raw.isdigit():
                return admin_app.flash_redirect(
                    "/settings", "Forwarder port must be a positive integer.", "danger",
                )
            n = int(port_raw)
            if n < 1 or n > 65535:
                return admin_app.flash_redirect(
                    "/settings", "Forwarder port must be between 1 and 65535.", "danger",
                )
        queue_raw = str(form.get("queue_size", "") or "").strip()
        if queue_raw:
            if not queue_raw.isdigit():
                return admin_app.flash_redirect(
                    "/settings", "Queue size must be a positive integer.", "danger",
                )
            n = int(queue_raw)
            if n < 100 or n > 1000000:
                return admin_app.flash_redirect(
                    "/settings", "Queue size must be between 100 and 1,000,000.", "danger",
                )
        # If the operator enables forwarding, host is mandatory -
        # otherwise the daemon would dial nothing and silently fail.
        if "enabled" in form:
            host_raw = str(form.get("host", "") or "").strip()
            if not host_raw:
                return admin_app.flash_redirect(
                    "/settings",
                    "Forwarder host is required when forwarding is enabled.",
                    "danger",
                )

    # [audit] section pre-save validation: parse the Zabbix-style time
    # period so the operator gets a clean error instead of a startup
    # ConfigError on the next reload.
    if section == "audit":
        period_raw = str(form.get("data_storage_period", "") or "").strip()
        if period_raw:
            try:
                from zabbix_mcp.config import parse_time_period
                parse_time_period(period_raw, default_unit="d")
            except Exception as exc:
                return admin_app.flash_redirect(
                    "/settings", f"Data storage period: {exc}", "danger"
                )
        size_raw = str(form.get("max_file_size_mb", "") or "").strip()
        if size_raw:
            if not size_raw.isdigit():
                return admin_app.flash_redirect(
                    "/settings",
                    "Max file size must be a positive integer (MB).",
                    "danger",
                )
            n = int(size_raw)
            if n < 1 or n > 4096:
                return admin_app.flash_redirect(
                    "/settings",
                    "Max file size must be between 1 and 4096 MB.",
                    "danger",
                )
        # Disabling audit is a compliance-relevant event. Require an
        # explicit confirm checkbox so an accidental click does not
        # silently turn the audit off.
        master_box = "enabled" in form
        currently_on = bool(admin_app.config.audit.enabled)
        if currently_on and not master_box:
            confirm = str(form.get("disable_confirm", "") or "").strip().upper()
            if confirm != "DISABLE":
                return admin_app.flash_redirect(
                    "/settings",
                    "To disable audit logging, type DISABLE in the confirmation field. "
                    "Audit logging is required by ISO 27001, SOC 2, NIS2 and similar "
                    "compliance frameworks; this action is itself audited.",
                    "danger",
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
                # Three input shapes get folded into the same parsed list:
                # (1) repeated form fields (checkbox group, e.g.
                #     default_scopes - one <input name=default_scopes value=X>
                #     per ticked scope), (2) tools drag-and-drop bubbles using
                #     newline-separated text, (3) comma-separated text input.
                multi = form.getlist(key) if hasattr(form, "getlist") else []
                if len(multi) > 1:
                    parsed = [str(v).strip() for v in multi if str(v).strip()]
                    raw = ",".join(parsed)
                else:
                    raw = str(form.get(key, "")).strip()
                if raw:
                    if len(multi) > 1:
                        # already parsed above
                        pass
                    else:
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
                # tool_prefix has the same regex constraint at the config
                # parser; mirror it here so the operator gets a clean
                # validation message instead of a startup ConfigError on
                # the next reload.
                if key == "tool_prefix" and isinstance(value, str) and value:
                    try:
                        from zabbix_mcp.config import _validate_tool_prefix
                        _validate_tool_prefix(value)
                    except Exception as exc:
                        return admin_app.flash_redirect(
                            "/settings", str(exc), "danger",
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

        # [admin] section: apply update-check toggle at runtime so the
        # operator does not have to restart the server to flip the
        # "Notify me when a newer version is released" switch. The
        # checker exposes start(enabled=...) which is idempotent and
        # safe to call multiple times.
        if section == "admin":
            try:
                from zabbix_mcp.admin.update_check import get_checker
                get_checker().start(enabled=bool(config_section.get("update_check_enabled", True)))
            except Exception:
                logger.exception("Failed to apply update-check toggle after settings save")

        # [audit.forward] section: re-configure the running forwarder
        # daemon without restart. configure() is idempotent and the
        # worker thread re-reads its destination on the next loop.
        if section == "audit_forward":
            try:
                from zabbix_mcp.admin import audit_forwarder as _afw
                _afw.configure(
                    enabled=bool(config_section.get("enabled", False)),
                    host=str(config_section.get("host", "") or ""),
                    port=int(config_section.get("port", 514) or 514),
                    protocol=str(config_section.get("protocol", "rfc5424_udp") or "rfc5424_udp"),
                    ca_cert=str(config_section.get("ca_cert", "") or ""),
                    queue_size=int(config_section.get("queue_size", 10000) or 10000),
                )
                _afw.start()
            except Exception:
                logger.exception("Failed to apply audit forwarder config after settings save")

        # [audit] section: apply runtime knobs without restart and
        # record a dedicated audit.toggle row when the master switch
        # flipped. The toggle row uses an action name that bypasses
        # the master gate so a "disable audit" event is always
        # recorded - see audit_writer._ALWAYS_AUDIT_ACTIONS.
        if section == "audit":
            from zabbix_mcp.admin import audit_writer as _aw
            from zabbix_mcp.config import parse_time_period
            try:
                period_raw_saved = str(config_section.get("data_storage_period", "31d"))
                size_mb_saved = int(config_section.get("max_file_size_mb", 50))
                new_state = {
                    "enabled": bool(config_section.get("enabled", True)),
                    "log_portal_operations": bool(config_section.get("log_portal_operations", True)),
                    "log_mcp_actions": bool(config_section.get("log_mcp_actions", True)),
                    "log_background_events": bool(config_section.get("log_background_events", True)),
                    "housekeeping_enabled": bool(config_section.get("housekeeping_enabled", True)),
                    "retention_seconds": parse_time_period(period_raw_saved, default_unit="d"),
                    "max_file_size_bytes": size_mb_saved * 1024 * 1024,
                }
                old_state = _aw.get_runtime_state()
                _aw.configure(**new_state)
                if new_state["housekeeping_enabled"]:
                    _aw.start_housekeeping()
                if old_state["enabled"] != new_state["enabled"]:
                    _aw.write_audit(
                        "audit.toggle",
                        user=session.user,
                        target_type="audit",
                        target_id="enabled",
                        details={
                            "from": old_state["enabled"],
                            "to": new_state["enabled"],
                        },
                        ip=client_ip,
                    )
            except Exception:
                logger.exception("Failed to apply audit runtime config after settings save")

        if needs_restart:
            admin_app.restart_needed = True

        msg = "Settings saved."
        if needs_restart:
            msg += " Restart required to apply changes."
        return admin_app.flash_redirect("/settings", msg)

    except Exception as e:
        logger.error("Failed to update settings: %s", e)
        return admin_app.flash_redirect("/settings", f"Failed to save settings: {e}", "danger")
