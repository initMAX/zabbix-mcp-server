#
# Zabbix MCP Server
# Copyright (C) 2026 initMAX s.r.o.
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License as published by the Free
# Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
# details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#

"""Login + consent UI for the embedded OAuth 2.1 authorization flow.

Lives on the MCP server's HTTP port (not the admin portal) so the
authorize redirect chain stays on a single origin. The view validates
operator credentials against the existing admin-portal user table
(``[admin.users.*]`` in config.toml, scrypt-hashed) so OAuth does not
introduce a second identity store.

The page reuses the admin portal's Jinja2 templates and ``style.css``
so the login surface looks identical to the portal's own login screen
(theme switcher, logo, light/dark variables).  The MCP server mounts
the same ``admin/static`` directory at ``/static/`` for that purpose.

Flow:

1. The framework's authorize handler calls
   ``ZmcpOAuthProvider.authorize`` which stashes the pending request
   and returns ``<public_url>/oauth/login?request_id=<opaque>``.
   FastMCP redirects the user-agent there.
2. GET renders a login form + a consent block listing the scopes the
   client asked for plus the scopes the server is willing to grant.
3. POST verifies username + password against ``[admin.users.*]``,
   calls ``provider.complete_pending(request_id, granted_scopes,
   subject)`` to mint the authorization code, then 302's to the
   client's redirect_uri (carrying ``code`` and ``state``).
"""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from typing import Any

import jinja2
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

from zabbix_mcp import __version__ as _zmcp_version
from zabbix_mcp.admin.auth import LoginRateLimiter

logger = logging.getLogger("zabbix_mcp.oauth_login")

# Per-IP brute-force throttle for /oauth/login.  Same parameters as the
# admin portal's /login (5 attempts per 5 minutes per IP) so an attacker
# does not get a softer surface here just because the OAuth flow is on
# a different port.  Single instance shared across requests via module
# scope - this module is imported once per server process.
_oauth_login_limiter = LoginRateLimiter()

# Reuse the admin portal's Jinja env so the login + error pages look
# identical to the portal's own login surface (logo, palette, theme
# switcher, ``style.css``).  Templates referenced below MUST live in
# ``plugins/zabbix/zabbix_mcp/admin/templates/``.
_TEMPLATE_DIR = Path(__file__).parent / "admin" / "templates"
_jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(str(_TEMPLATE_DIR)),
    autoescape=jinja2.select_autoescape(["html"]),
)


def _render_template(name: str, **ctx: Any) -> str:
    tmpl = _jinja_env.get_template(name)
    return tmpl.render(
        version=_zmcp_version,
        year=datetime.now().year,
        **ctx,
    )


def _render_error_page(message: str, *, status_code: int = 400) -> HTMLResponse:
    body = _render_template("oauth_error.html", message=message)
    return HTMLResponse(body, status_code=status_code)


# ---------------------------------------------------------------------------
# Admin user authentication
# ---------------------------------------------------------------------------


# Role -> maximum OAuth scope an operator with that role may grant
# to a third-party MCP client.  An operator cannot grant a scope wider
# than their own admin-portal role allows; this is the OAuth-side
# expression of "least privilege" the admin portal already enforces
# elsewhere.
_ROLE_SCOPE_CAP: dict[str, set[str]] = {
    "admin":    {"*"},
    "operator": {"monitoring", "data_collection", "alerts", "extensions"},
    "viewer":   {"monitoring", "extensions"},
}


def _verify_admin_user(config: Any, username: str, password: str) -> tuple[bool, str]:
    """Validate (username, password) against [admin.users.*] in config.

    Returns ``(authenticated, role)``.  ``role`` is the empty string
    when authentication failed.  Wrong username and wrong password
    both return False with the same code path so the response time
    does not leak which side mismatched.
    """
    if not username or not password:
        return False, ""
    cfg_path = getattr(config, "_config_path", None)
    if not cfg_path:
        return False, ""
    try:
        from zabbix_mcp.admin.config_writer import load_config_document
        from zabbix_mcp.admin.auth import verify_password
        doc = load_config_document(cfg_path)
        users = (doc.get("admin", {}) or {}).get("users", {}) or {}
        user = users.get(username)
        if user is None:
            return False, ""
        if user.get("disabled"):
            return False, ""
        if not verify_password(password, str(user.get("password_hash", ""))):
            return False, ""
        return True, str(user.get("role", "viewer") or "viewer")
    except Exception as exc:  # pragma: no cover
        logger.warning("Admin user verification failed for %s: %s", username, exc)
        return False, ""


def _scope_cap_for_role(role: str) -> set[str]:
    """Return the set of OAuth scope IDs an operator with ``role`` may grant."""
    return _ROLE_SCOPE_CAP.get(role, _ROLE_SCOPE_CAP["viewer"])


# ---------------------------------------------------------------------------
# Per-plugin tool catalog for the v1.31 consent screen
# ---------------------------------------------------------------------------
# v1.30 / earlier consent rendered a flat list of six tool-group rows
# (monitoring, alerts, ...) each with an opaque "X tools" badge. v1.31
# breaks the catalog down per plugin (today: just the bundled Zabbix
# module; future: NetBox / Nagios / Jira / FastSpring) AND down to
# individual tools so the operator can grant exactly what the client
# needs. The plugin section header has a Read-only / Read+Write toggle
# (cascades to per-tool checkboxes) plus an expandable per-tool list
# with search filter.

# One-line descriptions for the extension tools that are NOT covered by
# ALL_METHODS (those live as direct mcp.add_tool registrations in
# server.py and have no MethodDef). Keep in sync with the extension
# tool registrations.
_EXTENSION_TOOL_DESCRIPTIONS: dict[str, str] = {
    "graph_render": "Render a Zabbix graph as a PNG (returned as base64 data URL).",
    "anomaly_detect": "Z-score anomaly check over a metric history window.",
    "capacity_forecast": "Linear-regression forecast for items projecting to a threshold.",
    "item_threshold_search": "List items whose lastvalue crosses operator-supplied numeric thresholds.",
    "problem_active_get": "Active-only problems pre-filtered for disabled triggers / hosts and Information / Not classified noise.",
    "host_status_get": "Host + interfaces + active problems + last-value of top items in one call.",
    "hostgroup_overview_get": "Host group health roll-up with the top-N noisiest hosts.",
    "infrastructure_summary_get": "Whole-deployment dashboard summary (problem counts by severity, top groups, biggest hostgroups).",
    "item_history_summary_get": "Item metadata + history window + min/max/avg over the period.",
    "report_generate": "Generate a PDF report from a registered template (long-running, supports Tasks API).",
    "action_prepare": "Stage 1 of two-step write approval: stash the action and return a confirmation token.",
    "action_confirm": "Stage 2 of two-step write approval: execute the previously prepared action.",
    "zabbix_raw_api_call": "Admin escape hatch - call any Zabbix API method by name. Required for methods this server does not wrap.",
    "health_check": "Verify MCP server status and connectivity to all configured Zabbix servers.",
}


def _build_tool_catalog() -> list[dict[str, Any]]:
    """Return one row per registered tool, with metadata for the consent UI.

    Iterates ALL_METHODS (the wrapped Zabbix API methods) plus the
    standalone extension tools registered in server.py. Each row carries
    the canonical tool name (no plugin prefix), a one-line description,
    a write classification (drives the Read-only / Read+Write toggle),
    and the tool group it belongs to (drives the in-page sub-section
    headers).
    """
    from zabbix_mcp.api import ALL_METHODS
    from zabbix_mcp.config import TOOL_GROUPS

    # Map prefix -> first group it appears in (consistent with how
    # _expand_tool_groups treats overlapping groups; e.g. "host" appears
    # in monitoring -> use that as the canonical group label).
    prefix_to_group: dict[str, str] = {}
    for group, prefixes in TOOL_GROUPS.items():
        for p in prefixes:
            prefix_to_group.setdefault(p, group)

    catalog: list[dict[str, Any]] = []
    for m in ALL_METHODS:
        prefix = m.tool_name.rsplit("_", 1)[0] if "_" in m.tool_name else m.tool_name
        # Pre-correlated views (host_status_get etc.) have full names in
        # TOOL_GROUPS["extensions"] so check that first.
        if m.tool_name in prefix_to_group:
            group = prefix_to_group[m.tool_name]
        else:
            group = prefix_to_group.get(prefix, "other")
        first_line = (m.description or "").splitlines()[0].strip()
        catalog.append({
            "name": m.tool_name,
            "description": first_line[:160],
            "is_write": not m.read_only,
            "group": group,
        })

    # Add extension tools that are not wrapped via MethodDef. These are
    # direct registrations in server.py and need explicit descriptions.
    seen = {row["name"] for row in catalog}
    for name in TOOL_GROUPS.get("extensions", []):
        if name in seen:
            continue
        desc = _EXTENSION_TOOL_DESCRIPTIONS.get(name, name.replace("_", " ").title() + " (extension tool).")
        # Classify: the few writeful extensions (action_confirm,
        # zabbix_raw_api_call, history_push). Reuse the same rule the
        # runtime uses (_WRITE_EXTENSION_TOOLS) by importing it here.
        try:
            from zabbix_mcp.server import _WRITE_EXTENSION_TOOLS
            is_write = name in _WRITE_EXTENSION_TOOLS
        except Exception:  # pragma: no cover - defensive
            is_write = name in {"action_confirm", "zabbix_raw_api_call", "history_push"}
        catalog.append({
            "name": name,
            "description": desc[:160],
            "is_write": is_write,
            "group": "extensions",
        })

    catalog.sort(key=lambda r: (r["group"], r["name"]))
    return catalog


def _consent_plugin_catalog(
    requested_scopes: list[str],
    role_cap: set[str],
) -> dict[str, Any]:
    """Build the per-plugin consent UI structure consumed by oauth_consent.html.

    Today only the bundled Zabbix module is registered with the host;
    when the loader release lands, this function iterates the installed
    plugin registry and returns one section per active plugin. The
    template is already plugin-agnostic - it renders the list it gets.
    """
    requested = list(requested_scopes or [])
    has_wildcard_request = (not requested) or ("*" in requested)
    can_grant_wildcard = "*" in role_cap

    tool_catalog = _build_tool_catalog()
    write_count = sum(1 for t in tool_catalog if t["is_write"])
    read_count = len(tool_catalog) - write_count

    # Default plugin-level choice: pick the LEAST privilege that still
    # satisfies the client's request. Wildcard request -> read-only by
    # default (operator must explicitly upgrade to write). Specific
    # write-heavy groups (users / administration) -> write. Anything else
    # -> read-only.
    default_choice = "read"
    if any(s in {"users", "administration"} for s in requested):
        default_choice = "write"
    elif any(s.startswith("plugin:") and (s.endswith(".write") or "." not in s[7:]) for s in requested):
        default_choice = "write"

    # Group sub-sections inside the per-tool list (for template grouping).
    by_group: dict[str, list[dict[str, Any]]] = {}
    for row in tool_catalog:
        by_group.setdefault(row["group"], []).append(row)
    grouped_tools = [
        {"group": g, "label": _TOOL_GROUP_LABELS.get(g, g.replace("_", " ").title()),
         "tools": tools}
        for g, tools in sorted(by_group.items())
    ]

    return {
        "wildcard_requested": has_wildcard_request,
        "can_grant_wildcard": can_grant_wildcard,
        "plugins": [
            {
                "id": "zabbix",
                "name": "Zabbix",
                "subtitle": "Bundled - default-installed",
                "logo_url": "/static/module-zabbix.svg",
                "tool_count": len(tool_catalog),
                "read_count": read_count,
                "write_count": write_count,
                "default_choice": default_choice,
                "grouped_tools": grouped_tools,
            }
        ],
    }


_TOOL_GROUP_LABELS: dict[str, str] = {
    "monitoring": "Monitoring",
    "data_collection": "Data collection / templates",
    "alerts": "Alerts & actions",
    "users": "Users, roles & access",
    "administration": "Administration",
    "extensions": "Extensions",
    "other": "Other",
}


# ---------------------------------------------------------------------------
# Legacy scope catalog (v1.30 group-based consent UI) - retained as a fallback
# in case _build_tool_catalog cannot be invoked (early boot, missing imports).
# ---------------------------------------------------------------------------


_SCOPE_LABELS: dict[str, tuple[str, str]] = {
    "*":              ("Full access (all tools)", "Lets the client invoke every tool on every server, including write operations like host_create / host_delete / action_prepare."),
    "monitoring":     ("Monitoring", "Read live state: hosts, host groups, items, triggers, problems, history, graphs, discovery rules."),
    "data_collection":("Data collection / templates", "Read templates, value maps, dashboards. Required for clients that explore configuration."),
    "alerts":         ("Alerts & actions", "Read action definitions, alert history, media types, scripts."),
    "users":          ("Users & roles", "Read or modify Zabbix user accounts, groups, roles, MFA. High-privilege - decline unless the client really needs it."),
    "administration": ("Administration", "Read or modify housekeeping, proxies, audit log, maintenance windows, server settings. High-privilege."),
    "extensions":     ("Extension tools", "Run server-side analytics: graph_render, anomaly_detect, capacity_forecast, problem_active_get, report_generate, health_check."),
}


def _scopes_for_consent_ui(requested: list[str]) -> list[dict[str, Any]]:
    """Translate the client's requested scope list into checkbox rows.

    Each row gets a human label, a description, and a tool-count badge
    so the operator can decide row-by-row what to grant.  Wildcard
    ``*`` is rendered with a warning frame to flag the unlimited scope.

    When the client asked for ``*`` (or supplied no scope at all), we
    render the full catalog (all six groups) under the wildcard row so
    the operator can untick ``*`` and pick narrower groups instead.
    Without that expansion the consent screen has only one checkbox
    and unticking it sends the operator to the empty-grant error.
    """
    from zabbix_mcp.config import TOOL_GROUPS, _expand_tool_groups
    try:
        from zabbix_mcp.api import ALL_METHODS
        all_methods = list(ALL_METHODS)
        all_method_count = len(all_methods)
    except Exception:
        all_methods = []
        all_method_count = 0

    def _count(sid: str) -> int:
        if sid == "*":
            return all_method_count + len(TOOL_GROUPS.get("extensions", []))
        try:
            expanded = set(_expand_tool_groups([sid]))
            n = sum(
                1 for m in all_methods
                if (m.tool_name.rsplit("_", 1)[0] if "_" in m.tool_name else m.tool_name) in expanded
            )
            n += sum(1 for t in TOOL_GROUPS.get("extensions", []) if t in expanded)
            return n
        except Exception:
            return 0

    requested = list(requested) or ["*"]
    has_wildcard = "*" in requested

    # When client asked for "*", offer the wildcard row checked + the
    # six concrete groups unchecked so the operator can downscope.
    # When client asked for specific groups, show only those and pre-tick
    # them (the operator can untick what they do not want to grant).
    rows: list[dict[str, Any]] = []
    if has_wildcard:
        ids = ["*"] + list(TOOL_GROUPS.keys())
    else:
        ids = list(dict.fromkeys(requested))  # preserve order, drop dupes

    for sid in ids:
        label, desc = _SCOPE_LABELS.get(
            sid, (sid, "Custom scope - covers a single tool prefix."),
        )
        rows.append({
            "id": sid,
            "label": label,
            "description": desc,
            "tool_count": _count(sid),
            # Wildcard pre-checked (matches the requested grant); the six
            # concrete groups start unchecked so unticking * exposes
            # them for explicit selection.
            "checked": (sid in requested),
        })
    return rows


# ---------------------------------------------------------------------------
# Login + consent endpoint
# ---------------------------------------------------------------------------


async def handle_oauth_login(
    request: Request,
    provider: Any,
    config: Any,
) -> Response:
    """Route handler for the two-step OAuth interactive flow.

    Step 1 (login):
        ``GET /oauth/login?request_id=...``  -> render the login form.
        ``POST /oauth/login`` (no ``step`` field) -> verify credentials,
        if OK render the consent screen; on failure re-render the
        login form with an error.

    Step 2 (consent):
        ``POST /oauth/login`` (``step=consent`` + ``action=allow|deny``
        + ``scope=...`` checkboxes) -> finalise the authorization with
        only the scopes the operator ticked, redirect the browser back
        to the client's redirect_uri carrying ``code`` and ``state``.
        On Deny, redirect with ``error=access_denied``.
    """
    if request.method == "GET":
        return _render_login_form(provider, request)

    form = await request.form()
    request_id = str(form.get("request_id", "") or "")
    step = str(form.get("step", "") or "")

    from zabbix_mcp.token_store import current_client_ip
    client_ip = current_client_ip.get() or (
        request.client.host if request.client else "unknown"
    )

    # Brute-force throttle covers the credential-verify step only.
    if not _oauth_login_limiter.check(client_ip):
        return _render_error_page(
            "Too many failed login attempts. Wait 5 minutes before trying again.",
            status_code=429,
        )

    import time as _time
    pending = provider._pending.get(request_id)
    if pending is None or pending.expires_at < _time.time():
        if pending is not None:
            provider._pending.pop(request_id, None)
        return _render_error_page(
            "This authorization request has expired. Reconnect from your "
            "MCP client to begin a new login.",
        )

    if step == "consent":
        return _handle_consent_step(provider, pending, request_id, form, client_ip)
    return _handle_login_step(
        provider, pending, request_id, form, client_ip, config,
    )


def _render_login_form(provider: Any, request: Request) -> Response:
    import time as _time
    request_id = request.query_params.get("request_id", "")
    pending = provider._pending.get(request_id)
    if pending is None or pending.expires_at < _time.time():
        # Pop any expired pending entry on the way out so brute-force
        # probes against stale request_ids do not pin them in memory.
        if pending is not None:
            provider._pending.pop(request_id, None)
        return _render_error_page(
            "This authorization request has expired or was never started. "
            "Reconnect from your MCP client to begin a new login.",
        )
    client_name = (pending.client.client_name or "").strip() or str(pending.client.client_id or "")
    return HTMLResponse(_render_template(
        "oauth_login.html",
        request_id=request_id,
        client_name=client_name,
        scopes=list(pending.params.scopes or []),
        error=None,
        username="",
    ))


def _handle_login_step(
    provider: Any,
    pending: Any,
    request_id: str,
    form: Any,
    client_ip: str,
    config: Any,
) -> Response:
    """Step 1: credential verification -> render consent screen on success."""
    from zabbix_mcp.admin.audit_writer import write_audit

    username = str(form.get("username", "") or "").strip()
    password = str(form.get("password", "") or "")

    authenticated, role = _verify_admin_user(config, username, password)
    if not authenticated:
        _oauth_login_limiter.record_attempt(client_ip)
        write_audit(
            action="oauth.login_failed",
            user=username or "(empty)",
            target_type="oauth_client",
            target_id=str(pending.client.client_id or ""),
            details={"client_name": pending.client.client_name or "", "reason": "invalid_credentials"},
            ip=client_ip or "",
        )
        client_name = (pending.client.client_name or "").strip() or str(pending.client.client_id or "")
        return HTMLResponse(_render_template(
            "oauth_login.html",
            request_id=request_id,
            client_name=client_name,
            scopes=list(pending.params.scopes or []),
            error="Invalid username or password.",
            username=username,
        ), status_code=401)

    _oauth_login_limiter.reset(client_ip)
    pending.authenticated_subject = username
    pending.authenticated_role = role
    write_audit(
        action="oauth.login_success",
        user=username,
        target_type="oauth_client",
        target_id=str(pending.client.client_id or ""),
        details={"client_name": pending.client.client_name or "", "role": role, "stage": "credentials_verified"},
        ip=client_ip or "",
    )

    requested_scopes = list(pending.params.scopes or [])
    cap = _scope_cap_for_role(role)
    catalog = _consent_plugin_catalog(requested_scopes, cap)
    return HTMLResponse(_render_template(
        "oauth_consent.html",
        request_id=request_id,
        client_name=(pending.client.client_name or "").strip() or str(pending.client.client_id or ""),
        subject=username,
        subject_role=role,
        catalog=catalog,
        wildcard_requested=catalog["wildcard_requested"],
        can_grant_wildcard=catalog["can_grant_wildcard"],
        plugins=catalog["plugins"],
    ))


def _handle_consent_step(
    provider: Any,
    pending: Any,
    request_id: str,
    form: Any,
    client_ip: str,
) -> Response:
    """Step 2: operator clicked Allow / Deny on the consent screen."""
    from zabbix_mcp.admin.audit_writer import write_audit

    if pending.authenticated_subject is None:
        # Cannot reach the consent screen without first authenticating.
        # If we got here without a subject something tampered with the
        # form - treat as a failed attempt.
        _oauth_login_limiter.record_attempt(client_ip)
        return _render_error_page(
            "Authentication required. Reconnect from your MCP client to "
            "begin a new login.",
        )

    action = str(form.get("action", "") or "").lower()
    subject = pending.authenticated_subject

    if action == "deny":
        write_audit(
            action="oauth.consent_denied",
            user=subject,
            target_type="oauth_client",
            target_id=str(pending.client.client_id or ""),
            details={"client_name": pending.client.client_name or ""},
            ip=client_ip or "",
        )
        # Drop the pending entry and redirect the browser back to the
        # client with the standard OAuth 2.1 access_denied error.
        provider._pending.pop(request_id, None)
        from urllib.parse import urlencode
        params = {"error": "access_denied", "error_description": "Operator declined the consent prompt"}
        if pending.params.state:
            params["state"] = pending.params.state
        sep = "&" if "?" in str(pending.params.redirect_uri) else "?"
        return RedirectResponse(
            f"{pending.params.redirect_uri}{sep}{urlencode(params)}",
            status_code=302,
        )

    if action != "allow":
        return _render_error_page("Unrecognised consent action.")

    raw_granted = [str(s) for s in form.getlist("scope")] if hasattr(form, "getlist") else []
    # Drop empty strings that disabled hidden inputs can post when the
    # browser ignores ``disabled`` (defensive belt-and-braces for
    # unusual UAs - the consent screen disables the radio-driven hidden
    # input when "None" is selected).
    granted = [s for s in (s.strip() for s in raw_granted) if s]
    # Wildcard subsumes everything else - if both posted, simplify so
    # the audit log shows the actual grant rather than a super-set.
    if "*" in granted:
        granted = ["*"]

    if not granted:
        return _render_error_page(
            "You did not grant any scope. Either pick at least one access "
            "level / tool or click Deny to cancel.",
            status_code=400,
        )

    # Reject any scope the client did not originally request, BUT the
    # v1.31 grammar allows the operator to substitute equivalent or
    # narrower forms - e.g. a client that asked for "monitoring" should
    # accept "plugin:zabbix.read" or a hand-picked "tool:host_get" list,
    # because those are subsets of what was requested. We only enforce
    # the rejection when the client locked down its request to a
    # specific group set AND the operator answered with something
    # *broader* (e.g. wildcard *).
    requested_scopes = set(pending.params.scopes or [])
    if "*" in requested_scopes or not requested_scopes:
        candidate_grant = list(granted)
    else:
        # Client asked for a specific set - filter out any wildcard
        # broadening the operator might have ticked. Per-plugin and
        # per-tool grants are accepted because they are subsets of any
        # group the client could have asked for.
        candidate_grant = [
            s for s in granted
            if s != "*" or "*" in requested_scopes
        ]
        if not candidate_grant:
            return _render_error_page(
                "Granted scopes do not match what the client requested.",
                status_code=400,
            )

    # Cap by operator role -- a viewer cannot grant administration /
    # users no matter what the form posted.  Server-side check; the
    # disabled UI controls are only a hint. v1.31 grammar additions
    # (``plugin:zabbix.write``, ``tool:host_create``, ...) are gated on
    # the WRITE side so a non-admin cannot grant a write scope (or the
    # wildcard) regardless of what the form posted.
    cap = _scope_cap_for_role(pending.authenticated_role or "viewer")
    can_grant_writes = "*" in cap or any(
        s in {"users", "administration"} for s in cap
    )
    allowed_grant: list[str] = []
    rejected: list[str] = []
    for s in candidate_grant:
        if s == "*":
            if "*" in cap:
                allowed_grant.append(s)
            else:
                rejected.append(s)
        elif s.startswith("plugin:") and (s.endswith(".write") or "." not in s.split(":", 1)[1]):
            # plugin:<id> or plugin:<id>.write -> implies write access
            if can_grant_writes:
                allowed_grant.append(s)
            else:
                rejected.append(s)
        elif s.startswith("plugin:") and s.endswith(".read"):
            # Read-only plugin grant - any role can grant.
            allowed_grant.append(s)
        elif s.startswith("tool:"):
            # Per-tool grant. Allow only if the tool is a read tool OR
            # the operator can grant writes.
            tool_name = s[len("tool:"):]
            try:
                from zabbix_mcp.server import _ensure_write_tools_set, _WRITE_TOOLS
                _ensure_write_tools_set()
                is_write = tool_name in _WRITE_TOOLS
            except Exception:
                is_write = False
            if is_write and not can_grant_writes:
                rejected.append(s)
            else:
                allowed_grant.append(s)
        else:
            # Legacy group / prefix scope - apply the v1.30 cap check.
            if "*" in cap or s in cap:
                allowed_grant.append(s)
            else:
                rejected.append(s)

    if not allowed_grant:
        return _render_error_page(
            "None of the scopes you ticked are within your role's grant "
            "capability. Ask an admin to log in instead, or pick narrower "
            "scopes the client can use.",
            status_code=403,
        )

    redirect_url = provider.complete_pending(
        request_id, allowed_grant, subject=subject,
    )
    if redirect_url is None:
        return _render_error_page(
            "This authorization request has expired between submission "
            "and completion. Reconnect from your MCP client to begin a "
            "new login.",
        )
    # Audit-log details: keep the per-tool list capped so a 200-tool
    # grant does not blow the audit row size. Summary form: the first 8
    # tool names + a count.
    tool_grants = [s for s in allowed_grant if s.startswith("tool:")]
    plugin_grants = [s for s in allowed_grant if s.startswith("plugin:")]
    summary = {
        "wildcard": "*" in allowed_grant,
        "plugins": plugin_grants,
        "tools_count": len(tool_grants),
        "tools_sample": tool_grants[:8],
        "legacy": [s for s in allowed_grant if not s.startswith(("plugin:", "tool:")) and s != "*"],
    }
    if rejected:
        summary["rejected_by_role"] = rejected
    write_audit(
        action="oauth.consent_granted",
        user=subject,
        target_type="oauth_client",
        target_id=str(pending.client.client_id or ""),
        details={
            "client_name": pending.client.client_name or "",
            "requested_scopes": list(pending.params.scopes or []),
            "granted_scopes_summary": summary,
        },
        ip=client_ip or "",
    )
    logger.info(
        "OAuth consent granted: user=%s client=%s requested=%s "
        "granted=%d scopes (wildcard=%s, plugins=%s, tools=%d, legacy=%s)",
        subject, pending.client.client_id,
        list(pending.params.scopes or []),
        len(allowed_grant), summary["wildcard"], summary["plugins"],
        summary["tools_count"], summary["legacy"],
    )
    return RedirectResponse(redirect_url, status_code=302)
