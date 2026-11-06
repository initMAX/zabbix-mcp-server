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
   MCPServer redirects the user-agent there.
2. GET renders a login form + a consent block listing the scopes the
   client asked for plus the scopes the server is willing to grant.
3. POST verifies username + password against ``[admin.users.*]``,
   calls ``provider.complete_pending(request_id, granted_scopes,
   subject)`` to mint the authorization code, then 302's to the
   client's redirect_uri (carrying ``code`` and ``state``).
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
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
# ``src/zabbix_mcp/admin/templates/``.
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


def _verify_admin_user(config: Any, username: str, password: str) -> tuple[bool, str, str | None]:
    """Validate (username, password) against [admin.users.*] in config.

    Returns ``(authenticated, role, timezone)``.  ``role`` is the empty
    string and ``timezone`` is None when authentication failed.  Wrong
    username and wrong password both return False with the same code
    path so the response time does not leak which side mismatched.

    ``timezone`` is the user's optional ``[admin.users.X].timezone``
    (issue #75), validated here so a hand-edited unknown zone is
    dropped (logged) instead of failing the login.
    """
    if not username or not password:
        return False, "", None
    cfg_path = getattr(config, "_config_path", None)
    if not cfg_path:
        return False, "", None
    try:
        from zabbix_mcp.admin.config_writer import load_config_document
        from zabbix_mcp.admin.auth import verify_password_timed
        doc = load_config_document(cfg_path)
        users = (doc.get("admin", {}) or {}).get("users", {}) or {}
        user = users.get(username)
        # the same work whether the user exists or not (no timing tells the names)
        if not verify_password_timed(password, str((user or {}).get("password_hash", "")) or None):
            return False, "", None
        if user is None or user.get("disabled"):
            return False, "", None
        timezone = _valid_timezone_or_none(user.get("timezone"))
        if user.get("timezone") and timezone is None:
            logger.warning(
                "Admin user '%s' has an unknown timezone %r in config.toml; ignoring it",
                username, user.get("timezone"),
            )
        return True, str(user.get("role", "viewer") or "viewer"), timezone
    except Exception as exc:  # pragma: no cover
        logger.warning("Admin user verification failed for %s: %s", username, exc)
        return False, "", None


def _valid_timezone_or_none(raw: Any) -> str | None:
    """Normalised IANA zone name, or None when empty or unknown."""
    text = str(raw or "").strip()
    if not text:
        return None
    from zabbix_mcp.timezones import validate_timezone
    try:
        return validate_timezone(text)
    except ValueError:
        return None


def _browser_timezone(form: Any) -> str | None:
    """The zone the browser reported in the hidden ``browser_timezone``
    input (``Intl.DateTimeFormat().resolvedOptions().timeZone``), or
    None when JS was off or the value is not a zone we know. Never an
    error: the field is a hint, not something the operator typed.
    """
    return _valid_timezone_or_none(form.get("browser_timezone", ""))


def _resolve_consent_timezone(pending: Any, form: Any) -> str | None:
    """Zone the tokens of this consent will carry (issue #75).

    The portal user's explicit zone wins; else the zone the browser
    posted with the consent form (or, failing that, with the login
    form); else None = inherit from the Zabbix entry / ``[server]``.
    """
    explicit = getattr(pending, "authenticated_timezone", None)
    if explicit:
        return explicit
    return _browser_timezone(form) or getattr(pending, "browser_timezone", None) or None


def _scope_cap_for_role(role: str) -> set[str]:
    """Return the set of OAuth scope IDs an operator with ``role`` may grant."""
    return _ROLE_SCOPE_CAP.get(role, _ROLE_SCOPE_CAP["viewer"])


# ---------------------------------------------------------------------------
# Scope catalog for the consent screen
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
        return _handle_consent_step(provider, pending, request_id, form, client_ip,
                                    request.cookies.get(consent_cookie_name(request_id), ""))
    return _handle_login_step(
        provider, pending, request_id, form, client_ip, config,
        secure=request.url.scheme == "https",
    )


# The consent step belongs to the browser that logged in. A request_id alone is not
# enough: it travels in the login link, and whoever holds the link could otherwise
# submit "Allow" for a user who logged in through it and receive the code at a
# redirect URI of their own (a client registers itself without authentication).
CONSENT_COOKIE = "zmcp_oauth_consent"


def consent_cookie_name(request_id: str) -> str:
    """One cookie per login: two MCP clients connecting at once, in two tabs of one
    browser, do not overwrite each other's."""
    return f"{CONSENT_COOKIE}_{hashlib.sha256(request_id.encode('utf-8')).hexdigest()[:16]}"


def _nonce_hash(nonce: str) -> str:
    return hashlib.sha256(nonce.encode("utf-8")).hexdigest()


def _redirect_host(pending: Any) -> str:
    from urllib.parse import urlsplit
    parts = urlsplit(str(pending.params.redirect_uri or ""))
    return parts.netloc or str(pending.params.redirect_uri or "")


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
    *,
    secure: bool = False,
) -> Response:
    """Step 1: credential verification -> render consent screen on success."""
    from zabbix_mcp.admin.audit_writer import write_audit

    username = str(form.get("username", "") or "").strip()
    password = str(form.get("password", "") or "")

    authenticated, role, user_timezone = _verify_admin_user(config, username, password)
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
    # Zone hints for the consent step (issue #75): the user's own
    # portal zone and what their browser said on the login form.
    pending.authenticated_timezone = user_timezone
    pending.browser_timezone = _browser_timezone(form)
    write_audit(
        action="oauth.login_success",
        user=username,
        target_type="oauth_client",
        target_id=str(pending.client.client_id or ""),
        details={"client_name": pending.client.client_name or "", "role": role, "stage": "credentials_verified"},
        ip=client_ip or "",
    )

    requested_scopes = list(pending.params.scopes or [])
    has_wildcard = (not requested_scopes) or ("*" in requested_scopes)
    cap = _scope_cap_for_role(role)
    rows = _scopes_for_consent_ui(requested_scopes)
    # Apply role cap: scopes outside the operator's cap render disabled
    # with a "needs admin role" hint, so a viewer cannot accidentally
    # grant administration / users to a third-party client.
    can_grant_wildcard = "*" in cap
    for row in rows:
        if can_grant_wildcard:
            row["disabled"] = False
        else:
            allowed_for_this_role = row["id"] in cap
            row["disabled"] = not allowed_for_this_role
            if row["disabled"]:
                row["checked"] = False
                row["description"] = (
                    row["description"]
                    + f"  -- not available to your role ({role}); ask an admin."
                )
    nonce = secrets.token_urlsafe(32)
    pending.consent_nonce_hash = _nonce_hash(nonce)
    response = HTMLResponse(_render_template(
        "oauth_consent.html",
        request_id=request_id,
        client_name=(pending.client.client_name or "").strip() or str(pending.client.client_id or ""),
        redirect_host=_redirect_host(pending),
        subject=username,
        subject_role=role,
        scopes=rows,
        has_wildcard_request=has_wildcard,
    ))
    import time as _time
    # as long as the request it belongs to (the pending entry's lifetime, [oauth] setting);
    # path "/" so that it does not depend on where the login is served
    lifetime = max(60, int(getattr(pending, "expires_at", _time.time() + 600) - _time.time()))
    response.set_cookie(consent_cookie_name(request_id), nonce, max_age=lifetime, path="/",
                        httponly=True, samesite="strict", secure=secure)
    return response


def _handle_consent_step(
    provider: Any,
    pending: Any,
    request_id: str,
    form: Any,
    client_ip: str,
    nonce: str = "",
) -> Response:
    """Step 2: operator clicked Allow / Deny on the consent screen."""
    from zabbix_mcp.admin.audit_writer import write_audit

    expected = getattr(pending, "consent_nonce_hash", None)
    if pending.authenticated_subject is not None and (
            not expected or not nonce or not hmac.compare_digest(expected, _nonce_hash(nonce))):
        # not the browser that logged in
        _oauth_login_limiter.record_attempt(client_ip)
        write_audit(
            action="oauth.consent_rejected",
            user=pending.authenticated_subject,
            target_type="oauth_client",
            target_id=str(pending.client.client_id or ""),
            details={"client_name": pending.client.client_name or "", "reason": "not_the_browser_that_logged_in"},
            ip=client_ip or "",
        )
        return _render_error_page(
            "This consent was not sent from the browser that signed in. "
            "Reconnect from your MCP client to begin a new login.",
            status_code=403,
        )

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

    granted = [str(s) for s in form.getlist("scope")] if hasattr(form, "getlist") else []
    # Wildcard subsumes the concrete groups - if both are posted, drop
    # the redundant rows so the audit log shows the actual grant
    # ("scopes=['*']") instead of a confusing super-set.
    if "*" in granted:
        granted = ["*"]
    if not granted:
        # The operator unticked everything -- treat as a deny since an
        # empty grant is functionally useless and likely an accident.
        return _render_error_page(
            "You did not grant any scope. Either pick at least one scope "
            "or click Deny to cancel.",
            status_code=400,
        )

    requested_scopes = set(pending.params.scopes or [])
    if "*" in requested_scopes or not requested_scopes:
        requested_scopes |= {"*"}
        # When client requested wildcard, any scope set is allowed
        candidate_grant = list(granted)
    else:
        # Reject any scope the client did not originally request
        candidate_grant = [s for s in granted if s in requested_scopes]
        if not candidate_grant:
            return _render_error_page(
                "Granted scopes do not match what the client requested.",
                status_code=400,
            )

    # Cap by operator role -- a viewer cannot grant administration /
    # users no matter what the form posted.  Server-side check; the
    # disabled checkboxes in the consent UI are only a hint.
    cap = _scope_cap_for_role(pending.authenticated_role or "viewer")
    if "*" in cap:
        allowed_grant = candidate_grant
    else:
        allowed_grant = [s for s in candidate_grant if s in cap]
        # Reject the wildcard request from a non-admin operator entirely.
        if "*" in candidate_grant and "*" not in cap:
            allowed_grant = [s for s in allowed_grant if s != "*"]
    if not allowed_grant:
        return _render_error_page(
            "None of the scopes you ticked are within your role's grant "
            "capability. Ask an admin to log in instead, or pick narrower "
            "scopes the client can use.",
            status_code=403,
        )

    timezone = _resolve_consent_timezone(pending, form)
    # A zone the portal user set is the operator's word; one the browser
    # reported is only a hint and ranks below the server's own pins.
    timezone_implicit = bool(timezone) and not bool(getattr(pending, "authenticated_timezone", None))
    redirect_url = provider.complete_pending(
        request_id, allowed_grant, subject=subject,
        role=pending.authenticated_role or "viewer",
        timezone=timezone,
        timezone_implicit=timezone_implicit,
    )
    if redirect_url is None:
        return _render_error_page(
            "This authorization request has expired between submission "
            "and completion. Reconnect from your MCP client to begin a "
            "new login.",
        )
    write_audit(
        action="oauth.consent_granted",
        user=subject,
        target_type="oauth_client",
        target_id=str(pending.client.client_id or ""),
        details={
            "client_name": pending.client.client_name or "",
            "requested_scopes": list(pending.params.scopes or []),
            "granted_scopes": allowed_grant,
            "timezone": timezone,
        },
        ip=client_ip or "",
    )
    logger.info(
        "OAuth consent granted: user=%s client=%s requested=%s granted=%s timezone=%s",
        subject, pending.client.client_id,
        list(pending.params.scopes or []), allowed_grant, timezone,
    )
    done = RedirectResponse(redirect_url, status_code=302)
    done.delete_cookie(consent_cookie_name(request_id), path="/")
    return done
