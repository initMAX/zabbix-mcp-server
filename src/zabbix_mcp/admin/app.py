#
# Zabbix MCP Server
# Copyright (C) 2026 initMAX s.r.o.
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License as published by the Free
# Software Foundation, version 3.
#

"""Admin portal Starlette application — route registration and middleware."""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

import jinja2

from zabbix_mcp import __version__
from zabbix_mcp.admin.audit_writer import write_audit
from zabbix_mcp.admin.auth import SessionManager, LoginRateLimiter

if TYPE_CHECKING:
    from zabbix_mcp.config import AppConfig
    from zabbix_mcp.client import ClientManager
    from zabbix_mcp.token_store import TokenStore

logger = logging.getLogger("zabbix_mcp.admin")

TEMPLATE_DIR = Path(__file__).parent / "templates"
STATIC_DIR = Path(__file__).parent / "static"


class _PostRateLimitMiddleware:
    """ASGI middleware: rate-limit POST requests to 30/min per session."""

    def __init__(self, app: Starlette, max_requests: int = 30, window: int = 60) -> None:
        self.app = app
        self.state = app.state  # Forward state access for Starlette compatibility
        self.max_requests = max_requests
        self.window = window
        self._requests: dict[str, list[float]] = {}

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            method = scope.get("method", "GET")
            if method == "POST":
                import time
                headers = dict(scope.get("headers", []))
                cookie = headers.get(b"cookie", b"").decode()
                key = "anon"
                if "admin_session=" in cookie:
                    key = cookie.split("admin_session=")[1].split(";")[0][:20]
                now = time.time()
                if key not in self._requests:
                    self._requests[key] = []
                self._requests[key] = [t for t in self._requests[key] if now - t < self.window]
                if len(self._requests[key]) >= self.max_requests:
                    resp = Response("Rate limit exceeded. Max 30 POST requests per minute.", status_code=429)
                    await resp(scope, receive, send)
                    return
                self._requests[key].append(now)
        await self.app(scope, receive, send)


class AdminApp:
    """Admin portal application.

    Wraps a Starlette app with session auth and Jinja2 template rendering.
    CSRF protection via SameSite=Strict session cookies.
    """

    def __init__(
        self,
        config: AppConfig,
        config_path: str,
        client_manager: ClientManager,
        token_store: TokenStore,
    ) -> None:
        self.config = config
        self.config_path = config_path
        self.client_manager = client_manager
        self.token_store = token_store

        # Session management
        import secrets
        signing_key = secrets.token_hex(32)
        self.sessions = SessionManager(signing_key)
        self.rate_limiter = LoginRateLimiter()

        # Track whether config changed and restart is needed
        self.restart_needed = False
        self.start_time = datetime.now()

        # Jinja2 environment
        self.jinja = jinja2.Environment(
            loader=jinja2.FileSystemLoader(str(TEMPLATE_DIR)),
            autoescape=True,
        )

        # Build Starlette app
        self.app = self._build_app()

    def _build_app(self) -> Starlette:
        from zabbix_mcp.admin.views.dashboard import dashboard
        from zabbix_mcp.admin.views.tokens import token_list, token_create, token_detail, token_revoke, token_delete
        from zabbix_mcp.admin.views.users import user_list, user_create, user_detail, user_delete
        from zabbix_mcp.admin.views.servers import servers_view, server_create, server_edit, server_delete, server_test, server_restart, server_test_new
        from zabbix_mcp.admin.views.templates import template_list, template_create, template_edit, template_preview, template_delete
        from zabbix_mcp.admin.views.settings import settings_view, settings_update
        from zabbix_mcp.admin.views.uploads import upload_logo, upload_tls_cert, upload_tls_key
        from zabbix_mcp.admin.views.audit import audit_view, audit_export

        routes = [
            Route("/health", self._admin_health, methods=["GET"]),
            Route("/api/mcp-status", self._mcp_status, methods=["GET"]),
            Route("/api/server-status", self._server_status, methods=["GET"]),
            Route("/login", self._login, methods=["GET", "POST"]),
            Route("/logout", self._logout, methods=["POST"]),
            Route("/", dashboard),
            Route("/tokens", token_list),
            Route("/tokens/create", token_create, methods=["GET", "POST"]),
            Route("/tokens/{token_id}", token_detail, methods=["GET", "POST"]),
            Route("/tokens/{token_id}/revoke", token_revoke, methods=["POST"]),
            Route("/tokens/{token_id}/delete", token_delete, methods=["POST"]),
            Route("/users", user_list),
            Route("/users/create", user_create, methods=["GET", "POST"]),
            Route("/users/{username}", user_detail, methods=["GET", "POST"]),
            Route("/users/{username}/delete", user_delete, methods=["POST"]),
            Route("/servers", servers_view),
            Route("/servers/create", server_create, methods=["POST"]),
            Route("/servers/{server_name}/edit", server_edit, methods=["GET", "POST"]),
            Route("/servers/{server_name}/delete", server_delete, methods=["POST"]),
            Route("/servers/restart", server_restart, methods=["POST"]),
            Route("/servers/test-new", server_test_new, methods=["POST"]),
            Route("/servers/{server_name}/test", server_test, methods=["POST"]),
            Route("/templates", template_list),
            Route("/templates/create", template_create, methods=["GET", "POST"]),
            Route("/templates/preview", template_preview, methods=["POST"]),
            Route("/templates/{template_id}", template_edit, methods=["GET", "POST"]),
            Route("/templates/{template_id}/preview", template_preview, methods=["GET", "POST"]),
            Route("/templates/{template_id}/delete", template_delete, methods=["POST"]),
            Route("/settings", settings_view, methods=["GET"]),
            Route("/settings/upload/logo", upload_logo, methods=["POST"]),
            Route("/settings/upload/tls_cert", upload_tls_cert, methods=["POST"]),
            Route("/settings/upload/tls_key", upload_tls_key, methods=["POST"]),
            Route("/settings/{section}", settings_update, methods=["POST"]),
            Route("/audit", audit_view),
            Route("/audit/export", audit_export),
            Mount("/static", app=StaticFiles(directory=str(STATIC_DIR)), name="static"),
        ]

        async def not_found(request: Request, exc: Exception) -> Response:
            """Redirect 404s to dashboard (if logged in) or login."""
            if request.method == "GET":
                session = self._get_session(request)
                if session:
                    return RedirectResponse("/", status_code=303)
                return RedirectResponse("/login", status_code=303)
            return HTMLResponse("Not Found", status_code=404)

        app = Starlette(routes=routes, exception_handlers={404: not_found})
        app.state.admin_app = self

        # Wrap with POST rate limiting (30 req/min per session)
        return _PostRateLimitMiddleware(app)

    def render(self, template_name: str, request: Request, context: dict | None = None, status_code: int = 200) -> HTMLResponse:
        """Render a Jinja2 template with common context."""
        ctx: dict[str, Any] = {
            "version": __version__,
            "server_name": f"MCP: {self.config.server.host}:{self.config.server.port}/mcp",
            "current_user": "",
            "active": "",
            "flash_message": None,
            "flash_type": "info",
            "year": datetime.now().year,
            "restart_needed": self.restart_needed,
        }

        # Session user
        session = self._get_session(request)
        if session:
            ctx["current_user"] = session.user
            ctx["current_user_role"] = session.role

        # Consume flash message from cookie (set by redirects)
        flash_cookie = request.cookies.get("_flash")
        flash_type_cookie = request.cookies.get("_flash_type")
        if flash_cookie and not ctx.get("flash_message"):
            # Validate: only accept reasonable flash messages (prevents cookie injection XSS)
            if len(flash_cookie) <= 500 and flash_type_cookie in (None, "info", "success", "warning", "danger"):
                ctx["flash_message"] = flash_cookie
                ctx["flash_type"] = flash_type_cookie or "info"

        if context:
            ctx.update(context)

        template = self.jinja.get_template(template_name)
        html = template.render(**ctx)
        response = HTMLResponse(html, status_code=status_code)
        # Clear flash cookies after consuming
        if flash_cookie:
            response.delete_cookie("_flash")
            response.delete_cookie("_flash_type")
        return response

    @staticmethod
    def flash_redirect(url: str, message: str, flash_type: str = "success", status_code: int = 303) -> RedirectResponse:
        """Redirect with a flash message stored in a cookie."""
        response = RedirectResponse(url, status_code=status_code)
        response.set_cookie("_flash", message, max_age=10, httponly=True, samesite="strict")
        response.set_cookie("_flash_type", flash_type, max_age=10, httponly=True, samesite="strict")
        return response

    def _get_session(self, request: Request):
        """Extract and validate session from cookie."""
        token = request.cookies.get("admin_session")
        if not token:
            return None
        return self.sessions.validate_session(token)

    def require_auth(self, request: Request):
        """Check auth, return session or raise redirect."""
        session = self._get_session(request)
        if not session:
            return None
        return session

    async def _admin_health(self, request: Request) -> Response:
        """Health check endpoint — no auth required."""
        return JSONResponse({"status": "ok", "portal": "admin", "version": __version__})

    async def _mcp_status(self, request: Request) -> Response:
        """Proxy health check to MCP server — returns status for header indicator."""
        session = self._get_session(request)
        if not session:
            return JSONResponse({"error": "Unauthorized"}, status_code=401)
        import urllib.request
        mcp_port = getattr(self.config, '_runtime_port', None) or self.config.server.port or 8080
        url = f"http://127.0.0.1:{mcp_port}/health"
        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=3) as resp:
                import json
                data = json.loads(resp.read())
                # Calculate uptime
                uptime_delta = datetime.now() - self.start_time
                total_secs = int(uptime_delta.total_seconds())
                days, remainder = divmod(total_secs, 86400)
                hours, remainder = divmod(remainder, 3600)
                minutes, _ = divmod(remainder, 60)
                if days > 0:
                    uptime_str = f"{days}d {hours}h {minutes}m"
                elif hours > 0:
                    uptime_str = f"{hours}h {minutes}m"
                else:
                    uptime_str = f"{minutes}m"
                return JSONResponse({"status": "ok", "mcp": data, "uptime": uptime_str})
        except Exception as e:
            return JSONResponse({"status": "error", "error": str(e)}, status_code=503)

    async def _server_status(self, request: Request) -> Response:
        """Check all Zabbix servers in background — returns JSON for dashboard dots."""
        session = self._get_session(request)
        if not session:
            return JSONResponse({"error": "Unauthorized"}, status_code=401)

        import asyncio
        results = {}
        for name in self.client_manager.server_names:
            try:
                result = await asyncio.to_thread(self.client_manager.check_connection, name)
                version = self.client_manager.get_version(name)
                if result.get("token_ok"):
                    results[name] = {"status": "online", "version": version}
                else:
                    results[name] = {"status": "token_error", "version": version, "error": "API online but token invalid or expired"}
            except Exception as e:
                results[name] = {"status": "error", "error": str(e)[:100]}
        return JSONResponse(results)

    async def _login(self, request: Request) -> Response:
        """Handle login GET (form) and POST (submit)."""
        if request.method == "GET":
            # Already logged in?
            if self._get_session(request):
                return RedirectResponse("/", status_code=303)
            return self.render("login.html", request)

        # POST — process login
        form = await request.form()
        username = str(form.get("username", ""))
        password = str(form.get("password", ""))
        client_ip = request.client.host if request.client else "unknown"

        # Rate limit check
        if not self.rate_limiter.check(client_ip):
            return self.render("login.html", request, {
                "error": "Too many login attempts. Please wait 30 seconds.",
            }, status_code=429)

        # Validate credentials against config
        from zabbix_mcp.admin.auth import verify_password
        admin_users = getattr(self.config, "_admin_users", {})

        # Also check raw config for [admin.users.*]
        if not admin_users:
            from zabbix_mcp.admin.config_writer import load_config_document, TOMLKIT_AVAILABLE
            if TOMLKIT_AVAILABLE:
                try:
                    doc = load_config_document(self.config_path)
                    admin_section = doc.get("admin", {})
                    users_section = admin_section.get("users", {})
                    admin_users = {k: dict(v) for k, v in users_section.items()}
                except Exception:
                    pass

        user_data = admin_users.get(username)
        if not user_data or not verify_password(password, user_data.get("password_hash", "")):
            self.rate_limiter.record_attempt(client_ip)
            logger.warning("Failed login attempt for user '%s' from %s", username, client_ip)
            write_audit("login_failure", user=username, ip=client_ip)
            return self.render("login.html", request, {
                "error": "Invalid username or password.",
            }, status_code=401)

        # Success
        self.rate_limiter.reset(client_ip)
        role = user_data.get("role", "viewer")
        session_token = self.sessions.create_session(username, role, client_ip)
        logger.info("Admin login: user '%s' from %s (role: %s)", username, client_ip, role)
        write_audit("login_success", user=username, details={"role": role}, ip=client_ip)

        response = RedirectResponse("/", status_code=303)
        # CSRF protection: SameSite=Strict prevents cross-origin form submissions.
        # Combined with httponly=True, this provides robust CSRF defense.
        response.set_cookie(
            "admin_session",
            session_token,
            httponly=True,
            samesite="strict",
            secure=request.url.scheme == "https",
            max_age=self.sessions.SESSION_DURATION,
        )
        return response

    async def _logout(self, request: Request) -> Response:
        """Handle logout."""
        token = request.cookies.get("admin_session")
        if token:
            session = self.sessions.validate_session(token)
            if session:
                write_audit("logout", user=session.user, ip=request.client.host if request.client else "")
            self.sessions.destroy_session(token)
        response = RedirectResponse("/login", status_code=303)
        response.delete_cookie("admin_session")
        return response
