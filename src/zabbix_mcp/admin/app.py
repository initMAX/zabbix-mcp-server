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

from zabbix_mcp.admin.audit_writer import write_audit
from zabbix_mcp.admin.auth import SessionManager, LoginRateLimiter

if TYPE_CHECKING:
    from zabbix_mcp.config import AppConfig
    from zabbix_mcp.client import ClientManager
    from zabbix_mcp.token_store import TokenStore

logger = logging.getLogger("zabbix_mcp.admin")

TEMPLATE_DIR = Path(__file__).parent / "templates"
STATIC_DIR = Path(__file__).parent / "static"


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
        from zabbix_mcp.admin.views.servers import servers_view, server_create, server_edit, server_delete, server_test, server_restart
        from zabbix_mcp.admin.views.templates import template_list, template_create, template_edit, template_preview, template_delete
        from zabbix_mcp.admin.views.settings import settings_view, settings_update
        from zabbix_mcp.admin.views.audit import audit_view, audit_export

        routes = [
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
            Route("/servers/{server_name}/test", server_test, methods=["POST"]),
            Route("/templates", template_list),
            Route("/templates/create", template_create, methods=["GET", "POST"]),
            Route("/templates/preview", template_preview, methods=["POST"]),
            Route("/templates/{template_id}", template_edit, methods=["GET", "POST"]),
            Route("/templates/{template_id}/preview", template_preview, methods=["GET", "POST"]),
            Route("/templates/{template_id}/delete", template_delete, methods=["POST"]),
            Route("/settings", settings_view, methods=["GET"]),
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
        return app

    def render(self, template_name: str, request: Request, context: dict | None = None, status_code: int = 200) -> HTMLResponse:
        """Render a Jinja2 template with common context."""
        ctx: dict[str, Any] = {
            "version": "1.16",
            "server_name": f"MCP: {self.config.server.host}:{self.config.server.port}/mcp",
            "current_user": "",
            "active": "",
            "flash_message": None,
            "flash_type": "info",
            "year": datetime.now().year,
        }

        # Session user
        session = self._get_session(request)
        if session:
            ctx["current_user"] = session.user
            ctx["current_user_role"] = session.role

        if context:
            ctx.update(context)

        template = self.jinja.get_template(template_name)
        html = template.render(**ctx)
        return HTMLResponse(html, status_code=status_code)

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
