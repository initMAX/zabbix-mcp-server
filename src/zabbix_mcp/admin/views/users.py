#
# Zabbix MCP Server
# Copyright (C) 2026 initMAX s.r.o.
#

"""Admin user CRUD views."""

from __future__ import annotations

import logging

from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

from zabbix_mcp.admin.audit_writer import write_audit
from zabbix_mcp.admin.auth import hash_password
from zabbix_mcp.admin.config_writer import (
    add_config_table,
    load_config_document,
    remove_config_table,
    save_config_document,
    TOMLKIT_AVAILABLE,
)

logger = logging.getLogger("zabbix_mcp.admin")


def _get_admin_users(config_path: str) -> dict:
    """Read [admin.users.*] from config."""
    if not TOMLKIT_AVAILABLE:
        return {}
    try:
        doc = load_config_document(config_path)
        admin = doc.get("admin", {})
        users = admin.get("users", {})
        return {k: dict(v) for k, v in users.items()}
    except Exception:
        return {}


async def user_list(request: Request) -> Response:
    admin_app = request.app.state.admin_app
    session = admin_app.require_auth(request)
    if not session:
        return RedirectResponse("/login", status_code=303)

    users = _get_admin_users(admin_app.config_path)
    return admin_app.render("users/list.html", request, {
        "active": "users",
        "users": users,
    })


async def user_create(request: Request) -> Response:
    admin_app = request.app.state.admin_app
    session = admin_app.require_auth(request)
    if not session or session.role != "admin":
        return RedirectResponse("/users", status_code=303)

    if request.method == "GET":
        return admin_app.render("users/create.html", request, {
            "active": "users",
        })

    form = await request.form()
    username = str(form.get("username", "")).strip().lower()
    password = str(form.get("password", ""))
    role = str(form.get("role", "viewer"))

    if not username or len(username) < 2:
        return admin_app.render("users/create.html", request, {
            "active": "users",
            "error": "Username must be at least 2 characters.",
        })

    if len(password) < 8:
        return admin_app.render("users/create.html", request, {
            "active": "users",
            "error": "Password must be at least 8 characters.",
        })

    if role not in ("admin", "operator", "viewer"):
        role = "viewer"

    # Check if user exists
    existing = _get_admin_users(admin_app.config_path)
    if username in existing:
        return admin_app.render("users/create.html", request, {
            "active": "users",
            "error": f"User '{username}' already exists.",
        })

    try:
        import tomlkit
        password_hash = hash_password(password)
        # Write to [admin.users.<username>]
        doc = load_config_document(admin_app.config_path)
        admin = doc.get("admin", {})
        if "users" not in admin:
            admin["users"] = tomlkit.table(is_super_table=True)
        user_table = tomlkit.table()
        user_table["password_hash"] = password_hash
        user_table["role"] = role
        admin["users"][username] = user_table
        save_config_document(admin_app.config_path, doc)
        logger.info("User '%s' created (role: %s) by %s", username, role, session.user)
        client_ip = request.client.host if request.client else ""
        write_audit("user_create", user=session.user, target_type="user", target_id=username, details={"role": role}, ip=client_ip)
    except Exception as e:
        logger.exception("Failed to create user: %s", e)
        return admin_app.render("users/create.html", request, {
            "active": "users",
            "error": f"Failed to save: {e}",
        })

    return RedirectResponse("/users", status_code=303)


async def user_detail(request: Request) -> Response:
    admin_app = request.app.state.admin_app
    session = admin_app.require_auth(request)
    if not session or session.role != "admin":
        return RedirectResponse("/users", status_code=303)

    username = request.path_params["username"]
    users = _get_admin_users(admin_app.config_path)
    user = users.get(username)
    if not user:
        return RedirectResponse("/users", status_code=303)

    if request.method == "POST":
        form = await request.form()
        new_password = str(form.get("password", "")).strip()
        new_role = str(form.get("role", "")).strip()

        try:
            doc = load_config_document(admin_app.config_path)
            user_section = doc["admin"]["users"][username]

            if new_password and len(new_password) >= 8:
                user_section["password_hash"] = hash_password(new_password)

            if new_role in ("admin", "operator", "viewer"):
                user_section["role"] = new_role

            save_config_document(admin_app.config_path, doc)
            logger.info("User '%s' updated by %s", username, session.user)
            client_ip = request.client.host if request.client else ""
            write_audit("user_edit", user=session.user, target_type="user", target_id=username, ip=client_ip)
        except Exception as e:
            logger.error("Failed to update user: %s", e)

        return RedirectResponse(f"/users/{username}", status_code=303)

    return admin_app.render("users/create.html", request, {
        "active": "users",
        "edit_mode": True,
        "edit_username": username,
        "edit_role": user.get("role", "viewer"),
    })


async def user_delete(request: Request) -> Response:
    admin_app = request.app.state.admin_app
    session = admin_app.require_auth(request)
    if not session or session.role != "admin":
        return RedirectResponse("/users", status_code=303)

    username = request.path_params["username"]

    # Prevent deleting yourself
    if username == session.user:
        return RedirectResponse("/users", status_code=303)

    try:
        doc = load_config_document(admin_app.config_path)
        admin = doc.get("admin", {})
        users = admin.get("users", {})
        if username in users:
            del users[username]
            save_config_document(admin_app.config_path, doc)
            logger.info("User '%s' deleted by %s", username, session.user)
            client_ip = request.client.host if request.client else ""
            write_audit("user_delete", user=session.user, target_type="user", target_id=username, ip=client_ip)
    except Exception as e:
        logger.error("Failed to delete user: %s", e)

    return RedirectResponse("/users", status_code=303)
