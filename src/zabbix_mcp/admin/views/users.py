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
from zabbix_mcp.admin.auth import hash_password, verify_password
from zabbix_mcp.admin.config_writer import (
    add_config_table,
    load_config_document,
    remove_config_table,
    save_config_document,
    TOMLKIT_AVAILABLE,
)

logger = logging.getLogger("zabbix_mcp.admin")

# Cap on a single bulk-delete batch. See views.tokens for rationale.
BULK_DELETE_MAX = 500


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

    # Existing usernames for the on-blur duplicate-check on the
    # Username input (base.html _zmcpDupCheck). Reused across every
    # render path on this handler.
    existing_usernames = list(_get_admin_users(admin_app.config_path).keys())

    if request.method == "GET":
        return admin_app.render("users/create.html", request, {
            "active": "users",
            "existing_usernames": existing_usernames,
        })

    form = await request.form()
    username = str(form.get("username", "")).strip().lower()
    password = str(form.get("password", ""))
    role = str(form.get("role", "viewer"))

    form_ctx = {
        "active": "users",
        "form_username": username,
        "form_role": role,
        "existing_usernames": existing_usernames,
    }

    # Validation: ASCII-only, length 2-50, [a-z0-9_-]+. Without this, a
    # Unicode username like "šáš" passes through to tomlkit and breaks
    # config.toml writing with a 500 (reported 2026-04-17). Also caps
    # length so a 200-character username does not blow up table layouts.
    import re as _re
    if not username or len(username) < 2:
        return admin_app.render("users/create.html", request, {
            **form_ctx,
            "error": "Username must be at least 2 characters.",
        })
    if len(username) > 50:
        return admin_app.render("users/create.html", request, {
            **form_ctx,
            "error": "Username must be 50 characters or fewer.",
        })
    if not _re.match(r"^[a-z0-9_-]+$", username):
        return admin_app.render("users/create.html", request, {
            **form_ctx,
            "error": "Username can only contain lowercase letters, digits, dashes, and underscores (no spaces, accents, or other special characters).",
        })

    if len(password) < 10:
        return admin_app.render("users/create.html", request, {
            **form_ctx,
            "error": "Password must be at least 10 characters.",
        })

    if not any(c.isupper() for c in password):
        return admin_app.render("users/create.html", request, {
            **form_ctx,
            "error": "Password must contain at least one uppercase letter.",
        })

    if not any(c.isdigit() for c in password):
        return admin_app.render("users/create.html", request, {
            **form_ctx,
            "error": "Password must contain at least one digit.",
        })

    if role not in ("admin", "operator", "viewer"):
        role = "viewer"

    # Check if user exists
    existing = _get_admin_users(admin_app.config_path)
    if username in existing:
        return admin_app.render("users/create.html", request, {
            **form_ctx,
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
        admin_app.restart_needed = True
    except Exception as e:
        logger.exception("Failed to create user: %s", e)
        return admin_app.render("users/create.html", request, {
            **form_ctx,
            "error": f"Failed to save: {e}",
        })

    return admin_app.flash_redirect("/users", f"User '{username}' created. Restart required.")


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

    is_self = (username == session.user)

    if request.method == "POST":
        form = await request.form()

        # Concurrent-edit guard: refuse if config.toml mtime changed
        # since this form was rendered (another admin saved between).
        from zabbix_mcp.admin.config_writer import config_mtime
        submitted_mtime = str(form.get("_cfg_mtime", "") or "")
        if submitted_mtime and submitted_mtime != config_mtime(admin_app.config_path):
            return admin_app.flash_redirect(
                f"/users/{username}",
                "Another admin saved this config while you were editing. Reload to see the latest values, then re-apply your change.",
                "danger",
            )

        new_password = str(form.get("password", "")).strip()
        confirm_password = str(form.get("confirm_password", "")).strip()
        current_password = str(form.get("current_password", "")).strip()
        new_role = str(form.get("role", "")).strip()
        current_role = user.get("role", "viewer")

        error = None

        # Self role-change is a foot-gun: an admin who downgrades
        # themselves to viewer locks themselves out of the portal.
        # Reported 2026-04-27 - tester accidentally did exactly that
        # on a fresh install with one admin account. Other admins can
        # still demote them through their own session.
        if is_self and new_role and new_role != current_role:
            error = "You cannot change your own role. Ask another admin to do it."

        # The last remaining admin must stay an admin so the operator
        # can always recover. Pair check with the self-delete guard
        # below.
        if not error and current_role == "admin" and new_role and new_role != "admin":
            existing_users = _get_admin_users(admin_app.config_path)
            admin_count = sum(1 for u in existing_users.values() if u.get("role") == "admin")
            if admin_count <= 1:
                error = "At least one admin account must remain. Promote another user to admin before demoting this one."

        # If changing own password, require current password
        if is_self and new_password and not error:
            if not current_password:
                error = "Current password is required to change your own password."
            elif not verify_password(current_password, user.get("password_hash", "")):
                error = "Current password is incorrect."

        # Confirm password must match
        if new_password and new_password != confirm_password:
            error = "New password and confirmation do not match."

        if new_password and len(new_password) < 10:
            error = "Password must be at least 10 characters."
        elif new_password and not any(c.isupper() for c in new_password):
            error = "Password must contain at least one uppercase letter."
        elif new_password and not any(c.isdigit() for c in new_password):
            error = "Password must contain at least one digit."

        if error:
            return admin_app.render("users/create.html", request, {
                "active": "users",
                "edit_mode": True,
                "edit_username": username,
                "edit_role": user.get("role", "viewer"),
                "is_self": is_self,
                "error": error,
            })

        try:
            doc = load_config_document(admin_app.config_path)
            user_section = doc["admin"]["users"][username]

            if new_password:
                user_section["password_hash"] = hash_password(new_password)

            if new_role in ("admin", "operator", "viewer"):
                user_section["role"] = new_role

            save_config_document(admin_app.config_path, doc)
            logger.info("User '%s' updated by %s", username, session.user)
            client_ip = request.client.host if request.client else ""
            write_audit("user_edit", user=session.user, target_type="user", target_id=username, ip=client_ip)
            admin_app.restart_needed = True
            return admin_app.flash_redirect(f"/users/{username}", "User updated. Restart required.")
        except Exception as e:
            logger.error("Failed to update user: %s", e)
            return admin_app.flash_redirect(f"/users/{username}", f"Failed to update: {e}", "danger")

    from zabbix_mcp.admin.config_writer import config_mtime
    return admin_app.render("users/create.html", request, {
        "active": "users",
        "edit_mode": True,
        "edit_username": username,
        "edit_role": user.get("role", "viewer"),
        "is_self": is_self,
        "config_mtime": config_mtime(admin_app.config_path),
    })


async def user_bulk_delete(request: Request) -> Response:
    """Delete multiple admin users at once (Bug 27).

    Mirrors token_bulk_delete: pick rows, type DELETE N, submit.
    Self-row checkbox is omitted in the list template, so the
    operator can't even queue themselves; defensive check here too.
    """
    admin_app = request.app.state.admin_app
    session = admin_app.require_auth(request)
    if not session or session.role != "admin":
        return RedirectResponse("/users", status_code=303)

    form = await request.form()
    ids = [str(s).strip() for s in form.getlist("ids") if str(s).strip()]
    if not ids:
        return admin_app.flash_redirect("/users", "No users selected.", "danger")
    if len(ids) > BULK_DELETE_MAX:
        return admin_app.flash_redirect(
            "/users",
            f"Bulk delete is capped at {BULK_DELETE_MAX} users per request (got {len(ids)}).",
            "danger",
        )
    if session.user in ids:
        return admin_app.flash_redirect(
            "/users",
            f"You cannot include your own account ({session.user}) in a bulk delete.",
            "danger",
        )

    try:
        doc = load_config_document(admin_app.config_path)
        admin = doc.get("admin", {})
        users = admin.get("users", {})
        # Last-admin protection - reject the whole batch if it would
        # remove every remaining admin. Counting from `users` (config
        # snapshot) before we touch it.
        all_admins = {u for u, d in users.items() if d.get("role") == "admin"}
        targeted_admins = all_admins.intersection(ids)
        remaining_admins = all_admins - targeted_admins
        if all_admins and not remaining_admins:
            return admin_app.flash_redirect(
                "/users",
                f"This batch would remove the last admin ({', '.join(sorted(targeted_admins))}). Keep at least one admin or promote another user first.",
                "danger",
            )
        deleted: list[str] = []
        missing: list[str] = []
        for uid in ids:
            if uid in users:
                del users[uid]
                deleted.append(uid)
            else:
                missing.append(uid)
        save_config_document(admin_app.config_path, doc)
        client_ip = request.client.host if request.client else ""
        for uid in deleted:
            write_audit("user_delete", user=session.user, target_type="user", target_id=uid, ip=client_ip)
        logger.info("Bulk-deleted %d user(s) by %s: %s", len(deleted), session.user, deleted)
        admin_app.restart_needed = True
        msg = f"Deleted {len(deleted)} user(s). Restart required."
        if missing:
            msg += f" Skipped (not found): {', '.join(missing)}."
        return admin_app.flash_redirect("/users", msg)
    except Exception as e:
        logger.error("Bulk-delete users failed: %s", e)
        return admin_app.flash_redirect("/users", f"Bulk-delete failed: {e}", "danger")


async def user_delete(request: Request) -> Response:
    admin_app = request.app.state.admin_app
    session = admin_app.require_auth(request)
    if not session or session.role != "admin":
        return RedirectResponse("/users", status_code=303)

    username = request.path_params["username"]

    # Prevent deleting yourself - the previous bare 303 looked like a
    # successful delete, leaving the operator confused why the row was
    # still there. Surface a clear message.
    if username == session.user:
        return admin_app.flash_redirect(
            "/users",
            "You cannot delete your own account. Sign in as another admin to remove this user.",
            "danger",
        )

    try:
        doc = load_config_document(admin_app.config_path)
        admin = doc.get("admin", {})
        users = admin.get("users", {})
        if username not in users:
            return admin_app.flash_redirect("/users", f"User '{username}' not found.", "danger")
        # Refuse to remove the last admin - if this user is the only
        # account with role=admin, deleting them would lock everyone
        # out of the portal with no recovery short of editing
        # config.toml on disk.
        target_role = users[username].get("role", "viewer")
        if target_role == "admin":
            admin_count = sum(1 for u in users.values() if u.get("role") == "admin")
            if admin_count <= 1:
                return admin_app.flash_redirect(
                    "/users",
                    "Cannot delete the last admin account. Promote another user to admin first.",
                    "danger",
                )
        del users[username]
        save_config_document(admin_app.config_path, doc)
        logger.info("User '%s' deleted by %s", username, session.user)
        client_ip = request.client.host if request.client else ""
        write_audit("user_delete", user=session.user, target_type="user", target_id=username, ip=client_ip)
        admin_app.restart_needed = True
        return admin_app.flash_redirect("/users", f"User '{username}' deleted. Restart required.")
    except Exception as e:
        logger.error("Failed to delete user: %s", e)
        return admin_app.flash_redirect("/users", f"Failed to delete user: {e}", "danger")

    return RedirectResponse("/users", status_code=303)
