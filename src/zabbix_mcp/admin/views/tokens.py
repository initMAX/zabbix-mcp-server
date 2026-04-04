#
# Zabbix MCP Server
# Copyright (C) 2026 initMAX s.r.o.
#

"""MCP Token CRUD views — create, list, edit, revoke, delete."""

from __future__ import annotations

import logging

from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

from zabbix_mcp.admin.config_writer import (
    add_config_table,
    load_config_document,
    remove_config_table,
    update_config_section,
    TOMLKIT_AVAILABLE,
)
from zabbix_mcp.admin.audit_writer import write_audit
from zabbix_mcp.token_store import TokenStore

logger = logging.getLogger("zabbix_mcp.admin")


async def token_list(request: Request) -> Response:
    admin_app = request.app.state.admin_app
    session = admin_app.require_auth(request)
    if not session:
        return RedirectResponse("/login", status_code=303)

    tokens = admin_app.token_store.list_tokens()
    return admin_app.render("tokens/list.html", request, {
        "active": "tokens",
        "tokens": tokens,
    })


async def token_create(request: Request) -> Response:
    admin_app = request.app.state.admin_app
    session = admin_app.require_auth(request)
    if not session:
        return RedirectResponse("/login", status_code=303)
    if session.role == "viewer":
        return admin_app.render("tokens/list.html", request, {
            "active": "tokens",
            "tokens": admin_app.token_store.list_tokens(),
            "flash_message": "Insufficient permissions.",
            "flash_type": "danger",
        })

    if request.method == "GET":
        return admin_app.render("tokens/create.html", request, {
            "active": "tokens",
        })

    # POST — create token
    form = await request.form()
    name = str(form.get("name", "")).strip()
    if not name:
        return admin_app.render("tokens/create.html", request, {
            "active": "tokens",
            "error": "Name is required.",
        })

    # Parse scopes from form checkboxes
    scopes = form.getlist("scopes")
    if not scopes:
        scopes = ["*"]

    read_only = form.get("read_only") == "on"
    allowed_ips_raw = str(form.get("allowed_ips", "")).strip()
    allowed_ips = [ip.strip() for ip in allowed_ips_raw.split("\n") if ip.strip()] if allowed_ips_raw else None
    expires_at = str(form.get("expires_at", "")).strip() or None

    # Generate token
    raw_token, token_hash = TokenStore.generate_token()

    # Create a safe config key from the name
    import re
    token_id = re.sub(r"[^a-z0-9_]", "_", name.lower())[:50]
    if not token_id or not token_id[0].isalpha():
        token_id = "t_" + token_id

    # Write to config.toml
    token_data = {
        "name": name,
        "token_hash": token_hash,
        "scopes": list(scopes),
        "read_only": read_only,
    }
    if allowed_ips:
        token_data["allowed_ips"] = allowed_ips
    if expires_at:
        token_data["expires_at"] = expires_at

    try:
        add_config_table(admin_app.config_path, "tokens", token_id, token_data)
        # Reload token store
        _reload_tokens(admin_app)
        logger.info("Token '%s' created by %s", name, session.user)
        client_ip = request.client.host if request.client else ""
        write_audit("token_create", user=session.user, target_type="token", target_id=token_id, ip=client_ip)
    except Exception as e:
        logger.error("Failed to create token: %s", e)
        return admin_app.render("tokens/create.html", request, {
            "active": "tokens",
            "error": f"Failed to save: {e}",
        })

    # Show the raw token ONCE
    return admin_app.render("tokens/create.html", request, {
        "active": "tokens",
        "created_token": raw_token,
        "token_name": name,
        "token_id": token_id,
    })


async def token_detail(request: Request) -> Response:
    admin_app = request.app.state.admin_app
    session = admin_app.require_auth(request)
    if not session:
        return RedirectResponse("/login", status_code=303)

    token_id = request.path_params["token_id"]
    token = admin_app.token_store.get_token(token_id)
    if not token:
        return RedirectResponse("/tokens", status_code=303)

    if request.method == "POST" and session.role != "viewer":
        form = await request.form()
        updates = {}
        name = str(form.get("name", "")).strip()
        if name:
            updates["name"] = name

        scopes = form.getlist("scopes")
        if scopes:
            updates["scopes"] = list(scopes)

        read_only = form.get("read_only") == "on"
        updates["read_only"] = read_only

        allowed_ips_raw = str(form.get("allowed_ips", "")).strip()
        if allowed_ips_raw:
            updates["allowed_ips"] = [ip.strip() for ip in allowed_ips_raw.split("\n") if ip.strip()]
        else:
            updates["allowed_ips"] = []

        expires_at = str(form.get("expires_at", "")).strip()
        if expires_at:
            updates["expires_at"] = expires_at

        try:
            # Read current, merge updates
            doc = load_config_document(admin_app.config_path)
            tokens_section = doc.get("tokens", {})
            if token_id in tokens_section:
                for k, v in updates.items():
                    tokens_section[token_id][k] = v
                from zabbix_mcp.admin.config_writer import save_config_document
                save_config_document(admin_app.config_path, doc)
                _reload_tokens(admin_app)
                logger.info("Token '%s' updated by %s", token_id, session.user)
        except Exception as e:
            logger.error("Failed to update token: %s", e)

        return RedirectResponse(f"/tokens/{token_id}", status_code=303)

    return admin_app.render("tokens/detail.html", request, {
        "active": "tokens",
        "token": token,
        "token_id": token_id,
    })


async def token_revoke(request: Request) -> Response:
    admin_app = request.app.state.admin_app
    session = admin_app.require_auth(request)
    if not session or session.role == "viewer":
        return RedirectResponse("/tokens", status_code=303)

    token_id = request.path_params["token_id"]
    try:
        doc = load_config_document(admin_app.config_path)
        tokens_section = doc.get("tokens", {})
        if token_id in tokens_section:
            current = tokens_section[token_id].get("is_active", True)
            tokens_section[token_id]["is_active"] = not current
            from zabbix_mcp.admin.config_writer import save_config_document
            save_config_document(admin_app.config_path, doc)
            _reload_tokens(admin_app)
            action = "revoked" if current else "activated"
            logger.info("Token '%s' %s by %s", token_id, action, session.user)
            client_ip = request.client.host if request.client else ""
            write_audit(f"token_{action}", user=session.user, target_type="token", target_id=token_id, ip=client_ip)
    except Exception as e:
        logger.error("Failed to revoke token: %s", e)

    return RedirectResponse("/tokens", status_code=303)


async def token_delete(request: Request) -> Response:
    admin_app = request.app.state.admin_app
    session = admin_app.require_auth(request)
    if not session or session.role != "admin":
        return RedirectResponse("/tokens", status_code=303)

    token_id = request.path_params["token_id"]
    try:
        remove_config_table(admin_app.config_path, "tokens", token_id)
        _reload_tokens(admin_app)
        logger.info("Token '%s' deleted by %s", token_id, session.user)
        client_ip = request.client.host if request.client else ""
        write_audit("token_delete", user=session.user, target_type="token", target_id=token_id, ip=client_ip)
    except Exception as e:
        logger.error("Failed to delete token: %s", e)

    return RedirectResponse("/tokens", status_code=303)


def _reload_tokens(admin_app) -> None:
    """Reload tokens from config.toml into the token store."""
    try:
        doc = load_config_document(admin_app.config_path)
        tokens_raw = doc.get("tokens", {})
        tokens_config = {k: dict(v) for k, v in tokens_raw.items()}
        admin_app.token_store.load_from_config(tokens_config)
    except Exception as e:
        logger.error("Failed to reload tokens: %s", e)
