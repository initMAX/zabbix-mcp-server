#
# Zabbix MCP Server
# Copyright (C) 2026 initMAX s.r.o.
#

"""Report template CRUD views with interactive editor."""

from __future__ import annotations

import logging
from pathlib import Path

from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

from zabbix_mcp.admin.config_writer import (
    add_config_table,
    load_config_document,
    remove_config_table,
    save_config_document,
    TOMLKIT_AVAILABLE,
)
from zabbix_mcp.reporting.engine import TEMPLATE_DIR, _REPORT_TEMPLATES, REPORTING_AVAILABLE

logger = logging.getLogger("zabbix_mcp.admin")

CUSTOM_TEMPLATE_DIR = Path("/var/log/zabbix-mcp/templates")


def _get_builtin_templates() -> list[dict]:
    """List built-in report templates."""
    templates = []
    for key, filename in _REPORT_TEMPLATES.items():
        path = TEMPLATE_DIR / filename
        templates.append({
            "id": key,
            "name": key.replace("_", " ").title(),
            "filename": filename,
            "builtin": True,
            "exists": path.exists(),
        })
    return templates


def _get_custom_templates(config_path: str) -> list[dict]:
    """List custom report templates from config."""
    if not TOMLKIT_AVAILABLE:
        return []
    try:
        doc = load_config_document(config_path)
        templates = doc.get("report_templates", {})
        result = []
        for key, val in templates.items():
            v = dict(val)
            result.append({
                "id": key,
                "name": v.get("display_name", key),
                "description": v.get("description", ""),
                "template_file": v.get("template_file", ""),
                "builtin": False,
            })
        return result
    except Exception:
        return []


async def template_list(request: Request) -> Response:
    admin_app = request.app.state.admin_app
    session = admin_app.require_auth(request)
    if not session:
        return RedirectResponse("/login", status_code=303)

    builtin = _get_builtin_templates()
    custom = _get_custom_templates(admin_app.config_path)

    return admin_app.render("report_templates/list.html", request, {
        "active": "templates",
        "builtin_templates": builtin,
        "custom_templates": custom,
        "reporting_available": REPORTING_AVAILABLE,
    })


async def template_create(request: Request) -> Response:
    admin_app = request.app.state.admin_app
    session = admin_app.require_auth(request)
    if not session or session.role == "viewer":
        return RedirectResponse("/templates", status_code=303)

    if request.method == "GET":
        # Check if duplicating a built-in
        duplicate_from = request.query_params.get("duplicate")
        initial_content = ""
        if duplicate_from and duplicate_from in _REPORT_TEMPLATES:
            src_path = TEMPLATE_DIR / _REPORT_TEMPLATES[duplicate_from]
            if src_path.exists():
                initial_content = src_path.read_text(encoding="utf-8")

        return admin_app.render("report_templates/edit.html", request, {
            "active": "templates",
            "create_mode": True,
            "initial_content": initial_content,
            "duplicate_from": duplicate_from,
        })

    # POST — save new template
    form = await request.form()
    name = str(form.get("name", "")).strip()
    display_name = str(form.get("display_name", "")).strip() or name
    description = str(form.get("description", "")).strip()
    html_content = str(form.get("html_content", ""))

    if not name:
        return admin_app.render("report_templates/edit.html", request, {
            "active": "templates",
            "create_mode": True,
            "error": "Template name is required.",
            "initial_content": html_content,
        })

    # Sanitize name for filesystem
    import re
    safe_name = re.sub(r"[^a-z0-9_]", "_", name.lower())[:50]
    filename = f"{safe_name}.html"

    # Write HTML to file in writable location
    try:
        CUSTOM_TEMPLATE_DIR.mkdir(parents=True, exist_ok=True)
        file_path = CUSTOM_TEMPLATE_DIR / filename
        file_path.write_text(html_content, encoding="utf-8")
    except Exception as e:
        logger.error("Failed to write template file: %s", e)
        return admin_app.render("report_templates/edit.html", request, {
            "active": "templates",
            "create_mode": True,
            "error": f"Failed to write template file: {e}",
            "initial_content": html_content,
        })

    # Write to config
    try:
        add_config_table(admin_app.config_path, "report_templates", safe_name, {
            "display_name": display_name,
            "description": description,
            "template_file": str(CUSTOM_TEMPLATE_DIR / filename),
        })
        logger.info("Report template '%s' created by %s", safe_name, session.user)
    except Exception as e:
        logger.error("Failed to save template config: %s", e)

    return RedirectResponse("/templates", status_code=303)


async def template_edit(request: Request) -> Response:
    admin_app = request.app.state.admin_app
    session = admin_app.require_auth(request)
    if not session or session.role == "viewer":
        return RedirectResponse("/templates", status_code=303)

    template_id = request.path_params["template_id"]

    # Find template (custom only for editing)
    custom = _get_custom_templates(admin_app.config_path)
    tmpl = next((t for t in custom if t["id"] == template_id), None)
    if not tmpl:
        return RedirectResponse("/templates", status_code=303)

    tmpl_file = tmpl["template_file"]
    file_path = Path(tmpl_file) if tmpl_file.startswith("/") else TEMPLATE_DIR / tmpl_file
    content = file_path.read_text(encoding="utf-8") if file_path.exists() else ""

    if request.method == "POST":
        form = await request.form()
        display_name = str(form.get("display_name", "")).strip()
        description = str(form.get("description", "")).strip()
        html_content = str(form.get("html_content", ""))

        # Update file
        try:
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_text(html_content, encoding="utf-8")
        except Exception as e:
            logger.error("Failed to write template file: %s", e)

        # Update config
        try:
            doc = load_config_document(admin_app.config_path)
            templates = doc.get("report_templates", {})
            if template_id in templates:
                if display_name:
                    templates[template_id]["display_name"] = display_name
                if description is not None:
                    templates[template_id]["description"] = description
                save_config_document(admin_app.config_path, doc)
            logger.info("Report template '%s' updated by %s", template_id, session.user)
        except Exception as e:
            logger.error("Failed to update template config: %s", e)

        return RedirectResponse(f"/templates/{template_id}", status_code=303)

    return admin_app.render("report_templates/edit.html", request, {
        "active": "templates",
        "template": tmpl,
        "template_id": template_id,
        "initial_content": content,
    })


async def template_preview(request: Request) -> Response:
    """Render template preview with sample data."""
    admin_app = request.app.state.admin_app
    session = admin_app.require_auth(request)
    if not session:
        return HTMLResponse("Unauthorized", status_code=401)

    html_content = ""
    if request.method == "POST":
        form = await request.form()
        html_content = str(form.get("html_content", ""))
    elif "template_id" in request.path_params:
        # GET — load template content from file
        template_id = request.path_params["template_id"]
        custom = _get_custom_templates(admin_app.config_path)
        tmpl = next((t for t in custom if t["id"] == template_id), None)
        if tmpl and tmpl.get("template_file"):
            tmpl_file = tmpl["template_file"]
            file_path = Path(tmpl_file) if tmpl_file.startswith("/") else TEMPLATE_DIR / tmpl_file
            if file_path.exists():
                html_content = file_path.read_text(encoding="utf-8")

    if not html_content:
        return HTMLResponse("<p>No content to preview.</p>")

    # Render with sample context
    try:
        import jinja2
        env = jinja2.Environment(autoescape=True)
        template = env.from_string(html_content)
        rendered = template.render(
            company="Sample Company",
            subtitle="IT Monitoring Service",
            generated_at="2026-01-01 00:00 UTC",
            page_label="Page",
            logo_base64=None,
            availability_pct=99.5,
            hosts=[
                {"name": "host-01", "availability": 100.0, "events": 0},
                {"name": "host-02", "availability": 98.5, "events": 3},
            ],
            period_label="01/2026",
        )
        return HTMLResponse(rendered)
    except Exception as e:
        return HTMLResponse(f"<p style='color:red'>Template error: {e}</p>")


async def template_delete(request: Request) -> Response:
    admin_app = request.app.state.admin_app
    session = admin_app.require_auth(request)
    if not session or session.role != "admin":
        return RedirectResponse("/templates", status_code=303)

    template_id = request.path_params["template_id"]

    # Get template info to find the file
    custom = _get_custom_templates(admin_app.config_path)
    tmpl = next((t for t in custom if t["id"] == template_id), None)

    if tmpl:
        # Delete file
        tmpl_file = tmpl.get("template_file", "")
        file_path = Path(tmpl_file) if tmpl_file.startswith("/") else TEMPLATE_DIR / tmpl_file
        if file_path.exists() and str(file_path) != str(TEMPLATE_DIR):
            try:
                file_path.unlink()
            except Exception as e:
                logger.error("Failed to delete template file: %s", e)

        # Remove from config
        try:
            remove_config_table(admin_app.config_path, "report_templates", template_id)
            logger.info("Report template '%s' deleted by %s", template_id, session.user)
        except Exception as e:
            logger.error("Failed to delete template: %s", e)

    return RedirectResponse("/templates", status_code=303)
