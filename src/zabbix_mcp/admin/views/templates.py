#
# Zabbix MCP Server
# Copyright (C) 2026 initMAX s.r.o.
#

"""Report template CRUD views with interactive editor."""

from __future__ import annotations

import base64
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

_BUILTIN_DESCRIPTIONS = {
    "availability": "Host availability with SLA gauge chart and events per host",
    "capacity_host": "CPU, memory, and disk usage per host",
    "capacity_network": "Network bandwidth and traffic per interface",
    "backup": "Daily backup success/fail matrix (hosts \u00d7 days)",
}


def _get_builtin_templates() -> list[dict]:
    """List built-in report templates."""
    templates = []
    for key, filename in _REPORT_TEMPLATES.items():
        path = TEMPLATE_DIR / filename
        templates.append({
            "id": key,
            "name": key.replace("_", " ").title(),
            "description": _BUILTIN_DESCRIPTIONS.get(key, ""),
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
        initial_name = ""
        initial_description = ""
        if duplicate_from and duplicate_from in _REPORT_TEMPLATES:
            src_path = TEMPLATE_DIR / _REPORT_TEMPLATES[duplicate_from]
            if src_path.exists():
                initial_content = src_path.read_text(encoding="utf-8")
            initial_name = f"{duplicate_from}_custom"
            initial_description = _BUILTIN_DESCRIPTIONS.get(duplicate_from, "")

        return admin_app.render("report_templates/edit.html", request, {
            "active": "templates",
            "create_mode": True,
            "initial_content": initial_content,
            "initial_name": initial_name,
            "initial_description": initial_description,
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

    # Check for name collision
    existing_custom = _get_custom_templates(admin_app.config_path)
    if any(t["id"] == safe_name for t in existing_custom):
        return admin_app.render("report_templates/edit.html", request, {
            "active": "templates",
            "create_mode": True,
            "error": f"A template with name '{safe_name}' already exists.",
            "initial_content": html_content,
        })

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

    # SECURITY: validate path is within allowed directories (prevents path traversal via config)
    resolved = file_path.resolve()
    if not (str(resolved).startswith(str(CUSTOM_TEMPLATE_DIR.resolve())) or str(resolved).startswith(str(TEMPLATE_DIR.resolve()))):
        logger.warning("Template path outside allowed directory: %s", resolved)
        return RedirectResponse("/templates", status_code=303)

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
    if not session or session.role == "viewer":
        return HTMLResponse("Unauthorized", status_code=401)

    html_content = ""
    if request.method == "POST":
        form = await request.form()
        html_content = str(form.get("html_content", ""))
    elif "template_id" in request.path_params:
        # GET — load template content from file (custom or built-in)
        template_id = request.path_params["template_id"]

        # Check built-in templates first
        if template_id in _REPORT_TEMPLATES:
            builtin_path = TEMPLATE_DIR / _REPORT_TEMPLATES[template_id]
            if builtin_path.exists():
                html_content = builtin_path.read_text(encoding="utf-8")

        # Then check custom templates
        if not html_content:
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
        from jinja2.sandbox import SandboxedEnvironment
        from jinja2 import FileSystemLoader
        env = SandboxedEnvironment(
            autoescape=True,
            loader=FileSystemLoader(str(TEMPLATE_DIR)),
        )
        template = env.from_string(html_content)
        import math
        pct = 99.5
        angle_deg = 180.0 - (pct / 100.0) * 180.0
        angle_rad = math.radians(angle_deg)
        end_x = 100.0 + 80.0 * math.cos(angle_rad)
        end_y = 100.0 - 80.0 * math.sin(angle_rad)
        gauge_arc = f"M 20 100 A 80 80 0 1 1 {end_x:.1f} {end_y:.1f}"

        # Use initMAX logo as preview fallback
        logo_fallback = None
        logo_path = Path(__file__).parent.parent / "static" / "logo-horizontal-dark.svg"
        if logo_path.exists():
            logo_data = logo_path.read_bytes()
            logo_b64 = base64.b64encode(logo_data).decode("ascii")
            logo_fallback = f"data:image/svg+xml;base64,{logo_b64}"

        rendered = template.render(
            company="Sample Company",
            subtitle="IT Monitoring Service",
            generated_at="2026-01-01 00:00 UTC",
            page_label="Page",
            logo_base64=logo_fallback,
            availability_pct=pct,
            gauge_arc_path=gauge_arc,
            total_events=3,
            period_from="2026-01-01",
            period_to="2026-01-31",
            period_label="01/2026",
            hosts=[
                {"name": "host-01", "host": "host-01", "availability_pct": 100.0, "event_count": 0},
                {"name": "host-02", "host": "host-02", "availability_pct": 98.5, "event_count": 3},
            ],
            cpu_data=[{"host": "host-01", "avg": 15.2, "min": 2.1, "max": 78.5}],
            memory_data=[{"host": "host-01", "avg": 45.0, "min": 30.0, "max": 82.0}],
            disk_data=[{"host": "host-01", "avg": 55.0, "min": 40.0, "max": 70.0}],
            days=list(range(1, 31)),
            backup_matrix=[{"host": "host-01", "results": {d: True for d in range(1, 31)}}],
        )
        return HTMLResponse(rendered)
    except Exception as e:
        import html as _html
        return HTMLResponse(f"<p style='color:red'>Template error: {_html.escape(str(e))}</p>")


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
        # SECURITY: only delete files within allowed directories
        resolved_del = file_path.resolve()
        if not str(resolved_del).startswith(str(CUSTOM_TEMPLATE_DIR.resolve())):
            logger.warning("Blocked deletion outside custom template dir: %s", resolved_del)
        elif file_path.exists():
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
