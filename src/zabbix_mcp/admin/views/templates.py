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
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from zabbix_mcp.admin.config_writer import (
    add_config_table,
    load_config_document,
    remove_config_table,
    save_config_document,
    TOMLKIT_AVAILABLE,
)
from zabbix_mcp.reporting.engine import TEMPLATE_DIR, _REPORT_TEMPLATES, REPORTING_AVAILABLE

logger = logging.getLogger("zabbix_mcp.admin")

CUSTOM_TEMPLATE_DIR = Path("/etc/zabbix-mcp/templates")

def _validate_template_syntax(html_content: str) -> str | None:
    """Return a user-facing error string if the template won't render.

    Uses the same SandboxedEnvironment + sample context as the AI
    validator so operators who hand-edit or paste templates get the
    same guardrail the AI path already has. Returns None when the
    template renders cleanly against sample data.
    """
    if not html_content.strip():
        return None
    try:
        from zabbix_mcp.admin.ai_template import (
            AITemplateValidationError,
            validate_template,
        )
    except Exception:
        # Reporting extras not installed - skip validation rather
        # than block saves on a system that cannot render reports.
        return None
    try:
        validate_template(html_content)
        return None
    except AITemplateValidationError as exc:
        return str(exc)


_BUILTIN_DESCRIPTIONS = {
    "availability": "Host availability with SLA gauge chart and events per host",
    "capacity_host": "CPU, memory, and disk usage per host",
    "capacity_network": "Network bandwidth and traffic per interface",
    "backup": "Daily backup success/fail matrix (hosts \u00d7 days)",
    "showcase": "Showcase report - demonstrates every v1.23 visual editor widget (gauge, metric cards, bars, two/three columns, page breaks, note, hosts loop, backup matrix)",
}


def _ai_template_ctx(config) -> dict:
    """Return the {ai_enabled, ai_provider, ai_model} template context.

    "Enabled" in v1.23+ means "the UI button is available", which is
    always True because the wizard supports bring-your-own-key - the
    operator can paste their own Anthropic/OpenAI key right in the
    dialog without touching config.toml. We surface the server-side
    defaults so the dropdown can label the "Server default" option
    with the configured provider/model, or "none" when the section
    is missing.
    """
    try:
        from zabbix_mcp.admin.ai_template import is_ai_enabled
    except Exception:
        is_ai_enabled = lambda c: False  # noqa: E731
    ai = getattr(config, "admin_ai", None)
    server_configured = bool(is_ai_enabled(config))
    return {
        "ai_enabled": True,
        "ai_server_configured": server_configured,
        "ai_provider": (getattr(ai, "provider", "") or "") if server_configured else "",
        "ai_model": (getattr(ai, "model", "") or "") if server_configured else "",
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
            **_ai_template_ctx(admin_app.config),
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
            "initial_description": description,
            **_ai_template_ctx(admin_app.config),
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
            "initial_name": name,
            "initial_description": description,
            **_ai_template_ctx(admin_app.config),
        })

    # Validate Jinja syntax before write so we never ship a broken
    # template into the templates directory (and then hit the same
    # error on every preview/PDF attempt).
    validation_error = _validate_template_syntax(html_content)
    if validation_error:
        return admin_app.render("report_templates/edit.html", request, {
            "active": "templates",
            "create_mode": True,
            "error": f"Template will not render: {validation_error}",
            "initial_content": html_content,
            "initial_name": name,
            "initial_description": description,
            **_ai_template_ctx(admin_app.config),
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
            "initial_name": name,
            "initial_description": description,
            **_ai_template_ctx(admin_app.config),
        })

    # Write to config
    try:
        add_config_table(admin_app.config_path, "report_templates", safe_name, {
            "display_name": display_name,
            "description": description,
            "template_file": str(CUSTOM_TEMPLATE_DIR / filename),
        })
        logger.info("Report template '%s' created by %s", safe_name, session.user)
        from zabbix_mcp.admin.audit_writer import write_audit
        write_audit("template_create", user=session.user, target_type="template", target_id=safe_name, ip=request.client.host if request.client else "")
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
    _custom_dir = CUSTOM_TEMPLATE_DIR.resolve()
    _tmpl_dir = TEMPLATE_DIR.resolve()
    if not (resolved.is_relative_to(_custom_dir) or resolved.is_relative_to(_tmpl_dir)):
        logger.warning("Template path outside allowed directory: %s", resolved)
        return RedirectResponse("/templates", status_code=303)

    content = file_path.read_text(encoding="utf-8") if file_path.exists() else ""

    if request.method == "POST":
        form = await request.form()
        display_name = str(form.get("display_name", "")).strip()
        description = str(form.get("description", "")).strip()
        html_content = str(form.get("html_content", ""))

        # Validate Jinja syntax before overwriting the saved file so a
        # typo never replaces a working template with a broken one.
        validation_error = _validate_template_syntax(html_content)
        if validation_error:
            return admin_app.render("report_templates/edit.html", request, {
                "active": "templates",
                "t": {
                    "id": template_id,
                    "name": display_name or tmpl["name"],
                    "description": description,
                },
                "error": f"Template will not render: {validation_error}",
                "initial_content": html_content,
                **_ai_template_ctx(admin_app.config),
            })

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
            from zabbix_mcp.admin.audit_writer import write_audit
            write_audit("template_edit", user=session.user, target_type="template", target_id=template_id, ip=request.client.host if request.client else "")
        except Exception as e:
            logger.error("Failed to update template config: %s", e)

        return RedirectResponse(f"/templates/{template_id}", status_code=303)

    return admin_app.render("report_templates/edit.html", request, {
        "active": "templates",
        "template": tmpl,
        "template_id": template_id,
        "initial_content": content,
        **_ai_template_ctx(admin_app.config),
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
                # SECURITY: validate path is within allowed directories
                resolved = file_path.resolve()
                if not (resolved.is_relative_to(CUSTOM_TEMPLATE_DIR.resolve()) or resolved.is_relative_to(TEMPLATE_DIR.resolve())):
                    logger.warning("Template preview path outside allowed directory: %s", resolved)
                elif file_path.exists():
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
        # Reuse the canonical arc helper from the reporting engine so the
        # preview matches what `report_generate` produces. The inline
        # copy that used to live here had large-arc-flag=1 hard-coded,
        # which drew the lower semicircle for percentage values anyway
        # near 100%. Fixed in v1.21; keep a single source of truth.
        from zabbix_mcp.reporting.engine import _compute_gauge_arc_path
        pct = 99.5
        gauge_arc = _compute_gauge_arc_path(pct)

        # Prefer the operator's uploaded logo (config.server.report_logo)
        # so the preview matches what report_generate produces. Fall back
        # to the bundled initMAX admin logo if nothing is configured or
        # the configured file cannot be read.
        logo_fallback = None
        configured_logo = getattr(admin_app.config.server, "report_logo", None)
        if configured_logo:
            configured_path = Path(configured_logo)
            if configured_path.is_file() and not configured_path.is_symlink():
                try:
                    logo_data = configured_path.read_bytes()
                    ext = configured_path.suffix.lower()
                    mime = {
                        ".svg": "image/svg+xml",
                        ".png": "image/png",
                        ".jpg": "image/jpeg",
                        ".jpeg": "image/jpeg",
                    }.get(ext, "application/octet-stream")
                    logo_b64 = base64.b64encode(logo_data).decode("ascii")
                    logo_fallback = f"data:{mime};base64,{logo_b64}"
                except OSError as exc:
                    logger.warning("Preview logo read failed for %s: %s", configured_path, exc)
        if logo_fallback is None:
            logo_path = Path(__file__).parent.parent / "static" / "logo-horizontal-dark.svg"
            if logo_path.exists():
                logo_data = logo_path.read_bytes()
                logo_b64 = base64.b64encode(logo_data).decode("ascii")
                logo_fallback = f"data:image/svg+xml;base64,{logo_b64}"

        # Sample context for preview. The key names and nesting here
        # must mirror what `reporting.data_fetcher` produces at runtime,
        # otherwise the preview renders empty sections (capacity + backup
        # reports iterate over `metrics` / `backup_matrix` with specific
        # shapes). Kept in sync with `fetch_capacity_host_data` /
        # `fetch_capacity_network_data` / `fetch_backup_data`.
        sample_days = list(range(1, 32))
        sample_statuses = {d: True for d in sample_days}
        # Mark a few days as failed so the preview shows the red cells.
        for d in (7, 14, 22):
            sample_statuses[d] = False
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
            # `hosts` covers availability AND capacity_network (the latter
            # iterates host.interfaces). We attach interfaces to every
            # host; availability.html ignores them, capacity_network.html
            # uses them.
            hosts=[
                {
                    "name": "host-01", "host": "host-01",
                    "availability_pct": 100.0, "event_count": 0,
                    "interfaces": [
                        {"name": "eth0", "bandwidth_mbps": 1000.0, "cpu_avg": 12.5, "cpu_min": 2.0, "cpu_max": 34.1},
                        {"name": "eth1", "bandwidth_mbps": 100.0, "cpu_avg": 68.2, "cpu_min": 30.0, "cpu_max": 92.0},
                    ],
                },
                {
                    "name": "host-02", "host": "host-02",
                    "availability_pct": 98.5, "event_count": 3,
                    "interfaces": [
                        {"name": "eth0", "bandwidth_mbps": 10000.0, "cpu_avg": 91.4, "cpu_min": 80.0, "cpu_max": 97.0},
                    ],
                },
            ],
            # capacity_network.html renders `cpu_rows` as a standalone
            # block above the per-host interface breakdown.
            cpu_rows=[
                {"endpoint": "host-01", "avg": 15.2, "min": 2.1, "max": 78.5},
                {"endpoint": "host-02", "avg": 63.4, "min": 40.0, "max": 95.1},
            ],
            landline_count=2,
            # capacity_host.html iterates `metrics[*].label` and each row
            # has `endpoint/avg/min/max`. Three metrics cover the bar-color
            # ranges (< 60 green, < 85 yellow, else red) so every color
            # path is exercised in the preview.
            metrics=[
                {
                    "label": "CPU Usage (%)",
                    "rows": [
                        {"endpoint": "host-01", "avg": 15.2, "min": 2.1, "max": 78.5},
                        {"endpoint": "host-02", "avg": 63.4, "min": 40.0, "max": 95.1},
                    ],
                },
                {
                    "label": "Memory Usage (%)",
                    "rows": [
                        {"endpoint": "host-01", "avg": 45.0, "min": 30.0, "max": 82.0},
                        {"endpoint": "host-02", "avg": 88.5, "min": 70.0, "max": 97.0},
                    ],
                },
                {
                    "label": "Disk Usage (%)",
                    "rows": [
                        {"endpoint": "host-01", "avg": 55.0, "min": 40.0, "max": 70.0},
                        {"endpoint": "host-02", "avg": 91.0, "min": 80.0, "max": 98.0},
                    ],
                },
            ],
            # backup.html iterates days (list of ints) × backup_matrix rows.
            # Each row is {host, statuses: {day_int: True|False|None}}.
            days=sample_days,
            backup_matrix=[
                {"host": "host-01", "statuses": sample_statuses},
                {"host": "host-02", "statuses": {d: (d % 3 != 0) for d in sample_days}},
                {"host": "host-03", "statuses": {d: True for d in sample_days}},
            ],
        )
        return HTMLResponse(rendered)
    except Exception as e:
        import html as _html
        # Full HTML document so the preview iframe renders the error
        # in a readable card instead of a bare paragraph on white.
        err_msg = _html.escape(str(e))
        err_type = _html.escape(e.__class__.__name__)
        return HTMLResponse(
            "<!DOCTYPE html><html><head><meta charset='utf-8'>"
            "<style>body{font-family:system-ui,Segoe UI,sans-serif;background:#fafafa;"
            "color:#222;padding:24px;margin:0;}"
            ".card{max-width:720px;margin:40px auto;padding:20px 24px;"
            "background:#fff;border:1px solid #e0e0e0;border-radius:8px;"
            "box-shadow:0 2px 6px rgba(0,0,0,0.05);}"
            ".card h2{margin:0 0 8px;color:#d32f2f;font-size:18px;}"
            ".card code{background:#fff3e0;padding:2px 6px;border-radius:3px;"
            "font-size:13px;}"
            ".card p{line-height:1.45;margin:8px 0;}"
            ".hint{color:#666;font-size:13px;margin-top:14px;}"
            "</style></head><body>"
            f"<div class='card'><h2>&#x26A0; Template rendering failed</h2>"
            f"<p><strong>{err_type}:</strong></p>"
            f"<p><code>{err_msg}</code></p>"
            "<p class='hint'>Fix the Jinja syntax in the HTML Code tab and preview again. "
            "Common causes: mismatched <code>{% if %}</code>/<code>{% endif %}</code>, "
            "ternary written as <code>(x y z)</code> instead of <code>x if cond else z</code>, "
            "or a loop variable used outside its <code>{% for %}</code> block.</p>"
            "</div></body></html>"
        )


async def template_generate(request: Request) -> Response:
    """POST /templates/generate - AI-assisted Jinja2 template generation.

    Body: JSON or form with a single `request` field carrying the
    operator's plain-English description of the report they want.
    Returns JSON with the generated HTML (+ provider/model/elapsed
    metadata) on success, or a structured error with HTTP 4xx/5xx.

    Admin or operator role required. Feature is silently disabled
    (412) if `[admin.ai]` is not configured.
    """
    admin_app = request.app.state.admin_app
    session = admin_app.require_auth(request)
    if not session:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    if session.role not in ("admin", "operator"):
        return JSONResponse({"error": "forbidden"}, status_code=403)

    # Accept either application/json or application/x-www-form-urlencoded.
    # Payload may also carry per-call provider overrides (provider, api_key,
    # model) so operators can bring their own key without touching
    # config.toml. The override is never logged or persisted.
    content_type = request.headers.get("content-type", "")
    user_request = ""
    override_provider: str | None = None
    override_api_key: str | None = None
    override_model: str | None = None
    override_api_base: str | None = None
    if content_type.startswith("application/json"):
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "invalid_json"}, status_code=400)
        user_request = str(body.get("request", "") or "")
        override_provider = body.get("provider") or None
        override_api_key = body.get("api_key") or None
        override_model = body.get("model") or None
        override_api_base = body.get("api_base") or None
    else:
        form = await request.form()
        user_request = str(form.get("request", "") or "")
        override_provider = str(form.get("provider", "") or "") or None
        override_api_key = str(form.get("api_key", "") or "") or None
        override_model = str(form.get("model", "") or "") or None
        override_api_base = str(form.get("api_base", "") or "") or None

    from zabbix_mcp.admin.ai_template import (
        AIDisabledError,
        AIProviderError,
        AITemplateValidationError,
        generate_template,
    )
    from zabbix_mcp.admin.audit_writer import write_audit

    client_ip = request.client.host if request.client else ""
    try:
        result = generate_template(
            admin_app.config,
            user_request,
            override_provider=override_provider,
            override_api_key=override_api_key,
            override_model=override_model,
            override_api_base=override_api_base,
        )
    except AIDisabledError as exc:
        return JSONResponse(
            {"error": "ai_disabled", "message": str(exc)},
            status_code=412,
        )
    except AITemplateValidationError as exc:
        return JSONResponse(
            {"error": "validation_failed", "message": str(exc)},
            status_code=400,
        )
    except AIProviderError as exc:
        logger.warning("AI template generation failed: %s", exc)
        return JSONResponse(
            {"error": "provider_error", "message": str(exc)},
            status_code=502,
        )
    except Exception as exc:
        logger.exception("AI template generation crashed")
        return JSONResponse(
            {"error": "internal_error", "message": str(exc)},
            status_code=500,
        )

    # Audit the fact of generation + request length + token cost, but
    # NOT the request text (may contain NDA'd data) or the response
    # (potentially dozens of KB of HTML).
    try:
        write_audit(
            "template_generate_ai",
            user=session.user,
            details={
                "provider": result.provider,
                "model": result.model,
                # Flag that the operator used their own key for this
                # generation rather than the server-side config. The
                # key itself is NEVER logged (it already never leaves
                # this Python process, but double-check).
                "byo_key": bool(override_api_key),
                "request_chars": len(user_request),
                "html_chars": len(result.html),
                "elapsed_ms": result.elapsed_ms,
            },
            ip=client_ip,
        )
    except Exception:
        # Audit failure must not crash the generation.
        pass

    return JSONResponse({
        "html": result.html,
        "provider": result.provider,
        "model": result.model,
        "elapsed_ms": result.elapsed_ms,
    })


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
        # SECURITY: only delete files within allowed directories (proper ancestry check)
        resolved_del = file_path.resolve()
        _del_dir = CUSTOM_TEMPLATE_DIR.resolve()
        if not resolved_del.is_relative_to(_del_dir):
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
            from zabbix_mcp.admin.audit_writer import write_audit
            write_audit("template_delete", user=session.user, target_type="template", target_id=template_id, ip=request.client.host if request.client else "")
            admin_app.restart_needed = True
            return admin_app.flash_redirect("/templates", f"Template '{template_id}' deleted. Restart required.")
        except Exception as e:
            logger.error("Failed to delete template: %s", e)
            return admin_app.flash_redirect("/templates", f"Failed to delete template: {e}", "danger")

    return RedirectResponse("/templates", status_code=303)


async def template_bulk_delete(request: Request) -> Response:
    """Delete multiple custom templates at once (Bug 27).

    Same selection / type-to-confirm flow as token / user bulk delete.
    Each template's HTML file is unlinked too (only when inside the
    sanctioned custom-templates directory - same path-traversal guard
    as the per-template delete handler).
    """
    admin_app = request.app.state.admin_app
    session = admin_app.require_auth(request)
    if not session or session.role != "admin":
        return RedirectResponse("/templates", status_code=303)

    form = await request.form()
    ids = [str(s).strip() for s in form.getlist("ids") if str(s).strip()]
    if not ids:
        return admin_app.flash_redirect("/templates", "No templates selected.", "danger")

    custom = _get_custom_templates(admin_app.config_path)
    by_id = {t["id"]: t for t in custom}
    deleted: list[str] = []
    missing: list[str] = []
    custom_dir = CUSTOM_TEMPLATE_DIR.resolve()

    try:
        from zabbix_mcp.admin.audit_writer import write_audit
        client_ip = request.client.host if request.client else ""
        for tid in ids:
            tmpl = by_id.get(tid)
            if not tmpl:
                missing.append(tid)
                continue
            tmpl_file = tmpl.get("template_file", "")
            file_path = Path(tmpl_file) if tmpl_file.startswith("/") else TEMPLATE_DIR / tmpl_file
            try:
                resolved = file_path.resolve()
                if resolved.is_relative_to(custom_dir) and resolved.exists():
                    resolved.unlink()
            except Exception as exc:
                logger.warning("template_bulk_delete: could not unlink %s: %s", file_path, exc)
            try:
                remove_config_table(admin_app.config_path, "report_templates", tid)
                deleted.append(tid)
                write_audit("template_delete", user=session.user, target_type="template", target_id=tid, ip=client_ip)
            except Exception as exc:
                logger.error("template_bulk_delete: config remove failed for %s: %s", tid, exc)
                missing.append(tid)
        admin_app.restart_needed = True
        msg = f"Deleted {len(deleted)} template(s). Restart required."
        if missing:
            msg += f" Skipped (not found / failed): {', '.join(missing)}."
        logger.info("Bulk-deleted %d template(s) by %s: %s", len(deleted), session.user, deleted)
        return admin_app.flash_redirect("/templates", msg)
    except Exception as e:
        logger.error("Bulk-delete templates failed: %s", e)
        return admin_app.flash_redirect("/templates", f"Bulk-delete failed: {e}", "danger")
