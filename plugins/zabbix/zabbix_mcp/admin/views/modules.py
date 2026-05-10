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

"""Admin portal "MCP Modules" page - placeholder for the plugin loader.

In v1.31 this is read-only: it lists the bundled Zabbix module and
describes what is coming soon. When the plugin loader lands the same view
extends to enable / disable / install / update buttons backed by the
``install.sh add-plugin / remove-plugin`` CLI subcommands.

Kept intentionally tiny here so the v1.31 cut surfaces the new
sidebar entry without committing to plugin-management UX yet.
"""

from __future__ import annotations

from starlette.requests import Request
from starlette.responses import RedirectResponse, Response


async def modules_list(request: Request) -> Response:
    """GET /modules - list installed MCP modules + coming-soon roadmap.

    Reads plugin manifests via :mod:`zabbix_mcp.plugin_loader` so the
    page reflects the live plugin inventory rather than a hardcoded
    list. Bundled and operator-installed plugins both show up.
    """
    admin_app = request.app.state.admin_app
    session = admin_app.require_auth(request)
    if not session:
        return RedirectResponse("/login", status_code=303)

    plugins: list[dict] = []
    try:
        from zabbix_mcp.plugin_loader import discover
        for record in discover():
            plugins.append({
                "id": record.id,
                "name": record.name,
                "version": record.version,
                "description": record.description,
                "author": record.author,
                "transport": record.transport,
                "tool_prefix": record.tool_prefix,
                "tool_groups": record.tool_groups,
                "report_templates": record.report_templates,
                "bundled": record.bundled,
                "manifest_path": str(record.manifest_path),
            })
    except Exception as exc:
        # Discovery failure must not 500 the modules page - the
        # operator should still see SOMETHING so they can navigate
        # back to a working admin view.
        logger = __import__("logging").getLogger("zabbix_mcp.admin")
        logger.exception("plugin discovery failed for /modules render: %s", exc)

    return admin_app.render("modules.html", request, {
        "active": "modules",
        "page_title": "MCP Modules",
        "plugins": plugins,
    })
