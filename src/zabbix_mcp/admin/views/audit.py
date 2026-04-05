#
# Zabbix MCP Server
# Copyright (C) 2026 initMAX s.r.o.
#

"""Audit log viewer + CSV export."""

from __future__ import annotations

import csv
import io
import json
import logging
from pathlib import Path

from starlette.requests import Request
from starlette.responses import RedirectResponse, Response, StreamingResponse

logger = logging.getLogger("zabbix_mcp.admin")

AUDIT_LOG_PATH = Path("/var/log/zabbix-mcp/audit.log")


def _read_audit_entries(limit: int = 200, action_filter: str | None = None, search: str | None = None, date_from: str | None = None, date_to: str | None = None) -> list[dict]:
    """Read audit log entries (newest first)."""
    if not AUDIT_LOG_PATH.exists():
        return []

    entries = []
    try:
        with open(AUDIT_LOG_PATH, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    if action_filter and entry.get("action", "") != action_filter:
                        continue
                    if search and search.lower() not in json.dumps(entry).lower():
                        continue
                    if date_from and entry.get("timestamp", "") < date_from:
                        continue
                    if date_to and entry.get("timestamp", "") > date_to + " 23:59:59":
                        continue
                    entries.append(entry)
                except json.JSONDecodeError:
                    continue
    except Exception as e:
        logger.error("Failed to read audit log: %s", e)

    # Newest first
    entries.reverse()
    return entries[:limit]


async def audit_view(request: Request) -> Response:
    admin_app = request.app.state.admin_app
    session = admin_app.require_auth(request)
    if not session:
        return RedirectResponse("/login", status_code=303)

    action_filter = request.query_params.get("action")
    try:
        limit = min(int(request.query_params.get("limit", "200")), 10000)
    except (ValueError, TypeError):
        limit = 200
    search = request.query_params.get("search")
    date_from = request.query_params.get("date_from")
    date_to = request.query_params.get("date_to")

    entries = _read_audit_entries(limit=limit, action_filter=action_filter, search=search, date_from=date_from, date_to=date_to)

    # Collect unique action types for filter dropdown
    action_types = set()
    if AUDIT_LOG_PATH.exists():
        try:
            with open(AUDIT_LOG_PATH, "r") as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        action_types.add(entry.get("action", ""))
                    except (json.JSONDecodeError, KeyError):
                        pass
        except Exception:
            pass

    return admin_app.render("audit.html", request, {
        "active": "audit",
        "entries": entries,
        "action_types": sorted(action_types),
        "current_filter": action_filter,
        "filters": {
            "date_from": request.query_params.get("date_from", ""),
            "date_to": request.query_params.get("date_to", ""),
            "action": action_filter or "",
            "search": request.query_params.get("search", ""),
        },
    })


async def audit_export(request: Request) -> Response:
    """Export audit log as CSV."""
    admin_app = request.app.state.admin_app
    session = admin_app.require_auth(request)
    if not session:
        return RedirectResponse("/login", status_code=303)

    entries = _read_audit_entries(limit=10000)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Timestamp", "Action", "User", "Target Type", "Target ID", "Details", "IP"])

    for entry in entries:
        writer.writerow([
            entry.get("timestamp", ""),
            entry.get("action", ""),
            entry.get("user", ""),
            entry.get("target_type", ""),
            entry.get("target_id", ""),
            json.dumps(entry.get("details", {})) if entry.get("details") else "",
            entry.get("ip", ""),
        ])

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=audit_log.csv"},
    )
