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


_SORT_KEYS = {
    "timestamp": ("timestamp", ""),
    "action": ("action", ""),
    "user": ("user", ""),
    "target": ("target_id", ""),
    "ip": ("ip", ""),
}


def _read_audit_entries(
    limit: int = 200,
    offset: int = 0,
    action_filter: str | None = None,
    search: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    sort_by: str = "timestamp",
    sort_order: str = "desc",
    tool_filter: str | None = None,
    decision_filter: str | None = None,
    subject_filter: str | None = None,
) -> tuple[list[dict], int]:
    """Read audit log entries with filtering, sorting, pagination.

    Returns ``(entries, total_after_filter)``. Total count is what the
    UI uses to decide whether to show "Load more". Sort defaults to
    newest first because that's what an operator wants 95% of the
    time.

    The three issue-#49-specific filters (tool / decision / subject)
    target ``tool.invoke`` rows: when set they implicitly narrow the
    result to per-tool audit entries, so the filter bar shows only the
    rows an incident reviewer cares about. ``subject_filter`` is a
    case-insensitive substring match against ``oauth_subject`` (or
    ``user`` for admin events).
    """
    if not AUDIT_LOG_PATH.exists():
        return [], 0

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
                    if tool_filter and entry.get("tool_name", "") != tool_filter:
                        continue
                    if decision_filter and entry.get("policy_decision", "") != decision_filter:
                        continue
                    if subject_filter:
                        subj = (entry.get("oauth_subject") or entry.get("user") or "").lower()
                        if subject_filter.lower() not in subj:
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

    field, default = _SORT_KEYS.get(sort_by, _SORT_KEYS["timestamp"])
    reverse = sort_order != "asc"
    entries.sort(key=lambda e: e.get(field, default) or default, reverse=reverse)
    total = len(entries)
    return entries[offset:offset + limit], total


async def audit_view(request: Request) -> Response:
    admin_app = request.app.state.admin_app
    session = admin_app.require_auth(request)
    if not session:
        return RedirectResponse("/login", status_code=303)

    action_filter = request.query_params.get("action")
    try:
        limit = min(int(request.query_params.get("limit", "50")), 10000)
    except (ValueError, TypeError):
        limit = 50
    try:
        offset = max(int(request.query_params.get("offset", "0")), 0)
    except (ValueError, TypeError):
        offset = 0
    search = request.query_params.get("search")
    date_from = request.query_params.get("date_from")
    date_to = request.query_params.get("date_to")
    sort_by = request.query_params.get("sort", "timestamp")
    sort_order = request.query_params.get("order", "desc")
    if sort_by not in _SORT_KEYS:
        sort_by = "timestamp"
    if sort_order not in ("asc", "desc"):
        sort_order = "desc"
    tool_filter = request.query_params.get("tool")
    decision_filter = request.query_params.get("decision")
    subject_filter = request.query_params.get("subject")

    entries, total = _read_audit_entries(
        limit=limit, offset=offset,
        action_filter=action_filter, search=search,
        date_from=date_from, date_to=date_to,
        sort_by=sort_by, sort_order=sort_order,
        tool_filter=tool_filter, decision_filter=decision_filter,
        subject_filter=subject_filter,
    )

    # Collect unique action types + tool names for the filter dropdowns.
    # One file scan instead of two (the previous duplicate read for
    # action_types was wasteful on a busy log).
    action_types: set[str] = set()
    tool_names: set[str] = set()
    decision_types: set[str] = set()
    if AUDIT_LOG_PATH.exists():
        try:
            with open(AUDIT_LOG_PATH, "r") as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                    except (json.JSONDecodeError, KeyError):
                        continue
                    action_types.add(entry.get("action", ""))
                    if entry.get("action") == "tool.invoke":
                        if entry.get("tool_name"):
                            tool_names.add(entry["tool_name"])
                        if entry.get("policy_decision"):
                            decision_types.add(entry["policy_decision"])
        except Exception:
            pass

    ctx = {
        "active": "audit",
        "entries": entries,
        "total_entries": total,
        "offset": offset,
        "limit": limit,
        "next_offset": offset + limit if (offset + limit) < total else None,
        "has_more": (offset + limit) < total,
        "sort_by": sort_by,
        "sort_order": sort_order,
        "action_types": sorted(action_types),
        "tool_names": sorted(tool_names),
        "decision_types": sorted(decision_types),
        "current_filter": action_filter,
        "filters": {
            "date_from": request.query_params.get("date_from", ""),
            "date_to": request.query_params.get("date_to", ""),
            "action": action_filter or "",
            "search": request.query_params.get("search", ""),
            "tool": tool_filter or "",
            "decision": decision_filter or "",
            "subject": subject_filter or "",
        },
    }
    # When called via htmx (filter / sort change / load more), return
    # only the table partial so it can be swapped into #audit-table
    # without nesting the entire page inside itself - reported
    # 2026-04-17 with screenshots showing the page rendered twice.
    is_htmx = request.headers.get("HX-Request") == "true"
    template = "audit_table_partial.html" if is_htmx else "audit.html"
    return admin_app.render(template, request, ctx)


async def audit_export(request: Request) -> Response:
    """Export audit log as CSV."""
    admin_app = request.app.state.admin_app
    session = admin_app.require_auth(request)
    if not session:
        return RedirectResponse("/login", status_code=303)

    entries, _ = _read_audit_entries(limit=10000)

    output = io.StringIO()
    # QUOTE_ALL is mandatory because details fields can contain
    # commas, quotes, and newlines that would otherwise produce
    # invalid CSV. csv.writer handles the escaping automatically
    # (doubles internal quotes, wraps every field in quotes).
    writer = csv.writer(output, quoting=csv.QUOTE_ALL, lineterminator="\n")
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
