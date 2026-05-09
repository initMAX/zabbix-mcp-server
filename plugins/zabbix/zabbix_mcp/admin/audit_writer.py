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

"""Audit log writer - appends JSON entries to the audit log file.

Every payload routes through :mod:`zabbix_mcp.admin.audit_redactor` at
this boundary so call sites do not have to remember to scrub secrets.
The denylist is centralised; adding a new sensitive key is one edit in
``audit_redactor.py``.
"""

import json
import os
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any, Iterable

from zabbix_mcp.admin.audit_redactor import redact

AUDIT_LOG_PATH = Path("/var/log/zabbix-mcp/audit.log")

# Per-tool client-side audit log: a separate, more aggressively redacted
# stream that operators can hand to AI clients (Claude Desktop, ChatGPT,
# ...) for their own activity review without exposing infrastructure
# detail. Same JSONL format as the operator audit log, written alongside
# each operator-side ``tool.invoke`` row. Phase 5 of #49.
CLIENT_AUDIT_LOG_PATH = Path("/var/log/zabbix-mcp/client-audit.log")

MAX_AUDIT_SIZE = 50 * 1024 * 1024  # 50 MB

# Per-subject ring buffer of recent client-side audit rows. Backs the
# ``audit_self_get`` MCP tool (issue #49 Phase 5): a client can pull
# its own recent activity without the operator handing them the raw
# log file (which would carry every other client's activity too).
#
# Keyed by ``oauth_subject`` rather than client_id so OAuth + bearer
# tokens use the same path. Per-subject deques are bounded so a
# misbehaving client cannot grow the process RSS unboundedly.
_PER_SUBJECT_RING_MAX = 100
_per_subject_audit: dict[str, deque[dict[str, Any]]] = {}
_per_subject_audit_lock = threading.Lock()


def get_recent_client_audit(oauth_subject: str, limit: int = 50) -> list[dict[str, Any]]:
    """Return up to ``limit`` most recent client-audit rows for a subject.

    Used by ``audit_self_get`` to surface a client's own activity. The
    ring buffer is in-memory only - it is reset on process restart and
    bounded at :data:`_PER_SUBJECT_RING_MAX` entries per subject. A
    client that wants longer history asks the operator for the audit
    log directly.

    Returns newest-first. Empty list when no rows are recorded for
    ``oauth_subject`` yet.
    """
    if not oauth_subject:
        return []
    with _per_subject_audit_lock:
        ring = _per_subject_audit.get(oauth_subject)
        if not ring:
            return []
        # deque iter is oldest-first; reverse + cap at limit.
        items = list(ring)[-limit:]
    items.reverse()
    return items


def _push_client_ring(oauth_subject: str, entry: dict[str, Any]) -> None:
    """Append a client-audit entry to the per-subject ring buffer."""
    if not oauth_subject:
        return
    with _per_subject_audit_lock:
        ring = _per_subject_audit.get(oauth_subject)
        if ring is None:
            ring = deque(maxlen=_PER_SUBJECT_RING_MAX)
            _per_subject_audit[oauth_subject] = ring
        ring.append(entry)


def _rotate_audit_log(path: Path) -> None:
    """Simple audit log rotation."""
    backup = str(path) + ".1"
    old_backup = str(path) + ".2"
    if os.path.exists(old_backup):
        os.unlink(old_backup)
    if os.path.exists(backup):
        os.rename(backup, old_backup)
    os.rename(str(path), backup)


def write_audit(
    action: str,
    user: str = "",
    target_type: str = "",
    target_id: str = "",
    details: dict | None = None,
    ip: str = "",
) -> None:
    """Append a single audit entry as a JSON line.

    Sensitive fields in ``details`` are redacted at this boundary - see
    :mod:`zabbix_mcp.admin.audit_redactor` for the denylist.
    """
    safe_details = redact(details or {})
    entry = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "action": action,
        "user": user,
        "target_type": target_type,
        "target_id": target_id,
        "details": safe_details,
        "ip": ip,
    }
    try:
        AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        if AUDIT_LOG_PATH.exists() and AUDIT_LOG_PATH.stat().st_size > MAX_AUDIT_SIZE:
            try:
                _rotate_audit_log(AUDIT_LOG_PATH)
            except OSError:
                pass
        with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        import logging
        logging.getLogger("zabbix_mcp.admin").warning("Failed to write audit log: %s", e)


def write_tool_audit(
    *,
    oauth_subject: str,
    mapped_zabbix_user: str | None,
    mcp_session_id: str | None,
    tool_name: str,
    scopes: list[str],
    policy_decision: str,
    denial_reason: str | None,
    target: dict | None,
    filters: dict | None,
    result_count: int | str | None,
    ip: str = "",
    also_client: bool = True,
) -> None:
    """Append a per-tool-call audit row (Phase 1 of #49).

    Stable schema (per reviewer @musaabhasan): common fields are fixed,
    resource-specific values live in bounded ``target`` and ``filters``
    objects so the log stays grep-friendly across tools.

    For denied requests, the ``target`` and ``filters`` objects carry
    only resource references (host_id / hostgroup_id / item_id /
    severities / active_only flags) - never the raw kwargs. Redaction
    inside ``write_audit`` is a defence-in-depth second pass: the
    primary scrubbing happens in :mod:`audit_extractors.extract` before
    this function is called.

    When ``also_client`` is True (default), a redacted-twice copy is
    appended to the client-side audit log too (Phase 5). The client log
    drops the operator-only fields (``mapped_zabbix_user``, ``ip``,
    full ``denial_reason``) and keeps just the AI-client perspective:
    what tool was called, with what scope, was it allowed, how many
    results came back.
    """
    safe_target = redact(target or {})
    safe_filters = redact(filters or {})
    operator_entry = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "action": "tool.invoke",
        "oauth_subject": oauth_subject,
        "mapped_zabbix_user": mapped_zabbix_user,
        "mcp_session_id": mcp_session_id,
        "tool_name": tool_name,
        "scopes": list(scopes or []),
        "policy_decision": policy_decision,
        "denial_reason": denial_reason,
        "target": safe_target,
        "filters": safe_filters,
        "result_count": result_count,
        "ip": ip,
    }
    try:
        AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        if AUDIT_LOG_PATH.exists() and AUDIT_LOG_PATH.stat().st_size > MAX_AUDIT_SIZE:
            try:
                _rotate_audit_log(AUDIT_LOG_PATH)
            except OSError:
                pass
        with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(operator_entry) + "\n")
    except Exception as e:
        import logging
        logging.getLogger("zabbix_mcp.admin").warning("Failed to write tool audit: %s", e)

    if also_client:
        client_entry = {
            "timestamp": operator_entry["timestamp"],
            "tool": tool_name,
            "decision": policy_decision,
            # Drop full denial_reason on the client side - it can leak
            # operator-side detail (token names, scope strings). Just
            # the bucket category so the AI-client can show "denied
            # (scope)" without exposing the operator's policy text.
            "denial_bucket": _denial_bucket(policy_decision, denial_reason),
            "result_count": result_count,
            # Target is a resource reference (numeric id / name). Safe
            # to surface on the client side - the client already passed
            # these IDs to the tool.
            "target": safe_target,
        }
        # Push to the per-subject ring buffer first - audit_self_get
        # reads from this in-memory store. The file write below is for
        # operators (separate, longer retention) and may fail without
        # affecting the in-memory path.
        _push_client_ring(oauth_subject, client_entry)
        try:
            CLIENT_AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
            if CLIENT_AUDIT_LOG_PATH.exists() and CLIENT_AUDIT_LOG_PATH.stat().st_size > MAX_AUDIT_SIZE:
                try:
                    _rotate_audit_log(CLIENT_AUDIT_LOG_PATH)
                except OSError:
                    pass
            with open(CLIENT_AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps(client_entry) + "\n")
        except Exception as e:
            import logging
            logging.getLogger("zabbix_mcp.admin").warning("Failed to write client audit: %s", e)


_DENIAL_BUCKETS = {
    "deny_scope": "scope",
    "deny_read_only": "read_only",
    "deny_token_invalid": "auth",
    "deny_token_expired": "auth",
    "deny_server": "server",
    "deny_ip": "auth",
}


def _denial_bucket(policy_decision: str, denial_reason: str | None) -> str | None:
    """Map operator-side ``policy_decision`` to a client-friendly bucket.

    Operator log carries the full reason; the client log just gets the
    high-level category so we don't leak token names or scope strings
    via the client-facing log.
    """
    if policy_decision == "allow":
        return None
    return _DENIAL_BUCKETS.get(policy_decision, "other")
