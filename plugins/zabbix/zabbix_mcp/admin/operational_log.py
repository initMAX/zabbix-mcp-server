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

"""Operational log - service lifecycle + debug events.

Separate from the compliance audit log (``/var/log/zabbix-mcp/audit.log``)
on purpose:

* **audit.log** is the compliance trail. Stable schema, redaction
  rules, retention, signed by the housekeeping daemon, shippable to
  SIEM. An auditor reads this; nothing else has access.
* **mcp.log** (this file) is the operational debug log. Loose schema,
  operator-friendly grep targets. SREs read this when they ask "is
  the OAuth flow stuck on /token?" or "which tool took 12 seconds?".

Both files are JSON Lines so an operator can drive `jq` over them,
but they serve different audiences.

Design choices:

- **Schema-light**: ``write_event(event_type, **fields)`` - the caller
  decides what fields are useful, no fixed column set. This matches
  how operational logs are actually grepped in practice.
- **No redaction here**: this log captures debug detail. If the
  operator wants secrets out, they should not call ``write_event``
  with secret fields. The compliance audit log handles redaction.
- **Best-effort**: every write is wrapped in try/except. A full disk
  must not crash the request path.
- **Same rotation policy** as the audit log (50 MB threshold, 2
  backups). Daily rotation lives in the housekeeping daemon when
  ``[operational_log].housekeeping_enabled`` is on.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger("zabbix_mcp.admin.ops")

OPS_LOG_PATH = Path("/var/log/zabbix-mcp/mcp.log")
MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB

_state_lock = threading.Lock()
_write_lock = threading.Lock()
_enabled: bool = True
_path: Path = OPS_LOG_PATH


def configure(*, enabled: bool = True, path: str | Path | None = None) -> None:
    """Apply operational log knobs at runtime. Called from admin app boot."""
    global _enabled, _path
    with _state_lock:
        _enabled = bool(enabled)
        if path:
            _path = Path(path)


def get_runtime_state() -> dict:
    with _state_lock:
        return {"enabled": _enabled, "path": str(_path)}


def _rotate(p: Path) -> None:
    """Simple two-backup rotation, mirrors audit_writer."""
    backup = p.with_suffix(p.suffix + ".1")
    old = p.with_suffix(p.suffix + ".2")
    try:
        if old.exists():
            old.unlink()
        if backup.exists():
            backup.rename(old)
        p.rename(backup)
    except OSError:
        pass


def write_event(event: str, **fields: Any) -> None:
    """Append a single operational-log entry as a JSON line.

    Returns silently when the operational log is disabled or any I/O
    error occurs. The caller never has to remember to wrap in
    try/except - the operational log is best-effort by contract.
    """
    if not _enabled:
        return
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event,
        **fields,
    }
    try:
        _path.parent.mkdir(parents=True, exist_ok=True)
        try:
            if _path.exists() and _path.stat().st_size > MAX_FILE_SIZE_BYTES:
                _rotate(_path)
        except OSError:
            pass
        with _write_lock:
            with open(_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, default=str, ensure_ascii=False) + "\n")
    except Exception as exc:
        # Do NOT propagate - operational log failure must not break
        # the request path. Log the failure to the Python logger so
        # a misconfigured path surfaces in journalctl rather than
        # silently disappearing.
        logger.warning("Operational log write failed for event=%s: %s", event, exc)


# ----------------------------------------------------------------------
# Convenience helpers - the few event names the rest of the codebase
# emits frequently. Sugar over write_event() for grep-friendly call
# sites and to keep the event names consistent across modules.
# ----------------------------------------------------------------------


def service_start(version: str, transport: str, host: str, port: int, pid: int | None = None) -> None:
    write_event(
        "service.start",
        version=version, transport=transport, host=host, port=port,
        pid=pid,
    )


def service_shutdown(reason: str = "sigterm") -> None:
    write_event("service.shutdown", reason=reason)


def tool_call(
    tool_name: str,
    duration_seconds: float,
    decision: str,
    *,
    oauth_subject: str | None = None,
    result_size: int | None = None,
    error: str | None = None,
) -> None:
    """Operational view of a single MCP tool call.

    Counterpart to the compliance ``tool.invoke`` audit row - the audit
    row carries who/what/decision and is bounded; this row carries
    timings and result-size for performance debugging.
    """
    fields: dict[str, Any] = {
        "tool": tool_name,
        "duration_ms": int(duration_seconds * 1000),
        "decision": decision,
    }
    if oauth_subject:
        fields["oauth_subject"] = oauth_subject
    if result_size is not None:
        fields["result_size_bytes"] = result_size
    if error:
        fields["error"] = error
    write_event("tool.call", **fields)


def error_uncaught(where: str, exc_type: str, exc_message: str, stack: str | None = None) -> None:
    fields: dict[str, Any] = {
        "where": where,
        "exc_type": exc_type,
        "exc_message": exc_message,
    }
    if stack:
        fields["stack"] = stack
    write_event("error.uncaught", **fields)


def oauth_event(stage: str, **fields: Any) -> None:
    """OAuth flow stages: authorize_request / token_request / refresh /
    revoke / register / consent_granted. Stage is the verb."""
    write_event(f"oauth.{stage}", **fields)


def forwarder_event(stage: str, **fields: Any) -> None:
    """Audit forwarder lifecycle: connect_attempt / connected /
    disconnected / send_failure / queue_full."""
    write_event(f"forwarder.{stage}", **fields)
