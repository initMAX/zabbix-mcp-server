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

The four user-visible knobs from the Settings -> Audit log panel
(``enabled``, ``log_system_actions``, ``housekeeping_enabled``,
``data_storage_period``) are surfaced here as module-level runtime
state. The admin app calls :func:`configure` at boot and again on
every successful Settings save so a config reload takes effect
without restart. The Zabbix admin-panel UI is the source of truth.
"""

import gzip
import json
import logging
import os
import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from zabbix_mcp.admin.audit_redactor import redact

logger = logging.getLogger("zabbix_mcp.admin.audit")

AUDIT_LOG_PATH = Path("/var/log/zabbix-mcp/audit.log")

# Per-tool client-side audit log: a separate, more aggressively redacted
# stream that operators can hand to AI clients (Claude Desktop, ChatGPT,
# ...) for their own activity review without exposing infrastructure
# detail. Same JSONL format as the operator audit log, written alongside
# each operator-side ``tool.invoke`` row. Phase 5 of #49.
CLIENT_AUDIT_LOG_PATH = Path("/var/log/zabbix-mcp/client-audit.log")

MAX_AUDIT_SIZE = 50 * 1024 * 1024  # 50 MB - default, overridden by configure()

# ----------------------------------------------------------------------
# Runtime state for the four Settings -> Audit log knobs.
# configure() is called at boot from the admin app and again on every
# successful Settings save so a config reload takes effect without
# restart. Defaults match :class:`AuditConfig` in ``config.py``.
# ----------------------------------------------------------------------

_AUDIT_ENABLED: bool = True
_LOG_SYSTEM_ACTIONS: bool = False
_HOUSEKEEPING_ENABLED: bool = True
_RETENTION_SECONDS: int = 31 * 86400  # 31 days
_MAX_FILE_SIZE_BYTES: int = MAX_AUDIT_SIZE
_state_lock = threading.Lock()


def configure(
    *,
    enabled: bool = True,
    log_system_actions: bool = False,
    housekeeping_enabled: bool = True,
    retention_seconds: int = 31 * 86400,
    max_file_size_bytes: int = MAX_AUDIT_SIZE,
) -> None:
    """Apply the Settings -> Audit log knobs at runtime.

    Called once at boot (from the admin app, with values from
    :class:`AuditConfig`) and again on every successful Settings save.
    Idempotent - re-applying the same values is a no-op.
    """
    global _AUDIT_ENABLED, _LOG_SYSTEM_ACTIONS, _HOUSEKEEPING_ENABLED
    global _RETENTION_SECONDS, _MAX_FILE_SIZE_BYTES
    with _state_lock:
        _AUDIT_ENABLED = bool(enabled)
        _LOG_SYSTEM_ACTIONS = bool(log_system_actions)
        _HOUSEKEEPING_ENABLED = bool(housekeeping_enabled)
        _RETENTION_SECONDS = int(retention_seconds)
        _MAX_FILE_SIZE_BYTES = int(max_file_size_bytes)


def get_runtime_state() -> dict:
    """Snapshot the current audit-knob state for the admin UI."""
    with _state_lock:
        return {
            "enabled": _AUDIT_ENABLED,
            "log_system_actions": _LOG_SYSTEM_ACTIONS,
            "housekeeping_enabled": _HOUSEKEEPING_ENABLED,
            "retention_seconds": _RETENTION_SECONDS,
            "max_file_size_bytes": _MAX_FILE_SIZE_BYTES,
        }


# Action names that are ALWAYS audited regardless of the master toggle.
# Disabling audit is itself a compliance-relevant event - a reviewer
# must be able to see "audit was off between 14:00 and 15:30 by user
# alice" or the toggle becomes a stealth-mode footgun.
_ALWAYS_AUDIT_ACTIONS = frozenset({
    "audit.toggle",
    "audit.config_change",
})

# Action prefixes treated as "system actions". The
# ``log_system_actions`` toggle gates these. Default off so the
# operator log stays focused on user-driven actions.
_SYSTEM_ACTION_PREFIXES = (
    "system.",
    "housekeeping.",
    "forwarder.",
    "retention.",
    "background.",
)


def _is_system_action(action: str) -> bool:
    return any(action.startswith(p) for p in _SYSTEM_ACTION_PREFIXES)


def _enqueue_forward(entry: dict) -> None:
    """Best-effort hand-off to the SIEM forwarder. Silent on any failure.

    Imported lazily so a build that strips audit_forwarder.py (or an
    older venv missing the module) still boots.
    """
    try:
        from zabbix_mcp.admin import audit_forwarder
        audit_forwarder.enqueue(entry)
    except Exception:
        pass


def _should_emit(action: str) -> bool:
    """Apply the audit master + system-action gates."""
    if action in _ALWAYS_AUDIT_ACTIONS:
        return True
    if not _AUDIT_ENABLED:
        return False
    if _is_system_action(action) and not _LOG_SYSTEM_ACTIONS:
        return False
    return True

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


# Pattern of dated rotation files generated by housekeeping. Living
# alongside the legacy ``audit.log.1`` / ``audit.log.2`` naming so
# operators upgrading from v1.30 do not lose history during the
# rollover.
_DATED_SUFFIX_RE = "{name}.{date}.gz"


def _today_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _rotate_to_dated(path: Path) -> Path | None:
    """Rotate ``audit.log`` -> ``audit.log.YYYY-MM-DD.gz`` (gzipped).

    Returns the path of the rotated archive, or None when there was
    nothing to rotate (file missing or empty). Idempotent on the same
    day - if today's archive already exists, the contents are appended
    to it (gzip member concatenation is valid gzip).
    """
    if not path.exists() or path.stat().st_size == 0:
        return None
    archive = path.parent / f"{path.name}.{_today_iso()}.gz"
    try:
        # gzip in append-friendly binary mode. Concatenated gzip files
        # are valid gzip per RFC 1952 §2.2 - reading is transparent.
        with open(path, "rb") as src, gzip.open(archive, "ab") as dst:
            for chunk in iter(lambda: src.read(64 * 1024), b""):
                dst.write(chunk)
        # Truncate the live file in place so concurrent writers keep
        # writing into the new (empty) file without re-opening.
        with open(path, "w", encoding="utf-8") as f:
            f.truncate(0)
    except OSError as e:
        logger.warning("Audit rotation failed for %s: %s", path, e)
        return None
    return archive


def _purge_old_archives(path: Path, retention_seconds: int) -> tuple[int, int]:
    """Delete dated archives older than ``retention_seconds``.

    Returns ``(files_purged, bytes_freed)``. Only touches files whose
    name matches the dated archive pattern - the live ``audit.log``
    file and the legacy ``.1`` / ``.2`` rotation backups are left
    alone. ``retention_seconds <= 0`` short-circuits with 0 / 0
    (time-based purge disabled).
    """
    if retention_seconds <= 0:
        return (0, 0)
    cutoff = time.time() - retention_seconds
    purged = 0
    bytes_freed = 0
    base = path.name
    parent = path.parent
    if not parent.exists():
        return (0, 0)
    for entry in parent.iterdir():
        n = entry.name
        if not n.startswith(base + ".") or not n.endswith(".gz"):
            continue
        # Expected: <base>.YYYY-MM-DD.gz - skip anything else.
        try:
            date_part = n[len(base) + 1 : -3]  # strip prefix + ".gz"
            datetime.strptime(date_part, "%Y-%m-%d")
        except (ValueError, IndexError):
            continue
        try:
            mtime = entry.stat().st_mtime
            size = entry.stat().st_size
        except OSError:
            continue
        if mtime < cutoff:
            try:
                entry.unlink()
                purged += 1
                bytes_freed += size
            except OSError as e:
                logger.warning("Audit purge failed for %s: %s", entry, e)
    return (purged, bytes_freed)


# Background housekeeping daemon - one thread for both audit + client
# audit logs. Spawned by start_housekeeping(); idempotent so a config
# reload that re-applies the same toggle is a no-op.
_housekeeping_thread: threading.Thread | None = None
_housekeeping_stop = threading.Event()
_HOUSEKEEPING_TICK_SECONDS = 60.0
_last_rotation_date: dict[str, str] = {}


def _housekeeping_cycle() -> None:
    """One pass of: rotate-on-size, rotate-on-day, purge-by-age."""
    paths = [AUDIT_LOG_PATH, CLIENT_AUDIT_LOG_PATH]
    today = _today_iso()
    with _state_lock:
        max_size = _MAX_FILE_SIZE_BYTES
        retention = _RETENTION_SECONDS
        active = _HOUSEKEEPING_ENABLED
    if not active:
        return
    archives_made = 0
    purged_total = 0
    bytes_freed_total = 0
    for p in paths:
        if not p.parent.exists():
            continue
        # Size-based rotation.
        try:
            if p.exists() and p.stat().st_size > max_size:
                if _rotate_to_dated(p):
                    archives_made += 1
        except OSError:
            pass
        # Daily rotation: if file has any content and we have not
        # rotated today yet, archive it under today's date.
        last = _last_rotation_date.get(str(p))
        if last != today:
            try:
                if p.exists() and p.stat().st_size > 0:
                    if _rotate_to_dated(p):
                        archives_made += 1
            except OSError:
                pass
            _last_rotation_date[str(p)] = today
        # Age-based purge.
        purged, freed = _purge_old_archives(p, retention)
        purged_total += purged
        bytes_freed_total += freed
    if (archives_made or purged_total) and _LOG_SYSTEM_ACTIONS:
        # Self-event so an operator can see the housekeeping running.
        _bypass_audit(
            action="housekeeping.cycle",
            details={
                "archives_made": archives_made,
                "files_purged": purged_total,
                "bytes_freed": bytes_freed_total,
            },
        )


def _bypass_audit(action: str, details: dict) -> None:
    """Write a system-action audit row directly, bypassing the gate.

    Used by the housekeeping daemon to record its own activity when
    ``log_system_actions`` is on. Bypasses :func:`_should_emit` so
    we do not recurse on the system-action toggle.
    """
    entry = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "action": action,
        "user": "system",
        "target_type": "",
        "target_id": "",
        "details": redact(details or {}),
        "ip": "",
    }
    try:
        AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass


def _housekeeping_loop() -> None:
    while not _housekeeping_stop.is_set():
        try:
            _housekeeping_cycle()
        except Exception:
            logger.exception("Audit housekeeping cycle failed")
        # Wait with timeout so the thread reacts to stop within the tick.
        _housekeeping_stop.wait(_HOUSEKEEPING_TICK_SECONDS)


def start_housekeeping() -> None:
    """Idempotent: launch the housekeeping daemon if not already running."""
    global _housekeeping_thread
    if _housekeeping_thread is not None and _housekeeping_thread.is_alive():
        return
    _housekeeping_stop.clear()
    t = threading.Thread(
        target=_housekeeping_loop,
        name="audit-housekeeping",
        daemon=True,
    )
    t.start()
    _housekeeping_thread = t


def stop_housekeeping() -> None:
    """Stop the housekeeping daemon (used by tests + graceful shutdown)."""
    _housekeeping_stop.set()


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

    Honours the master ``[audit].enabled`` toggle and the
    ``log_system_actions`` sub-toggle (see :func:`_should_emit`).
    Toggle-change events themselves are always recorded so a reviewer
    can see when audit logging was disabled.
    """
    if not _should_emit(action):
        return
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
        if AUDIT_LOG_PATH.exists() and AUDIT_LOG_PATH.stat().st_size > _MAX_FILE_SIZE_BYTES:
            try:
                _rotate_audit_log(AUDIT_LOG_PATH)
            except OSError:
                pass
        with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        import logging
        logging.getLogger("zabbix_mcp.admin").warning("Failed to write audit log: %s", e)
    # Best-effort SIEM / syslog ship after the local-log write succeeded
    # (or failed - the forwarder is independent).
    _enqueue_forward(entry)


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

    Honours the master ``[audit].enabled`` toggle. When audit is off
    the function returns silently without writing to either stream.
    """
    if not _AUDIT_ENABLED:
        return
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
        if AUDIT_LOG_PATH.exists() and AUDIT_LOG_PATH.stat().st_size > _MAX_FILE_SIZE_BYTES:
            try:
                _rotate_audit_log(AUDIT_LOG_PATH)
            except OSError:
                pass
        with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(operator_entry) + "\n")
    except Exception as e:
        import logging
        logging.getLogger("zabbix_mcp.admin").warning("Failed to write tool audit: %s", e)
    # Best-effort SIEM / syslog ship of the operator-side row. The
    # client-stream copy is intentionally not forwarded (it carries
    # less context and is for the AI client's self-review only).
    _enqueue_forward(operator_entry)

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
            if CLIENT_AUDIT_LOG_PATH.exists() and CLIENT_AUDIT_LOG_PATH.stat().st_size > _MAX_FILE_SIZE_BYTES:
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
