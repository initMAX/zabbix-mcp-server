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

"""External SIEM / syslog forwarder for the audit log.

Each audit row written by :func:`audit_writer.write_audit` /
:func:`write_tool_audit` is also enqueued here when forwarding is
enabled (``[audit.forward].enabled = true``). A background thread
drains the queue and ships rows over UDP / TCP / TLS in one of four
wire formats (RFC 5424, CEF, LEEF, JSON).

Design choices:

* **Local log is primary, forwarder is best-effort.** A drop /
  reconnect on the wire NEVER affects the local audit.log files. The
  forwarder maintains an in-memory queue and re-tries on its own
  schedule. If the queue fills up (SOC down for a long time), the
  OLDEST entries are dropped first - newer events matter more for
  incident review than week-old already-aged-out ones.

* **No external dependencies.** UDP / TCP / TLS sockets only, plus
  Python's ``ssl`` for TLS. No syslog-ng / rsyslog-style external
  helper - operators that need fancy filtering / aggregation can run
  their own pipeline in front of the SIEM.

* **Idempotent reconnect.** TCP / TLS connections drop on SOC restart,
  network blips, etc. The forwarder reconnects with exponential
  backoff (1s, 2s, 4s, 8s, ... capped at 60s) and keeps the queue
  drained while the connection is up.

* **Observability.** ``get_runtime_state()`` exposes the live queue
  depth, last-success timestamp, and last-error message so the admin
  UI can render a "forwarder healthy / lagging / disconnected"
  indicator without operators having to grep server logs.
"""

from __future__ import annotations

import json
import logging
import queue
import socket
import ssl
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("zabbix_mcp.admin.audit.forwarder")

# Hostname is needed for the syslog HOSTNAME field on every send. Fetch
# once at module load - if the hostname changes at runtime the operator
# can restart to pick it up.
_HOSTNAME = socket.gethostname() or "zabbix-mcp"
_APPNAME = "zabbix-mcp"
# Syslog facility 13 = log audit (RFC 5424 §6.2.1). Severity 5 = notice
# for allow rows; severity 4 = warning for deny rows. Composed PRI
# value is computed per-row from the ``policy_decision`` field.
_FACILITY_AUDIT = 13


# ----------------------------------------------------------------------
# Module-level runtime state
# ----------------------------------------------------------------------

_state_lock = threading.Lock()
_config: dict[str, Any] = {
    "enabled": False,
    "host": "",
    "port": 514,
    "protocol": "rfc5424_udp",
    "ca_cert": "",
    "queue_size": 10000,
}
_queue: queue.Queue[dict] | None = None
_thread: threading.Thread | None = None
_stop_event = threading.Event()
_runtime_stats: dict[str, Any] = {
    "last_success_at": None,         # ISO 8601
    "last_error": "",                # human-readable
    "last_error_at": None,           # ISO 8601
    "messages_sent": 0,
    "messages_dropped_queue_full": 0,
    "messages_failed": 0,
    "connection_state": "stopped",   # stopped / connecting / connected / disconnected
}
_recent_errors: deque[str] = deque(maxlen=10)


def configure(
    *,
    enabled: bool,
    host: str,
    port: int,
    protocol: str,
    ca_cert: str = "",
    queue_size: int = 10000,
) -> None:
    """Apply forwarder configuration. Called at boot and on Settings save.

    Re-creates the queue + restarts the forwarder thread when the
    configuration shape changes (queue size, host, port, protocol).
    Idempotent on identical configuration.
    """
    global _queue
    with _state_lock:
        prev = dict(_config)
        _config.update({
            "enabled": bool(enabled),
            "host": str(host or "").strip(),
            "port": int(port),
            "protocol": str(protocol or "rfc5424_udp").strip().lower(),
            "ca_cert": str(ca_cert or "").strip(),
            "queue_size": int(queue_size),
        })
        new = dict(_config)
        # Re-create the queue if size changed or on first configure.
        if _queue is None or prev.get("queue_size") != new["queue_size"]:
            _queue = queue.Queue(maxsize=new["queue_size"])
        # If host/port/protocol/CA changed, signal the worker to
        # disconnect on its next loop so it picks up the new config.
        config_changed = (
            prev.get("host") != new["host"]
            or prev.get("port") != new["port"]
            or prev.get("protocol") != new["protocol"]
            or prev.get("ca_cert") != new["ca_cert"]
        )
    if config_changed and is_running():
        logger.info("Audit forwarder destination changed - reconnecting")
        # Worker re-reads _config on each loop iteration, so just
        # nudging it to re-evaluate is enough; the explicit reconnect
        # happens inside _worker_loop.


def get_runtime_state() -> dict:
    """Snapshot the forwarder state for the admin UI."""
    with _state_lock:
        cfg = dict(_config)
        stats = dict(_runtime_stats)
        depth = _queue.qsize() if _queue is not None else 0
    return {
        "enabled": cfg["enabled"],
        "host": cfg["host"],
        "port": cfg["port"],
        "protocol": cfg["protocol"],
        "queue_depth": depth,
        "queue_size": cfg["queue_size"],
        "last_success_at": stats["last_success_at"],
        "last_error": stats["last_error"],
        "last_error_at": stats["last_error_at"],
        "messages_sent": stats["messages_sent"],
        "messages_dropped_queue_full": stats["messages_dropped_queue_full"],
        "messages_failed": stats["messages_failed"],
        "connection_state": stats["connection_state"],
    }


def is_running() -> bool:
    return _thread is not None and _thread.is_alive()


# ----------------------------------------------------------------------
# Public API: enqueue an audit row
# ----------------------------------------------------------------------


def enqueue(audit_row: dict) -> None:
    """Enqueue an audit row for forwarding (best-effort).

    Returns immediately. Never raises. When forwarding is disabled
    (config) or no queue has been created (forwarder never started),
    the call is a silent no-op.

    When the queue is full, the OLDEST entry is dropped to make room -
    record-side backpressure. A counter (``messages_dropped_queue_full``)
    is incremented so the admin UI surfaces "SOC is lagging" status.
    """
    if not _config.get("enabled"):
        return
    q = _queue
    if q is None:
        return
    try:
        q.put_nowait(audit_row)
    except queue.Full:
        # Drop oldest to make room.
        try:
            q.get_nowait()
        except queue.Empty:
            pass
        try:
            q.put_nowait(audit_row)
        except queue.Full:
            pass
        with _state_lock:
            _runtime_stats["messages_dropped_queue_full"] += 1


# ----------------------------------------------------------------------
# Worker thread
# ----------------------------------------------------------------------


def start() -> None:
    """Start the forwarder thread. Idempotent."""
    global _thread
    if is_running():
        return
    _stop_event.clear()
    t = threading.Thread(
        target=_worker_loop,
        name="audit-forwarder",
        daemon=True,
    )
    t.start()
    _thread = t


def stop() -> None:
    _stop_event.set()


def _set_connection_state(state: str, error: str | None = None) -> None:
    with _state_lock:
        _runtime_stats["connection_state"] = state
        if error:
            _runtime_stats["last_error"] = error
            _runtime_stats["last_error_at"] = datetime.now(timezone.utc).isoformat()
            _recent_errors.append(error)


def _record_success() -> None:
    with _state_lock:
        _runtime_stats["last_success_at"] = datetime.now(timezone.utc).isoformat()
        _runtime_stats["messages_sent"] += 1


def _record_failure(error: str) -> None:
    with _state_lock:
        _runtime_stats["messages_failed"] += 1
        _runtime_stats["last_error"] = error
        _runtime_stats["last_error_at"] = datetime.now(timezone.utc).isoformat()
        _recent_errors.append(error)


def _worker_loop() -> None:
    backoff = 1.0
    max_backoff = 60.0
    sock: socket.socket | None = None
    while not _stop_event.is_set():
        with _state_lock:
            cfg = dict(_config)
        if not cfg["enabled"]:
            _set_connection_state("stopped")
            time.sleep(2.0)
            continue
        if not cfg["host"]:
            _set_connection_state("disconnected", "Forwarder enabled but host is empty")
            time.sleep(5.0)
            continue
        # Establish (or re-establish) the connection. UDP is connectionless
        # so this is a one-shot getaddrinfo + bind; TCP / TLS need a real
        # connect.
        try:
            _set_connection_state("connecting")
            sock = _open_socket(cfg)
            _set_connection_state("connected")
            backoff = 1.0  # reset on success
        except Exception as e:
            _set_connection_state("disconnected", f"Connection failed: {e}")
            logger.warning("Audit forwarder connect failed: %s", e)
            _stop_event.wait(backoff)
            backoff = min(backoff * 2, max_backoff)
            continue
        # Drain queue while connection is healthy.
        q = _queue
        if q is None:
            time.sleep(2.0)
            continue
        try:
            while not _stop_event.is_set():
                try:
                    row = q.get(timeout=1.0)
                except queue.Empty:
                    # No work to do. Reload config to detect protocol/
                    # host changes mid-flight.
                    with _state_lock:
                        new_cfg = dict(_config)
                    if (new_cfg["host"] != cfg["host"]
                            or new_cfg["port"] != cfg["port"]
                            or new_cfg["protocol"] != cfg["protocol"]
                            or new_cfg["ca_cert"] != cfg["ca_cert"]
                            or not new_cfg["enabled"]):
                        break
                    continue
                try:
                    _send_one(sock, row, cfg)
                    _record_success()
                except (OSError, ssl.SSLError) as e:
                    _record_failure(f"Send failed: {e}")
                    logger.warning("Audit forwarder send failed: %s", e)
                    # Re-enqueue to retry on the next connection. Use
                    # put_nowait + drop-oldest semantics so we do not
                    # block the worker.
                    try:
                        q.put_nowait(row)
                    except queue.Full:
                        try:
                            q.get_nowait()
                            q.put_nowait(row)
                        except queue.Empty:
                            pass
                    break  # break to outer loop -> reconnect
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
                sock = None


def _open_socket(cfg: dict) -> socket.socket:
    """Create a connected socket per the configured protocol."""
    proto = cfg["protocol"]
    transport = proto.split("_")[-1]  # udp / tcp / tls
    host = cfg["host"]
    port = cfg["port"]
    if transport == "udp":
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # UDP "connect" sets the default peer; we still use sendall via send().
        s.connect((host, port))
        return s
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10.0)
    s.connect((host, port))
    if transport == "tls":
        ca_cert = cfg.get("ca_cert", "") or ""
        if ca_cert:
            ctx = ssl.create_default_context(cafile=ca_cert)
        else:
            ctx = ssl.create_default_context()
        # Strict server-side validation by default. Operators with
        # private CAs should set ca_cert to their bundle path.
        s = ctx.wrap_socket(s, server_hostname=host)
    s.settimeout(None)
    return s


def _send_one(sock: socket.socket, row: dict, cfg: dict) -> None:
    """Format ``row`` per the configured wire format and send it."""
    proto = cfg["protocol"]
    fmt = proto.split("_")[0]  # rfc5424 / cef / leef / json
    if fmt == "rfc5424":
        wire = _format_rfc5424(row)
    elif fmt == "cef":
        wire = _format_cef(row)
    elif fmt == "leef":
        wire = _format_leef(row)
    elif fmt == "json":
        wire = _format_json_line(row)
    else:
        raise ValueError(f"Unknown wire format: {proto}")
    transport = proto.split("_")[-1]
    payload = wire.encode("utf-8")
    if transport == "udp":
        # UDP datagrams are atomic up to MTU; truncation at ~1400 bytes
        # is the operator's problem. Most syslog daemons accept ~8 KB;
        # we cap at 8000 to stay safe across receivers.
        sock.send(payload[:8000])
        return
    # TCP / TLS: octet-counted framing per RFC 6587 §3.4.1 (length
    # prefix + space + message). Many SIEMs accept newline-delimited
    # too; octet-counted is the safer default.
    framed = f"{len(payload)} ".encode("ascii") + payload
    sock.sendall(framed)


# ----------------------------------------------------------------------
# Wire-format converters
# ----------------------------------------------------------------------


def _row_severity(row: dict) -> int:
    """Map a policy_decision to a syslog severity (RFC 5424 §6.2.1).

    allow / non-tool admin actions  -> 5 (notice)
    deny_*                          -> 4 (warning)
    error                           -> 3 (error)
    """
    decision = str(row.get("policy_decision") or row.get("action") or "").lower()
    if decision == "error":
        return 3
    if decision.startswith("deny_"):
        return 4
    return 5


def _format_rfc5424(row: dict) -> str:
    """RFC 5424 syslog message wrapping the audit row JSON.

    Format::

        <PRI>1 TIMESTAMP HOST APP PROCID MSGID STRUCTURED-DATA MSG

    The full audit row is embedded as the MSG (UTF-8 JSON) so a SIEM
    parser can both extract the structured fields (PRI / TIMESTAMP /
    HOST / APP) and pull the rich payload from MSG.
    """
    sev = _row_severity(row)
    pri = (_FACILITY_AUDIT * 8) + sev
    # ISO 8601 with millisecond precision per RFC 5424 §6.2.3.
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z"
    msgid = str(row.get("action") or row.get("tool_name") or "audit")[:32]
    msg = json.dumps(row, default=str, ensure_ascii=False)
    return f"<{pri}>1 {ts} {_HOSTNAME} {_APPNAME} - {msgid} - {msg}"


def _cef_escape(value: Any) -> str:
    """Escape CEF special chars per Common Event Format §3.5.

    Backslash, equals, and pipe must be escaped. Newlines drop to
    literal \\n so the receiver does not see a line break inside a
    field.
    """
    s = str(value) if value is not None else ""
    s = s.replace("\\", "\\\\").replace("|", "\\|").replace("=", "\\=")
    s = s.replace("\n", "\\n").replace("\r", "")
    return s


def _format_cef(row: dict) -> str:
    """ArcSight Common Event Format - prefix + key=value extension.

    CEF:0|Vendor|Product|Version|EventID|Name|Severity|Extension
    """
    sev = _row_severity(row)
    prefix = (
        f"CEF:0|initMAX|zabbix-mcp-server|1.31|"
        f"{_cef_escape(row.get('action') or row.get('tool_name') or 'audit')}|"
        f"{_cef_escape(row.get('policy_decision') or row.get('action') or 'audit')}|"
        f"{sev}|"
    )
    parts = []
    # Map common audit-row fields to CEF extension keys. Keys like
    # ``suser`` / ``src`` are CEF standard names that SIEM dashboards
    # already understand; everything else lands as cs1-cs6 custom
    # strings or as a JSON blob in the ``msg`` field.
    if row.get("oauth_subject"):
        parts.append(f"suser={_cef_escape(row['oauth_subject'])}")
    if row.get("ip"):
        parts.append(f"src={_cef_escape(row['ip'])}")
    if row.get("user"):
        parts.append(f"duser={_cef_escape(row['user'])}")
    if row.get("tool_name"):
        parts.append(f"act={_cef_escape(row['tool_name'])}")
    if row.get("mcp_session_id"):
        parts.append(f"externalId={_cef_escape(row['mcp_session_id'])}")
    if row.get("mapped_zabbix_user"):
        parts.append(f"cs1Label=mapped_zabbix_user")
        parts.append(f"cs1={_cef_escape(row['mapped_zabbix_user'])}")
    if row.get("scopes"):
        parts.append(f"cs2Label=scopes")
        parts.append(f"cs2={_cef_escape(','.join(row['scopes']))}")
    if row.get("denial_reason"):
        parts.append(f"reason={_cef_escape(row['denial_reason'])}")
    if row.get("result_count") is not None:
        parts.append(f"cn1Label=result_count")
        parts.append(f"cn1={_cef_escape(row['result_count'])}")
    # Full audit row as JSON in the msg field for full fidelity.
    parts.append(f"msg={_cef_escape(json.dumps(row, default=str, ensure_ascii=False))}")
    sev_pri = (_FACILITY_AUDIT * 8) + sev
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z"
    # CEF is typically wrapped in syslog framing too.
    return f"<{sev_pri}>1 {ts} {_HOSTNAME} {_APPNAME} - - - {prefix}{' '.join(parts)}"


def _leef_escape(value: Any) -> str:
    """LEEF allows nearly anything except the field separator (TAB by default)."""
    s = str(value) if value is not None else ""
    return s.replace("\t", " ").replace("\n", "\\n").replace("\r", "")


def _format_leef(row: dict) -> str:
    """IBM QRadar Log Event Extended Format."""
    sev = _row_severity(row)
    sev_pri = (_FACILITY_AUDIT * 8) + sev
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z"
    header = (
        "LEEF:2.0|initMAX|zabbix-mcp-server|1.31|"
        f"{_leef_escape(row.get('action') or row.get('tool_name') or 'audit')}|\t|"
    )
    fields = []
    fields.append(f"devTime={ts}")
    if row.get("oauth_subject"):
        fields.append(f"usrName={_leef_escape(row['oauth_subject'])}")
    if row.get("ip"):
        fields.append(f"src={_leef_escape(row['ip'])}")
    if row.get("tool_name"):
        fields.append(f"action={_leef_escape(row['tool_name'])}")
    if row.get("policy_decision"):
        fields.append(f"decision={_leef_escape(row['policy_decision'])}")
    if row.get("denial_reason"):
        fields.append(f"reason={_leef_escape(row['denial_reason'])}")
    if row.get("result_count") is not None:
        fields.append(f"resultCount={_leef_escape(row['result_count'])}")
    if row.get("mcp_session_id"):
        fields.append(f"sessionId={_leef_escape(row['mcp_session_id'])}")
    if row.get("mapped_zabbix_user"):
        fields.append(f"mappedUser={_leef_escape(row['mapped_zabbix_user'])}")
    fields.append(f"raw={_leef_escape(json.dumps(row, default=str, ensure_ascii=False))}")
    return f"<{sev_pri}>1 {ts} {_HOSTNAME} {_APPNAME} - - - {header}{chr(9).join(fields)}"


def _format_json_line(row: dict) -> str:
    """Newline-delimited JSON wrapped in syslog framing for ELK / Graylog."""
    sev = _row_severity(row)
    sev_pri = (_FACILITY_AUDIT * 8) + sev
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z"
    payload = json.dumps(row, default=str, ensure_ascii=False)
    return f"<{sev_pri}>1 {ts} {_HOSTNAME} {_APPNAME} - - - {payload}"
