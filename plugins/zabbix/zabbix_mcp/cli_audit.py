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

"""CLI helpers for the audit log (issue #49 acceptance criteria).

Three subcommands:

* ``grep`` - filter rows by user / tool / decision / action / target /
  timestamp window. Output as table (default), JSON, or CSV.
* ``tail`` - show the last N rows, optionally as JSON.
* ``stats`` - decision / top-tool / top-subject / top-action aggregates
  for incident-review and capacity-planning summaries.

All three operate on the operator log at
``/var/log/zabbix-mcp/audit.log`` by default; ``--include-archives``
also scans the dated ``audit.log.YYYY-MM-DD.gz`` rotation files.

Usage examples::

    zabbix-mcp-server audit grep --user alice
    zabbix-mcp-server audit grep --tool host_get --decision allow --limit 50
    zabbix-mcp-server audit grep --decision deny_scope --since 2026-05-01 --format=json
    zabbix-mcp-server audit grep --target hostid:10084 --include-archives
    zabbix-mcp-server audit tail -n 100 --format=json
    zabbix-mcp-server audit stats --since 2026-05-01 --top 20
"""

from __future__ import annotations

import argparse
import csv
import gzip
import json
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator

DEFAULT_AUDIT_LOG = Path("/var/log/zabbix-mcp/audit.log")


# ----------------------------------------------------------------------
# Common helpers
# ----------------------------------------------------------------------


def _iter_log_lines(log_path: str | Path, include_archives: bool = False) -> Iterator[dict]:
    """Yield decoded audit rows from ``log_path`` (and optional archives)."""
    p = Path(log_path)
    files: list[Path] = []
    if include_archives:
        for entry in sorted(p.parent.glob(f"{p.name}.*.gz")):
            files.append(entry)
    files.append(p)
    for fp in files:
        if not fp.exists():
            continue
        try:
            if fp.suffix == ".gz":
                f = gzip.open(fp, "rt", encoding="utf-8", errors="replace")
            else:
                f = open(fp, "r", encoding="utf-8", errors="replace")
        except OSError as e:
            print(f"warning: cannot open {fp}: {e}", file=sys.stderr)
            continue
        with f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue


def _parse_ts(s: str | None) -> datetime | None:
    """Parse ``YYYY-MM-DD`` or ``YYYY-MM-DD HH:MM:SS`` into a datetime."""
    if not s:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    raise ValueError(f"Invalid timestamp {s!r}; expected YYYY-MM-DD or YYYY-MM-DD HH:MM:SS")


def _row_ts(row: dict) -> datetime | None:
    ts = row.get("timestamp")
    if not ts:
        return None
    try:
        return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return None


def _row_matches(row: dict, args: argparse.Namespace) -> bool:
    """Apply the ``grep`` filter set to a single row."""
    if getattr(args, "user", None):
        u = row.get("oauth_subject") or row.get("user") or ""
        if args.user not in u:
            return False
    if getattr(args, "tool", None):
        if row.get("tool_name") != args.tool:
            return False
    if getattr(args, "action", None):
        if row.get("action") != args.action:
            return False
    if getattr(args, "decision", None):
        if row.get("policy_decision") != args.decision:
            return False
    if getattr(args, "target", None):
        key, _, value = args.target.partition(":")
        target = row.get("target") or {}
        cell = target.get(key)
        # Match either exact (``hostid:10084``) or substring inside a list
        # (``hostids:10084`` matches when the row carries
        # ``"hostids": ["10084", "10085"]``).
        if isinstance(cell, list):
            if value not in [str(x) for x in cell]:
                return False
        else:
            if str(cell) != value:
                return False
    if getattr(args, "since", None) or getattr(args, "until", None):
        ts = _row_ts(row)
        if ts is None:
            return False
        if args.since:
            since = _parse_ts(args.since)
            if since and ts < since:
                return False
        if args.until:
            until = _parse_ts(args.until)
            if until and ts > until:
                return False
    return True


# ----------------------------------------------------------------------
# Renderers
# ----------------------------------------------------------------------


def _render_table(rows: list[dict]) -> None:
    for r in rows:
        ts = r.get("timestamp", "?")
        if r.get("action") == "tool.invoke":
            subj = r.get("oauth_subject", "?")
            tool = r.get("tool_name", "?")
            dec = r.get("policy_decision", "?")
            target = r.get("target") or {}
            t_str = " ".join(f"{k}={v}" for k, v in target.items())
            count = r.get("result_count")
            count_s = f" -> {count}" if count is not None else ""
            print(f"{ts}  [{dec:18s}]  {subj:32.32s}  {tool:28.28s}{count_s}  {t_str}")
        else:
            act = r.get("action", "?")
            u = r.get("user", "")
            tt = r.get("target_type", "")
            tid = r.get("target_id", "")
            ip = r.get("ip", "")
            tail = f"{tt}/{tid}".strip("/")
            print(f"{ts}  [{act:25.25s}]  {u:24.24s}  {tail:30.30s}  {ip}")


def _render_json(rows: list[dict]) -> None:
    for r in rows:
        print(json.dumps(r, ensure_ascii=False))


_CSV_KEYS = [
    "timestamp", "action", "oauth_subject", "mapped_zabbix_user",
    "user", "mcp_session_id", "tool_name", "policy_decision",
    "denial_reason", "result_count", "scopes", "target_type",
    "target_id", "ip",
]


def _render_csv(rows: list[dict]) -> None:
    w = csv.writer(sys.stdout)
    w.writerow(_CSV_KEYS)
    for r in rows:
        out: list[str] = []
        for k in _CSV_KEYS:
            v = r.get(k, "")
            if isinstance(v, (list, dict)):
                v = json.dumps(v, ensure_ascii=False)
            out.append("" if v is None else str(v))
        w.writerow(out)


# ----------------------------------------------------------------------
# Subcommand handlers
# ----------------------------------------------------------------------


def _cmd_grep(args: argparse.Namespace) -> int:
    rows: list[dict] = []
    for row in _iter_log_lines(args.log, args.include_archives):
        if _row_matches(row, args):
            rows.append(row)
            if args.limit and len(rows) >= args.limit:
                break
    if args.format == "json":
        _render_json(rows)
    elif args.format == "csv":
        _render_csv(rows)
    else:
        _render_table(rows)
    if not rows and args.format == "table":
        print(f"# 0 rows matched ({args.log})", file=sys.stderr)
    return 0


def _cmd_tail(args: argparse.Namespace) -> int:
    rows = list(_iter_log_lines(args.log))
    if args.lines and args.lines > 0:
        rows = rows[-args.lines:]
    if args.format == "json":
        _render_json(rows)
    else:
        _render_table(rows)
    return 0


def _cmd_stats(args: argparse.Namespace) -> int:
    since = _parse_ts(args.since) if args.since else None
    until = _parse_ts(args.until) if args.until else None
    decisions: Counter[str] = Counter()
    tools: Counter[str] = Counter()
    subjects: Counter[str] = Counter()
    actions: Counter[str] = Counter()
    total = 0
    tool_invokes = 0
    for r in _iter_log_lines(args.log, args.include_archives):
        ts = _row_ts(r)
        if since and ts and ts < since:
            continue
        if until and ts and ts > until:
            continue
        total += 1
        if r.get("action") == "tool.invoke":
            tool_invokes += 1
            decisions[r.get("policy_decision") or "?"] += 1
            tools[r.get("tool_name") or "?"] += 1
            subjects[r.get("oauth_subject") or "?"] += 1
        else:
            actions[r.get("action") or "?"] += 1

    print(f"Audit log: {args.log}")
    if since or until:
        bound = []
        if since:
            bound.append(f"since {args.since}")
        if until:
            bound.append(f"until {args.until}")
        print(f"Window:    {', '.join(bound)}")
    print(f"Total rows:        {total}")
    print(f"Tool invocations:  {tool_invokes}")
    print(f"Admin events:      {total - tool_invokes}")
    if decisions:
        print()
        print("Tool invocations by decision:")
        for dec, n in decisions.most_common():
            print(f"  {dec:25s} {n}")
    if tools:
        print()
        print(f"Top {args.top} tools (tool.invoke):")
        for tool, n in tools.most_common(args.top):
            print(f"  {tool:30s} {n}")
    if subjects:
        print()
        print(f"Top {args.top} subjects:")
        for u, n in subjects.most_common(args.top):
            print(f"  {u:50.50s} {n}")
    if actions:
        print()
        print(f"Top {args.top} admin actions:")
        for act, n in actions.most_common(args.top):
            print(f"  {act:30s} {n}")
    return 0


# ----------------------------------------------------------------------
# Entry point
# ----------------------------------------------------------------------


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="zabbix-mcp-server audit",
        description="Audit log incident-review utilities",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("grep", help="Filter audit log entries")
    g.add_argument("--log", default=str(DEFAULT_AUDIT_LOG),
                   help=f"Audit log path (default {DEFAULT_AUDIT_LOG})")
    g.add_argument("--user", help="Filter by oauth_subject / user (substring match)")
    g.add_argument("--tool", help="Filter by tool_name (exact, e.g. host_get)")
    g.add_argument("--action", help="Filter by action (e.g. tool.invoke / login_success / settings_update)")
    g.add_argument("--decision", help="Filter by policy_decision (allow / deny_scope / deny_read_only / ...)")
    g.add_argument("--target", help="Filter by target field (key:value, e.g. hostid:10084 or hostids:10084)")
    g.add_argument("--since", help="Lower-bound timestamp (YYYY-MM-DD or YYYY-MM-DD HH:MM:SS)")
    g.add_argument("--until", help="Upper-bound timestamp")
    g.add_argument("--limit", type=int, default=0, help="Stop after N matches (0 = unlimited)")
    g.add_argument("--include-archives", action="store_true",
                   help=f"Also scan rotated audit.log.YYYY-MM-DD.gz files in the same directory")
    g.add_argument("--format", choices=["table", "json", "csv"], default="table")
    g.set_defaults(func=_cmd_grep)

    t = sub.add_parser("tail", help="Show the last N audit rows")
    t.add_argument("--log", default=str(DEFAULT_AUDIT_LOG))
    t.add_argument("-n", "--lines", type=int, default=20)
    t.add_argument("--format", choices=["table", "json"], default="table")
    t.set_defaults(func=_cmd_tail)

    s = sub.add_parser("stats", help="Aggregate counts per decision / top tools / top subjects")
    s.add_argument("--log", default=str(DEFAULT_AUDIT_LOG))
    s.add_argument("--since", help="Lower-bound timestamp")
    s.add_argument("--until", help="Upper-bound timestamp")
    s.add_argument("--top", type=int, default=10, help="Top-N items per category (default 10)")
    s.add_argument("--include-archives", action="store_true")
    s.set_defaults(func=_cmd_stats)

    v = sub.add_parser("verify", help="Verify HMAC tamper chain integrity")
    v.add_argument("--log", default=str(DEFAULT_AUDIT_LOG),
                   help=f"Audit log path (default {DEFAULT_AUDIT_LOG})")
    v.add_argument("--secret", required=True,
                   help="Path to the HMAC secret file (same as [audit].hmac_secret_path)")
    v.set_defaults(func=_cmd_verify)

    args = parser.parse_args(argv)
    return args.func(args)


def _cmd_verify(args: argparse.Namespace) -> int:
    """Walk the audit log forward, recompute the HMAC chain, and report
    any row whose chain digest does not match the recorded one.

    Exit code 0 = chain intact. 1 = mismatch (some row was modified,
    deleted, or inserted). 2 = setup error (secret unreadable, log
    not chained).
    """
    import hashlib, hmac
    from pathlib import Path
    try:
        content = Path(args.secret).read_text(encoding="utf-8").strip()
        try:
            secret = bytes.fromhex(content)
        except ValueError:
            secret = content.encode("utf-8")
    except OSError as e:
        print(f"ERROR: cannot read secret {args.secret}: {e}", file=sys.stderr)
        return 2
    if not secret:
        print(f"ERROR: secret file {args.secret} is empty", file=sys.stderr)
        return 2

    prev = "0" * 64
    rows_verified = 0
    rows_unsigned = 0
    first_break: tuple[int, str] | None = None
    line_no = 0
    try:
        with open(args.log, "r", encoding="utf-8", errors="replace") as f:
            for raw in f:
                line_no += 1
                line = raw.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                got = row.pop("hmac_chain", None)
                if got is None:
                    rows_unsigned += 1
                    continue
                payload = json.dumps(row, sort_keys=True, default=str, ensure_ascii=False)
                expected = hmac.new(
                    secret, (prev + payload).encode("utf-8"), hashlib.sha256,
                ).hexdigest()
                if not _const_eq(expected, got):
                    if first_break is None:
                        first_break = (line_no, str(got))
                    # Continue checking - downstream rows depend on the
                    # expected chain so they will all be reported as
                    # broken; we still want to count them.
                    prev = got  # advance with the on-disk value so
                                # subsequent rows that ARE consistent
                                # with each other still match.
                else:
                    prev = got
                rows_verified += 1
    except OSError as e:
        print(f"ERROR: cannot read log {args.log}: {e}", file=sys.stderr)
        return 2

    print(f"Log: {args.log}")
    print(f"Secret: {args.secret} ({len(secret)} bytes)")
    print(f"Signed rows verified: {rows_verified}")
    print(f"Unsigned rows skipped: {rows_unsigned}")
    if first_break:
        print(f"\nCHAIN BROKEN at line {first_break[0]}: hmac_chain {first_break[1][:16]}...")
        print("Verdict: TAMPER DETECTED - audit log integrity compromised.")
        return 1
    if rows_verified == 0 and rows_unsigned > 0:
        print("\nVerdict: log is unsigned - enable [audit].hmac_secret_path to start chaining.")
        return 2
    print("\nVerdict: chain intact.")
    return 0


def _const_eq(a: str, b: str) -> bool:
    """Constant-time string compare for the chain digest."""
    if len(a) != len(b):
        return False
    diff = 0
    for x, y in zip(a, b):
        diff |= ord(x) ^ ord(y)
    return diff == 0
