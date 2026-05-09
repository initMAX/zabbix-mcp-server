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

"""``zabbix-mcp-server audit`` CLI helper tests (issue #49 acceptance)."""

from __future__ import annotations

import argparse
import gzip
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path


def _make_args(**kw):
    a = argparse.Namespace()
    for k in ("user", "tool", "action", "decision", "target", "since", "until"):
        setattr(a, k, kw.get(k))
    return a


def _write_log(rows: list[dict]) -> tempfile._TemporaryFileWrapper:
    f = tempfile.NamedTemporaryFile("w", suffix=".log", delete=False, encoding="utf-8")
    for r in rows:
        f.write(json.dumps(r) + "\n")
    f.close()
    return f


SAMPLE_ROWS = [
    {
        "timestamp": "2026-05-09 10:00:00", "action": "tool.invoke",
        "oauth_subject": "token:CI", "tool_name": "host_get",
        "policy_decision": "allow", "target": {"hostids": ["10084"]},
        "result_count": 1, "scopes": ["*"],
    },
    {
        "timestamp": "2026-05-09 10:01:00", "action": "tool.invoke",
        "oauth_subject": "token:CI", "tool_name": "host_create",
        "policy_decision": "deny_scope", "denial_reason": "read-only",
        "target": {}, "scopes": ["monitoring"],
    },
    {
        "timestamp": "2026-05-09 10:02:00", "action": "tool.invoke",
        "oauth_subject": "oauth:abc:alice", "tool_name": "host_get",
        "policy_decision": "allow", "target": {"hostids": ["20000"]},
        "result_count": "N", "scopes": ["plugin:zabbix.read"],
    },
    {
        "timestamp": "2026-05-09 10:05:00", "action": "login_success",
        "user": "alice", "target_type": "admin", "target_id": "alice",
        "ip": "10.0.0.1",
    },
    {
        "timestamp": "2026-05-09 10:06:00", "action": "login_failed",
        "user": "mallory", "ip": "203.0.113.7",
    },
]


class TestAuditCLIFilters(unittest.TestCase):
    """Predicate matrix for ``audit grep`` filter args."""

    def test_filter_user_substring(self):
        from zabbix_mcp.cli_audit import _row_matches
        self.assertTrue(_row_matches(SAMPLE_ROWS[0], _make_args(user="CI")))
        self.assertTrue(_row_matches(SAMPLE_ROWS[0], _make_args(user="token:")))
        self.assertFalse(_row_matches(SAMPLE_ROWS[0], _make_args(user="alice")))
        self.assertTrue(_row_matches(SAMPLE_ROWS[3], _make_args(user="alice")))

    def test_filter_tool_exact(self):
        from zabbix_mcp.cli_audit import _row_matches
        self.assertTrue(_row_matches(SAMPLE_ROWS[0], _make_args(tool="host_get")))
        self.assertFalse(_row_matches(SAMPLE_ROWS[0], _make_args(tool="host_create")))

    def test_filter_decision(self):
        from zabbix_mcp.cli_audit import _row_matches
        self.assertTrue(_row_matches(SAMPLE_ROWS[0], _make_args(decision="allow")))
        self.assertTrue(_row_matches(SAMPLE_ROWS[1], _make_args(decision="deny_scope")))
        self.assertFalse(_row_matches(SAMPLE_ROWS[0], _make_args(decision="deny_scope")))

    def test_filter_action(self):
        from zabbix_mcp.cli_audit import _row_matches
        self.assertTrue(_row_matches(SAMPLE_ROWS[3], _make_args(action="login_success")))
        self.assertFalse(_row_matches(SAMPLE_ROWS[0], _make_args(action="login_success")))

    def test_filter_target_list_membership(self):
        from zabbix_mcp.cli_audit import _row_matches
        self.assertTrue(_row_matches(SAMPLE_ROWS[0], _make_args(target="hostids:10084")))
        self.assertFalse(_row_matches(SAMPLE_ROWS[0], _make_args(target="hostids:99999")))

    def test_filter_since_until(self):
        from zabbix_mcp.cli_audit import _row_matches
        self.assertTrue(_row_matches(SAMPLE_ROWS[0], _make_args(since="2026-05-08")))
        self.assertFalse(_row_matches(SAMPLE_ROWS[0], _make_args(since="2026-05-10")))
        self.assertTrue(_row_matches(SAMPLE_ROWS[0], _make_args(until="2026-05-09 23:59:59")))
        self.assertFalse(_row_matches(SAMPLE_ROWS[0], _make_args(until="2026-05-08")))


class TestAuditCLIGrepCommand(unittest.TestCase):
    """End-to-end grep / tail / stats with synthesised log."""

    def setUp(self):
        self.f = _write_log(SAMPLE_ROWS)
        self.path = self.f.name

    def tearDown(self):
        Path(self.path).unlink(missing_ok=True)

    def test_grep_json_format_emits_one_line_per_match(self):
        from zabbix_mcp.cli_audit import main
        buf = io.StringIO()
        with redirect_stdout(buf):
            main(["grep", "--log", self.path, "--tool", "host_get", "--format", "json"])
        lines = [l for l in buf.getvalue().splitlines() if l.strip()]
        self.assertEqual(len(lines), 2)
        for line in lines:
            row = json.loads(line)
            self.assertEqual(row["tool_name"], "host_get")

    def test_grep_csv_format_has_header_row(self):
        from zabbix_mcp.cli_audit import main, _CSV_KEYS
        buf = io.StringIO()
        with redirect_stdout(buf):
            main(["grep", "--log", self.path, "--decision", "allow", "--format", "csv"])
        out = buf.getvalue().splitlines()
        self.assertEqual(out[0].split(","), _CSV_KEYS)
        self.assertEqual(len(out), 3)  # header + 2 allow rows

    def test_grep_limit_caps_output(self):
        from zabbix_mcp.cli_audit import main
        buf = io.StringIO()
        with redirect_stdout(buf):
            main(["grep", "--log", self.path, "--format", "json", "--limit", "2"])
        lines = [l for l in buf.getvalue().splitlines() if l.strip()]
        self.assertEqual(len(lines), 2)

    def test_grep_target_filter_matches_list_membership(self):
        from zabbix_mcp.cli_audit import main
        buf = io.StringIO()
        with redirect_stdout(buf):
            main(["grep", "--log", self.path, "--target", "hostids:10084",
                  "--format", "json"])
        lines = [l for l in buf.getvalue().splitlines() if l.strip()]
        self.assertEqual(len(lines), 1)

    def test_tail_returns_last_n_rows(self):
        from zabbix_mcp.cli_audit import main
        buf = io.StringIO()
        with redirect_stdout(buf):
            main(["tail", "--log", self.path, "-n", "2", "--format", "json"])
        lines = [l for l in buf.getvalue().splitlines() if l.strip()]
        self.assertEqual(len(lines), 2)
        # Last two should be login_success + login_failed
        actions = [json.loads(l)["action"] for l in lines]
        self.assertEqual(actions, ["login_success", "login_failed"])

    def test_stats_aggregates_by_decision_and_subject(self):
        from zabbix_mcp.cli_audit import main
        buf = io.StringIO()
        with redirect_stdout(buf):
            main(["stats", "--log", self.path])
        out = buf.getvalue()
        self.assertIn("Total rows:        5", out)
        self.assertIn("Tool invocations:  3", out)
        self.assertIn("Admin events:      2", out)
        self.assertIn("allow", out)
        self.assertIn("deny_scope", out)
        self.assertIn("token:CI", out)
        self.assertIn("login_success", out)


class TestAuditCLIArchiveScan(unittest.TestCase):
    """``--include-archives`` walks gzipped rotation files."""

    def test_grep_includes_dated_gz_archive(self):
        from zabbix_mcp.cli_audit import main
        with tempfile.TemporaryDirectory() as d:
            live = Path(d) / "audit.log"
            arch = Path(d) / "audit.log.2026-04-01.gz"
            live.write_text(json.dumps(SAMPLE_ROWS[0]) + "\n", encoding="utf-8")
            with gzip.open(arch, "wt", encoding="utf-8") as g:
                g.write(json.dumps(SAMPLE_ROWS[3]) + "\n")  # login_success
            buf = io.StringIO()
            with redirect_stdout(buf):
                main(["grep", "--log", str(live), "--include-archives",
                      "--format", "json"])
            lines = [l for l in buf.getvalue().splitlines() if l.strip()]
            actions = sorted(json.loads(l)["action"] for l in lines)
            self.assertEqual(actions, ["login_success", "tool.invoke"])


if __name__ == "__main__":
    unittest.main()
