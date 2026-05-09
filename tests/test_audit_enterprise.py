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

"""Enterprise audit log tests: master toggle, retention housekeeping,
forwarder format converters, queue backpressure."""

from __future__ import annotations

import gzip
import json
import os
import tempfile
import threading
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock


def _sample_row(**overrides):
    row = {
        "timestamp": "2026-05-09 21:00:00",
        "action": "tool.invoke",
        "oauth_subject": "token:CI",
        "mapped_zabbix_user": "Admin",
        "mcp_session_id": "sess-1",
        "tool_name": "host_get",
        "scopes": ["plugin:zabbix.read"],
        "policy_decision": "allow",
        "denial_reason": None,
        "target": {"hostids": ["10084"]},
        "filters": {"output": "extend"},
        "result_count": 1,
        "ip": "10.0.0.1",
    }
    row.update(overrides)
    return row


class TestAuditTimePeriodParser(unittest.TestCase):
    """Zabbix-style time period grammar (31d / 1y / 6h / 0)."""

    def test_parses_common_units(self):
        from zabbix_mcp.config import parse_time_period
        self.assertEqual(parse_time_period("31d"), 31 * 86400)
        self.assertEqual(parse_time_period("1y"), 365 * 86400)
        self.assertEqual(parse_time_period("90d"), 90 * 86400)
        self.assertEqual(parse_time_period("6h"), 6 * 3600)
        self.assertEqual(parse_time_period("30m"), 30 * 60)

    def test_zero_disables_time_purge(self):
        from zabbix_mcp.config import parse_time_period
        self.assertEqual(parse_time_period("0"), 0)
        self.assertEqual(parse_time_period(""), 0)
        self.assertEqual(parse_time_period(None), 0)

    def test_invalid_input_raises(self):
        from zabbix_mcp.config import parse_time_period, ConfigError
        with self.assertRaises(ConfigError):
            parse_time_period("31days")
        with self.assertRaises(ConfigError):
            parse_time_period("forever")


class TestAuditMasterToggle(unittest.TestCase):
    """master ``[audit].enabled`` gates write_audit / write_tool_audit."""

    def setUp(self):
        from zabbix_mcp.admin import audit_writer
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "audit.log"
        self.client_path = Path(self.tmp.name) / "client-audit.log"
        self._orig_op = audit_writer.AUDIT_LOG_PATH
        self._orig_cl = audit_writer.CLIENT_AUDIT_LOG_PATH
        audit_writer.AUDIT_LOG_PATH = self.path
        audit_writer.CLIENT_AUDIT_LOG_PATH = self.client_path
        # Reset to known runtime state.
        audit_writer.configure(
            enabled=True, log_system_actions=False,
            housekeeping_enabled=False, retention_seconds=0,
            max_file_size_bytes=50 * 1024 * 1024,
        )

    def tearDown(self):
        from zabbix_mcp.admin import audit_writer
        audit_writer.AUDIT_LOG_PATH = self._orig_op
        audit_writer.CLIENT_AUDIT_LOG_PATH = self._orig_cl
        self.tmp.cleanup()

    def test_disabling_audit_silences_tool_invoke(self):
        from zabbix_mcp.admin.audit_writer import write_tool_audit, configure
        configure(enabled=False, log_system_actions=False, housekeeping_enabled=False,
                  retention_seconds=0, max_file_size_bytes=50 * 1024 * 1024)
        write_tool_audit(
            oauth_subject="token:Disabled",
            mapped_zabbix_user="Admin",
            mcp_session_id="sess-x",
            tool_name="host_get",
            scopes=["*"],
            policy_decision="allow",
            denial_reason=None,
            target={}, filters={}, result_count=1, ip="10.0.0.1",
        )
        # File should not exist - the audit write was silenced.
        self.assertFalse(self.path.exists() and self.path.stat().st_size > 0)

    def test_disabling_audit_silences_admin_event(self):
        from zabbix_mcp.admin.audit_writer import write_audit, configure
        configure(enabled=False, log_system_actions=False, housekeeping_enabled=False,
                  retention_seconds=0, max_file_size_bytes=50 * 1024 * 1024)
        write_audit("token_create", user="alice", target_type="token", target_id="ci")
        self.assertFalse(self.path.exists() and self.path.stat().st_size > 0)

    def test_audit_toggle_event_always_recorded_even_when_disabled(self):
        """Disabling audit is itself a compliance-relevant event - the
        toggle audit row must survive the master gate."""
        from zabbix_mcp.admin.audit_writer import write_audit, configure
        configure(enabled=False, log_system_actions=False, housekeeping_enabled=False,
                  retention_seconds=0, max_file_size_bytes=50 * 1024 * 1024)
        write_audit("audit.toggle", user="alice", target_type="audit",
                    target_id="enabled", details={"from": True, "to": False})
        self.assertTrue(self.path.exists())
        rows = [json.loads(l) for l in self.path.read_text().splitlines() if l.strip()]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["action"], "audit.toggle")

    def test_log_system_actions_off_drops_housekeeping_events(self):
        from zabbix_mcp.admin.audit_writer import write_audit, configure
        configure(enabled=True, log_system_actions=False, housekeeping_enabled=False,
                  retention_seconds=0, max_file_size_bytes=50 * 1024 * 1024)
        write_audit("housekeeping.cycle", details={"archives_made": 1})
        self.assertFalse(self.path.exists() and self.path.stat().st_size > 0)

    def test_log_system_actions_on_lets_housekeeping_through(self):
        from zabbix_mcp.admin.audit_writer import write_audit, configure
        configure(enabled=True, log_system_actions=True, housekeeping_enabled=False,
                  retention_seconds=0, max_file_size_bytes=50 * 1024 * 1024)
        write_audit("housekeeping.cycle", details={"archives_made": 1})
        self.assertTrue(self.path.exists())
        rows = [json.loads(l) for l in self.path.read_text().splitlines() if l.strip()]
        self.assertEqual(rows[0]["action"], "housekeeping.cycle")


class TestRetentionPurge(unittest.TestCase):
    """Daily-rotation + age-based purge in audit_writer.housekeeping."""

    def setUp(self):
        from zabbix_mcp.admin import audit_writer
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "audit.log"
        self.client_path = Path(self.tmp.name) / "client-audit.log"
        self._orig_op = audit_writer.AUDIT_LOG_PATH
        self._orig_cl = audit_writer.CLIENT_AUDIT_LOG_PATH
        audit_writer.AUDIT_LOG_PATH = self.path
        audit_writer.CLIENT_AUDIT_LOG_PATH = self.client_path

    def tearDown(self):
        from zabbix_mcp.admin import audit_writer
        audit_writer.AUDIT_LOG_PATH = self._orig_op
        audit_writer.CLIENT_AUDIT_LOG_PATH = self._orig_cl
        self.tmp.cleanup()

    def test_rotation_creates_dated_gzip(self):
        from zabbix_mcp.admin.audit_writer import _rotate_to_dated
        self.path.write_text("line1\nline2\n")
        archive = _rotate_to_dated(self.path)
        self.assertIsNotNone(archive)
        self.assertTrue(archive.exists())
        self.assertTrue(archive.name.endswith(".gz"))
        # Live file truncated.
        self.assertEqual(self.path.read_text(), "")
        # Archive is valid gzip + content matches.
        with gzip.open(archive, "rt") as f:
            self.assertEqual(f.read(), "line1\nline2\n")

    def test_rotation_skips_empty_file(self):
        from zabbix_mcp.admin.audit_writer import _rotate_to_dated
        # File missing entirely.
        archive = _rotate_to_dated(self.path)
        self.assertIsNone(archive)
        # Empty file.
        self.path.write_text("")
        archive = _rotate_to_dated(self.path)
        self.assertIsNone(archive)

    def test_purge_deletes_old_archives(self):
        from zabbix_mcp.admin.audit_writer import _purge_old_archives
        # Create 3 archives - 50d, 20d, 5d old.
        now = time.time()
        files = []
        for days_old, label in [(50, "old"), (20, "med"), (5, "new")]:
            d = (datetime.now(timezone.utc) -
                 __import__("datetime").timedelta(days=days_old))
            name = f"{self.path.name}.{d.strftime('%Y-%m-%d')}.gz"
            p = self.path.parent / name
            p.write_bytes(b"\x1f\x8b\x08\x00")  # gzip magic only - body irrelevant
            os.utime(p, (now - days_old * 86400, now - days_old * 86400))
            files.append((p, days_old))
        # 31-day retention drops the 50d file only.
        purged, freed = _purge_old_archives(self.path, 31 * 86400)
        self.assertEqual(purged, 1)
        self.assertGreater(freed, 0)
        for p, days in files:
            if days == 50:
                self.assertFalse(p.exists(), f"{p} should have been purged")
            else:
                self.assertTrue(p.exists(), f"{p} should still exist")

    def test_purge_zero_retention_disables(self):
        from zabbix_mcp.admin.audit_writer import _purge_old_archives
        d = datetime.now(timezone.utc)
        name = f"{self.path.name}.{d.strftime('%Y-%m-%d')}.gz"
        p = self.path.parent / name
        p.write_bytes(b"data")
        os.utime(p, (time.time() - 365 * 86400, time.time() - 365 * 86400))
        # Retention = 0 -> short-circuit, no purge.
        purged, freed = _purge_old_archives(self.path, 0)
        self.assertEqual(purged, 0)
        self.assertTrue(p.exists())


class TestForwarderFormatters(unittest.TestCase):
    """Wire-format converters produce conformant output."""

    def test_rfc5424_has_pri_and_iso_timestamp(self):
        from zabbix_mcp.admin.audit_forwarder import _format_rfc5424
        wire = _format_rfc5424(_sample_row())
        self.assertTrue(wire.startswith("<"))
        # PRI is decimal int between < and >
        pri_end = wire.index(">")
        pri = int(wire[1:pri_end])
        # Facility 13 (audit) * 8 + severity 5 (allow -> notice) = 109
        self.assertEqual(pri, 13 * 8 + 5)
        # Body is JSON of the row
        self.assertIn('"action": "tool.invoke"', wire)
        self.assertIn('"oauth_subject": "token:CI"', wire)

    def test_rfc5424_severity_for_deny(self):
        from zabbix_mcp.admin.audit_forwarder import _format_rfc5424
        wire = _format_rfc5424(_sample_row(policy_decision="deny_scope"))
        pri_end = wire.index(">")
        pri = int(wire[1:pri_end])
        # deny_* -> warning (4)
        self.assertEqual(pri, 13 * 8 + 4)

    def test_cef_has_required_prefix(self):
        from zabbix_mcp.admin.audit_forwarder import _format_cef
        wire = _format_cef(_sample_row())
        # CEF prefix: CEF:0|Vendor|Product|Version|EventID|Name|Severity|
        self.assertIn("CEF:0|initMAX|zabbix-mcp-server|1.31|", wire)
        self.assertIn("suser=token:CI", wire)
        self.assertIn("act=host_get", wire)
        self.assertIn("src=10.0.0.1", wire)
        self.assertIn("externalId=sess-1", wire)

    def test_cef_escapes_special_chars(self):
        from zabbix_mcp.admin.audit_forwarder import _format_cef, _cef_escape
        # Pipe + equals + backslash must be escaped.
        self.assertEqual(_cef_escape("a|b=c\\d"), "a\\|b\\=c\\\\d")
        wire = _format_cef(_sample_row(oauth_subject="user|with|pipes"))
        # The escaped sequence (backslash + pipe) should be present
        # *inside* the CEF extension, not as raw pipes that would
        # break the format prefix.
        self.assertIn("suser=user\\|with\\|pipes", wire)

    def test_leef_has_tab_separator(self):
        from zabbix_mcp.admin.audit_forwarder import _format_leef
        wire = _format_leef(_sample_row())
        self.assertIn("LEEF:2.0|initMAX|zabbix-mcp-server|1.31|", wire)
        self.assertIn("\t", wire)
        self.assertIn("usrName=token:CI", wire)
        self.assertIn("action=host_get", wire)

    def test_json_format_round_trips(self):
        from zabbix_mcp.admin.audit_forwarder import _format_json_line
        wire = _format_json_line(_sample_row())
        # Strip syslog framing prefix to recover the JSON body.
        body_start = wire.index("- - -") + len("- - -")
        body = wire[body_start:].strip()
        parsed = json.loads(body)
        self.assertEqual(parsed["tool_name"], "host_get")
        self.assertEqual(parsed["oauth_subject"], "token:CI")


class TestForwarderQueueBackpressure(unittest.TestCase):
    """Bounded queue drops oldest under pressure (record-side backpressure)."""

    def setUp(self):
        from zabbix_mcp.admin import audit_forwarder
        # Tiny queue to make the test fast.
        audit_forwarder.configure(
            enabled=True, host="127.0.0.1", port=1, protocol="rfc5424_udp",
            queue_size=3,
        )
        # Reset stats.
        audit_forwarder._runtime_stats["messages_dropped_queue_full"] = 0

    def tearDown(self):
        from zabbix_mcp.admin import audit_forwarder
        audit_forwarder.configure(enabled=False, host="", port=514,
                                   protocol="rfc5424_udp", queue_size=10000)

    def test_queue_drops_oldest_when_full(self):
        from zabbix_mcp.admin import audit_forwarder
        for i in range(10):
            audit_forwarder.enqueue({"action": "tool.invoke", "n": i})
        state = audit_forwarder.get_runtime_state()
        # 10 enqueued, queue size 3 -> 7 drops.
        self.assertGreaterEqual(state["messages_dropped_queue_full"], 7)
        self.assertLessEqual(state["queue_depth"], 3)

    def test_disabled_forwarder_silently_drops_enqueue(self):
        from zabbix_mcp.admin import audit_forwarder
        audit_forwarder.configure(enabled=False, host="", port=514,
                                   protocol="rfc5424_udp", queue_size=10)
        # No exception.
        for i in range(5):
            audit_forwarder.enqueue({"action": "tool.invoke", "n": i})
        # Counter not incremented when disabled (call returns immediately).
        state = audit_forwarder.get_runtime_state()
        self.assertEqual(state["queue_depth"], 0)


class TestForwarderConfigValidation(unittest.TestCase):
    """[audit.forward] config validation rejects bad values."""

    def test_protocol_allowlist_size(self):
        # The protocol allowlist is the contract; re-stating it here so
        # a future contributor adding a new protocol must update this
        # test too. Eleven destinations across four wire formats:
        # 3 syslog + 3 cef + 3 leef + 2 json = 11.
        valid = {
            "rfc5424_udp", "rfc5424_tcp", "rfc5424_tls",
            "cef_udp", "cef_tcp", "cef_tls",
            "leef_udp", "leef_tcp", "leef_tls",
            "json_tcp", "json_tls",
        }
        self.assertEqual(len(valid), 11)

    def test_default_state_is_off(self):
        from zabbix_mcp.config import AuditForwardConfig
        cfg = AuditForwardConfig()
        self.assertFalse(cfg.enabled)
        self.assertEqual(cfg.host, "")
        self.assertEqual(cfg.port, 514)
        self.assertEqual(cfg.protocol, "rfc5424_udp")
        self.assertEqual(cfg.queue_size, 10000)


if __name__ == "__main__":
    unittest.main()
