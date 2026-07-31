#
# Zabbix MCP Server
# Copyright (C) 2026 initMAX s.r.o.
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License as published by the Free
# Software Foundation, version 3.
#

"""Issue #61: [zabbix.X] sections skipped at config load must be
reported with their validation reason, not shown as restart-pending.

A skipped section stays skipped on every boot - presenting it as
"needs restart" sent the operator into an endless restart loop.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from zabbix_mcp.config import load_config
from zabbix_mcp.client import ClientManager


_CONFIG = """
[server]
transport = "http"
auth_token = "test-token-0123456789abcdef0123456789abcdef"

[zabbix.good]
url = "https://zabbix.example.com"
api_token = "dummy"

[zabbix.broken]
url = "not-a-valid-url"
api_token = "dummy"
"""


class TestSkippedServers(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.NamedTemporaryFile(
            "w", suffix=".toml", delete=False)
        self._tmp.write(_CONFIG)
        self._tmp.close()
        self.config = load_config(self._tmp.name)

    def tearDown(self):
        Path(self._tmp.name).unlink(missing_ok=True)

    def test_broken_section_skipped_with_reason(self):
        self.assertIn("good", self.config.zabbix_servers)
        self.assertNotIn("broken", self.config.zabbix_servers)
        self.assertIn("broken", self.config.skipped_zabbix_servers)
        self.assertIn("invalid URL", self.config.skipped_zabbix_servers["broken"])

    def test_client_manager_exposes_skipped(self):
        cm = ClientManager(self.config)
        self.assertEqual(cm.server_names, ["good"])
        self.assertIn("broken", cm.skipped_servers)
        self.assertIn("invalid URL", cm.skipped_servers["broken"])

    def test_all_valid_config_has_empty_skips(self):
        with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as f:
            f.write(_CONFIG.replace('url = "not-a-valid-url"',
                                    'url = "https://other.example.com"'))
            path = f.name
        try:
            cfg = load_config(path)
            self.assertEqual(cfg.skipped_zabbix_servers, {})
            self.assertEqual(ClientManager(cfg).skipped_servers, {})
        finally:
            Path(path).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
