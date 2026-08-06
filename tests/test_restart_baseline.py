#
# Zabbix MCP Server
# Copyright (C) 2026 initMAX s.r.o.
# Licensed under the GNU Affero General Public License v3.
# See LICENSE for details.
#

"""Issue #69: a runtime config write that the process already absorbed
must not raise the "restart needed" banner.

Dynamic OAuth client registration appends an ``[oauth_clients.<id>]``
section to config.toml so the client survives the next boot. The
provider already holds it in memory, so demanding a restart is a false
alarm - and it recurs after every restart as soon as a client
reconnects (reported in #67).
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

_CONFIG = """
[server]
transport = "http"
auth_token = "test-token-0123456789abcdef0123456789abcdef"

[zabbix.main]
url = "https://zabbix.example.com"
api_token = "dummy"

[admin]
enabled = true
"""


def _admin_app(config_path: str):
    """Build an AdminApp with collaborators stubbed out.

    Only the config-snapshot / drift machinery is under test here.
    """
    from zabbix_mcp.admin.app import AdminApp
    from zabbix_mcp.config import load_config
    return AdminApp(
        config=load_config(config_path),
        config_path=config_path,
        client_manager=MagicMock(),
        token_store=MagicMock(),
        oauth_provider=None,
    )


class TestRestartBaseline(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False)
        tmp.write(_CONFIG)
        tmp.close()
        self.path = tmp.name
        self.app = _admin_app(self.path)

    def tearDown(self):
        Path(self.path).unlink(missing_ok=True)

    def _append_oauth_client(self) -> None:
        with open(self.path, "a") as fh:
            fh.write(
                '\n[oauth_clients.11111111-2222-3333-4444-555555555555]\n'
                'client_id = "11111111-2222-3333-4444-555555555555"\n'
                'redirect_uris = ["https://claude.ai/api/mcp/auth_callback"]\n'
            )

    def test_clean_start_has_no_pending_changes(self):
        self.assertFalse(self.app._compute_restart_needed())

    def test_runtime_write_alone_would_flag_restart(self):
        # Guard rail: without the refresh, any config write trips the
        # detector - this is what made the banner reappear (#67).
        self._append_oauth_client()
        self.assertTrue(self.app._compute_restart_needed())

    def test_refresh_baseline_clears_the_false_alarm(self):
        self._append_oauth_client()
        self.assertTrue(self.app._compute_restart_needed())
        from zabbix_mcp.admin.app import refresh_config_baseline
        refresh_config_baseline()
        self.assertFalse(
            self.app._compute_restart_needed(),
            "registering an OAuth client must not demand a restart",
        )

    def test_real_operator_edit_still_flags_restart(self):
        # The detector must stay honest about changes the running
        # process has NOT absorbed.
        from zabbix_mcp.admin.app import refresh_config_baseline
        self._append_oauth_client()
        refresh_config_baseline()
        with open(self.path, "a") as fh:
            fh.write('\n[zabbix.second]\nurl = "https://other.example.com"\napi_token = "x"\n')
        self.assertTrue(self.app._compute_restart_needed())

    def test_refresh_is_a_noop_without_a_running_portal(self):
        import zabbix_mcp.admin.app as app_mod
        saved = app_mod._LIVE_ADMIN_APP
        app_mod._LIVE_ADMIN_APP = None
        try:
            app_mod.refresh_config_baseline()  # must not raise
        finally:
            app_mod._LIVE_ADMIN_APP = saved


if __name__ == "__main__":
    unittest.main()
