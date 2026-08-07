#
# Zabbix MCP Server
# Copyright (C) 2026 initMAX s.r.o.
# Licensed under the GNU Affero General Public License v3.
# See LICENSE for details.
#

"""The /servers drift check must compare like with like.

Reported by @G0nz0uk in #67 (tracked as #72): a "restart needed" banner
that survived every restart and appeared only on /servers. The page
reads the raw TOML string while the running client holds what the config
loader produced, and the loader strips the trailing slash. So a URL
written as `https://host/` differed from itself forever - and restarting
could not help, because the next boot stripped the slash again and the
page compared the same two values.

These drive the real `_render_servers_list()`, not a copy of its
comparison: the bug lived in how that function sources its two operands,
so a test that re-implements the comparison would have passed against
the broken code.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from zabbix_mcp.admin.views.servers import _render_servers_list
from zabbix_mcp.config import ZabbixServerConfig


class _FakeClientManager:
    """The running state: URLs as the config loader normalised them."""

    def __init__(self, live: dict[str, str]):
        # The loader does url.rstrip("/") - mirror that, because the
        # point of the test is the gap between raw and normalised.
        self._cfgs = {
            name: ZabbixServerConfig(name=name, url=url.rstrip("/"), api_token="t",
                                     read_only=True, verify_ssl=True)
            for name, url in live.items()
        }
        self.skipped_servers = {}

    @property
    def server_names(self):
        return list(self._cfgs)

    def get_server_config(self, name):
        return self._cfgs[name]


class _FakeAdminApp:
    def __init__(self, config_path, client_manager):
        self.config_path = str(config_path)
        self.client_manager = client_manager
        self.restart_needed = False
        self.rendered = None

    def render(self, template, request, ctx):
        self.rendered = (template, ctx)
        return "rendered"


def _render(config_toml: str, live: dict[str, str]) -> _FakeAdminApp:
    """Render /servers against this config and return the admin app."""
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "config.toml"
        path.write_text(config_toml)
        app = _FakeAdminApp(path, _FakeClientManager(live))
        _render_servers_list(request=None, admin_app=app)
        return app


def _cfg(url: str, name: str = "Dev") -> str:
    return f'[zabbix.{name}]\nurl = "{url}"\napi_token = "t"\n'


class TestDriftOnRender(unittest.TestCase):

    def test_trailing_slash_does_not_raise_the_banner(self):
        # The reported bug, exactly: config.toml says 'https://host/',
        # the running client holds 'https://host'.
        app = _render(_cfg("https://zabbix.example.com/"),
                      {"Dev": "https://zabbix.example.com/"})
        self.assertFalse(app.restart_needed)
        self.assertFalse(app.rendered[1]["servers"][0]["config_changed"])

    def test_rendering_twice_does_not_arm_it_either(self):
        # The banner was re-armed on every render, so once is not proof.
        for _ in range(3):
            app = _render(_cfg("https://zabbix.example.com/"),
                          {"Dev": "https://zabbix.example.com/"})
            self.assertFalse(app.restart_needed)

    def test_identical_urls_do_not_raise_the_banner(self):
        app = _render(_cfg("https://zabbix.example.com"),
                      {"Dev": "https://zabbix.example.com"})
        self.assertFalse(app.restart_needed)

    def test_a_real_url_change_still_raises_the_banner(self):
        # The check must keep doing its job.
        app = _render(_cfg("https://new.example.com"),
                      {"Dev": "https://old.example.com"})
        self.assertTrue(app.restart_needed)
        self.assertTrue(app.rendered[1]["servers"][0]["config_changed"])

    def test_scheme_change_still_raises_the_banner(self):
        app = _render(_cfg("https://zabbix.example.com"),
                      {"Dev": "http://zabbix.example.com"})
        self.assertTrue(app.restart_needed)

    def test_path_change_still_raises_the_banner(self):
        app = _render(_cfg("https://host/zabbix"), {"Dev": "https://host"})
        self.assertTrue(app.restart_needed)

    def test_a_server_added_to_config_but_not_live_still_raises_it(self):
        # The other drift path must be untouched by the fix.
        app = _render(_cfg("https://zabbix.example.com") + _cfg("https://new.example.com", "Prod"),
                      {"Dev": "https://zabbix.example.com"})
        self.assertTrue(app.restart_needed)

    def test_a_live_server_removed_from_config_still_raises_it(self):
        app = _render(_cfg("https://zabbix.example.com"),
                      {"Dev": "https://zabbix.example.com",
                       "Gone": "https://gone.example.com"})
        self.assertTrue(app.restart_needed)

    def test_two_servers_both_with_trailing_slashes(self):
        # G0nz0uk's shape: Dev and Prod, both online.
        app = _render(_cfg("https://dev.example.com/") + _cfg("https://prod.example.com/", "Prod"),
                      {"Dev": "https://dev.example.com/", "Prod": "https://prod.example.com/"})
        self.assertFalse(app.restart_needed)


if __name__ == "__main__":
    unittest.main()
