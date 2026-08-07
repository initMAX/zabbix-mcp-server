#
# Zabbix MCP Server
# Copyright (C) 2026 initMAX s.r.o.
# Licensed under the GNU Affero General Public License v3.
# See LICENSE for details.
#

"""The /servers drift check must compare like with like.

Reported by @G0nz0uk in #67: a "restart needed" banner that survived
every restart and appeared only on /servers. The page reads the raw
TOML string while the running client holds the value the config loader
produced, and the loader strips the trailing slash. So a URL written as
`https://host/` differed from itself forever - and restarting could not
help, because the next boot stripped the slash again and the page
compared the same two values.
"""

from __future__ import annotations

import unittest

from zabbix_mcp.admin.views.servers import _normalize_url
from zabbix_mcp.config import ZabbixServerConfig


def _drift(config_toml_url: str, running_url: str) -> bool:
    """The comparison as /servers performs it."""
    return _normalize_url(config_toml_url) != _normalize_url(running_url)


class TestUrlDrift(unittest.TestCase):

    def test_trailing_slash_is_not_drift(self):
        # The reported bug: config.toml says 'https://host/', the loader
        # handed the client 'https://host'.
        self.assertFalse(_drift("https://zabbix.example.com/", "https://zabbix.example.com"))

    def test_several_trailing_slashes_are_not_drift(self):
        self.assertFalse(_drift("https://zabbix.example.com///", "https://zabbix.example.com"))

    def test_identical_urls_are_not_drift(self):
        self.assertFalse(_drift("https://zabbix.example.com", "https://zabbix.example.com"))

    def test_a_real_change_is_still_drift(self):
        # The check has to keep doing its job: an operator who edits the
        # URL must still be told to restart.
        self.assertTrue(_drift("https://new.example.com", "https://old.example.com"))

    def test_scheme_change_is_still_drift(self):
        self.assertTrue(_drift("https://zabbix.example.com", "http://zabbix.example.com"))

    def test_path_change_is_still_drift(self):
        self.assertTrue(_drift("https://host/zabbix", "https://host"))

    def test_missing_url_does_not_crash(self):
        self.assertFalse(_drift("", ""))


class TestMatchesLoaderNormalisation(unittest.TestCase):
    """Whatever the loader does to the URL, this must mirror it."""

    def test_loader_output_is_already_normal(self):
        # ZabbixServerConfig is what the running client holds; the loader
        # builds it with url.rstrip("/"). Normalising it again must be a
        # no-op, otherwise the two sides drift apart again.
        live = ZabbixServerConfig(
            name="Dev", url="https://zabbix.example.com", api_token="t",
            read_only=True, verify_ssl=True)
        self.assertEqual(_normalize_url(live.url), live.url)


if __name__ == "__main__":
    unittest.main()
