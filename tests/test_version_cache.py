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

"""Version cache tests - no live Zabbix server required."""

import unittest
from unittest.mock import patch

from zabbix_mcp.client import ClientManager
from zabbix_mcp.config import AppConfig, ZabbixServerConfig


def _manager() -> ClientManager:
    return ClientManager(
        AppConfig(
            zabbix_servers={
                "t": ZabbixServerConfig(name="t", url="http://z", api_token="tok")
            }
        )
    )


class TestVersionCache(unittest.TestCase):
    def test_reconnect_refreshes_cached_version(self):
        # Issue #89: after a Zabbix upgrade behind the same URL, Test
        # Connection (check_connection -> _reconnect) logs the new release
        # but the admin pages kept showing the pre-upgrade one, because
        # _versions was never invalidated.
        mgr = _manager()
        with patch("zabbix_mcp.client.ZabbixAPI") as cls:
            api = cls.return_value
            api.api_version.return_value = "6.0.46"
            self.assertEqual(mgr.get_version("t"), "6.0.46")

            # The upgrade happens; the next reconnect talks to Zabbix 7.0.
            api.api_version.return_value = "7.0.26"
            mgr._reconnect("t")

            self.assertEqual(mgr.get_version("t"), "7.0.26")

    def test_auto_reconnect_on_call_failure_refreshes_cached_version(self):
        # The same stale report came from the auto-reconnect in call():
        # the connection recovered, the version display did not.
        mgr = _manager()
        with patch("zabbix_mcp.client.ZabbixAPI") as cls:
            api = cls.return_value
            api.api_version.return_value = "6.0.46"
            self.assertEqual(mgr.get_version("t"), "6.0.46")

            api.api_version.return_value = "7.0.26"
            api.host.get.side_effect = [ConnectionError("socket died"), ["h1"]]
            result = mgr.call("t", "host.get", {"limit": 1})

            self.assertEqual(result, ["h1"])
            self.assertEqual(mgr.get_version("t"), "7.0.26")


if __name__ == "__main__":
    unittest.main()
