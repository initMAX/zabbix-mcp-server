"""A call whose answer was lost is asked again only when it changes nothing.

``ClientManager.call`` reconnects after a connection-class error and used
to send the same call again, whatever it was. Those errors arrive after the
request went out (most often a timeout while Zabbix is still working), so a
write sent again runs twice: two ``script.execute``, two imports.
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from zabbix_mcp.api import ALL_METHODS  # noqa: E402
from zabbix_mcp.client import ClientManager, UnknownOutcomeError, resend_is_safe  # noqa: E402
from zabbix_mcp.config import AppConfig, ServerConfig, ZabbixServerConfig  # noqa: E402


def _manager() -> ClientManager:
    return ClientManager(
        AppConfig(
            server=ServerConfig(),
            zabbix_servers={"t": ZabbixServerConfig(name="t", url="http://z", api_token="tok")},
        )
    )


class TestResendIsSafe(unittest.TestCase):
    def test_reads_are_safe_writes_are_not(self):
        for method in ("host.get", "apiinfo.version", "configuration.export", "sla.getsli",
                       "script.getscriptsbyhosts", "user.checkAuthentication", "HOST.GET"):
            self.assertTrue(resend_is_safe(method), method)
        for method in ("host.create", "host.update", "host.delete", "host.massadd", "script.execute",
                       "event.acknowledge", "history.push", "history.clear", "configuration.import",
                       "token.generate", "user.unblock", "task.create", "device.offboard", "nonsense"):
            self.assertFalse(resend_is_safe(method), method)

    def test_agrees_with_the_tool_registry(self):
        # a tool that may run on a read-only server is one that can be asked
        # again, and the other way round: the two lists cannot drift apart
        for tool in ALL_METHODS:
            self.assertEqual(resend_is_safe(tool.api_method), tool.read_only, tool.api_method)


class TestCallAfterALostAnswer(unittest.TestCase):
    def test_a_read_is_asked_again(self):
        mgr = _manager()
        with patch("zabbix_mcp.client.ZabbixAPI") as cls:
            api = cls.return_value
            api.api_version.return_value = "8.0.0"
            api.host.get.side_effect = [TimeoutError("timed out"), ["h1"]]
            self.assertEqual(mgr.call("t", "host.get", {"limit": 1}), ["h1"])
            self.assertEqual(api.host.get.call_count, 2)

    def test_a_write_is_sent_once(self):
        for error in (TimeoutError("timed out"), ConnectionResetError("reset by peer"), OSError("broken pipe")):
            mgr = _manager()
            with patch("zabbix_mcp.client.ZabbixAPI") as cls:
                api = cls.return_value
                api.api_version.return_value = "8.0.0"
                api.script.execute.side_effect = [error, {"response": "success"}]
                with self.assertRaises(UnknownOutcomeError) as caught:
                    mgr.call("t", "script.execute", {"scriptid": "1", "hostid": "2"})
                self.assertEqual(api.script.execute.call_count, 1, type(error).__name__)
                text = str(caught.exception)
                self.assertIn("script.execute", text)
                self.assertIn("was not sent again", text)
                self.assertIn(type(error).__name__, text)

    def test_the_next_call_works_on_a_fresh_connection(self):
        mgr = _manager()
        with patch("zabbix_mcp.client.ZabbixAPI") as cls:
            api = cls.return_value
            api.api_version.return_value = "8.0.0"
            api.host.create.side_effect = [TimeoutError("timed out")]
            with self.assertRaises(UnknownOutcomeError):
                mgr.call("t", "host.create", {"host": "a"})
            connects = cls.call_count
            self.assertGreaterEqual(connects, 2)   # the first client and the reconnect
            api.host.get.return_value = [{"hostid": "1"}]
            self.assertEqual(mgr.call("t", "host.get", {"filter": {"host": "a"}}), [{"hostid": "1"}])

    def test_a_reconnect_that_fails_does_not_hide_the_message(self):
        mgr = _manager()
        with patch("zabbix_mcp.client.ZabbixAPI") as cls:
            api = cls.return_value
            api.api_version.return_value = "8.0.0"
            api.host.update.side_effect = [TimeoutError("timed out")]
            mgr._get_client("t")
            with patch.object(mgr, "_reconnect", side_effect=OSError("still down")):
                with self.assertRaises(UnknownOutcomeError):
                    mgr.call("t", "host.update", {"hostid": "1", "status": 1})

    def test_a_refused_session_is_sent_again_whatever_the_method(self):
        # Zabbix answered "re-login": it did not run the call
        from zabbix_utils.exceptions import ProcessingError
        mgr = _manager()
        with patch("zabbix_mcp.client.ZabbixAPI") as cls:
            api = cls.return_value
            api.api_version.return_value = "8.0.0"
            api.host.create.side_effect = [ProcessingError("Session terminated, re-login, please."), {"hostids": ["5"]}]
            self.assertEqual(mgr.call("t", "host.create", {"host": "a"}), {"hostids": ["5"]})
            self.assertEqual(api.host.create.call_count, 2)


if __name__ == "__main__":
    unittest.main()
