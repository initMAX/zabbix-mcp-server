#!/usr/bin/env python3

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

"""Zabbix 8.0 removed five API methods; the matching tools say so instead of
forwarding a call that comes back as a bare "Method not found"."""

import asyncio
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, "src")

from zabbix_mcp.client import ClientManager  # noqa: E402
from zabbix_mcp.config import AppConfig, ServerConfig, ZabbixServerConfig  # noqa: E402
from zabbix_mcp.api.versions import unavailable_reason, METHOD_REMOVED
from zabbix_mcp.server import _refuse_if_unavailable, _register_tools  # noqa: E402

REMOVED_TOOLS = {
    "host_massupdate": {"params": {"hosts": [{"hostid": "1"}], "status": 1}},
    "hostgroup_massupdate": {"params": {"groups": [{"groupid": "1"}], "hosts": []}},
    "template_massupdate": {"params": {"templates": [{"templateid": "1"}], "groups": []}},
    "templategroup_massupdate": {"params": {"groups": [{"groupid": "1"}], "templates": []}},
    "hostinterface_replacehostinterfaces": {"params": {"hostid": "1", "interfaces": []}},
    # 8.0.0 removed the write half of the host interface API (ZBXNEXT-10814)
    "hostinterface_create": {"params": {"hostid": "1", "type": 1, "main": 1, "useip": 1, "ip": "127.0.0.1", "dns": "", "port": "10050"}},
    "hostinterface_update": {"params": {"interfaceid": "1", "port": "10051"}},
    "hostinterface_delete": {"ids": ["1"]},
    "hostinterface_massadd": {"params": {"hosts": [{"hostid": "1"}], "interfaces": []}},
    "hostinterface_massremove": {"params": {"hostids": ["1"], "interfaces": []}},
}


class TestRefuseIfRemoved(unittest.TestCase):
    def test_table_matches_the_8_0_changes_page(self):
        self.assertEqual({m for m, (release, _) in METHOD_REMOVED.items() if release == "8.0"}, {
            "host.massupdate", "hostgroup.massupdate", "template.massupdate",
            "templategroup.massupdate", "hostinterface.replacehostinterfaces",
            "hostinterface.create", "hostinterface.update", "hostinterface.delete",
            "hostinterface.massadd", "hostinterface.massremove"})

    def test_host_interface_writes_point_at_the_host(self):
        # the reference: "Please use methods of the host object instead"
        for method in ("hostinterface.create", "hostinterface.update", "hostinterface.delete",
                       "hostinterface.massadd", "hostinterface.massremove", "hostinterface.replacehostinterfaces"):
            with self.subTest(method=method):
                reason = unavailable_reason(method, "8.0.0")
                self.assertIn("removed in Zabbix 8.0", reason)
                self.assertIn("host.update", reason)
                self.assertNotIn("hostinterface.update,", reason)
                self.assertIsNone(unavailable_reason(method, "7.4.14"))
        self.assertIsNone(unavailable_reason("hostinterface.get", "8.0.0"))

    def test_legacy_objects_are_dated_from_the_reference_index(self):
        # the 5.0 ... 8.0 reference index pages: last release with the object page + 1
        expected = {"templatescreen.get": "5.2", "templatescreenitem.get": "5.2", "settings.getglobal": "5.4",
                    "application.get": "5.4", "screen.get": "5.4", "screenitem.get": "5.4",
                    "service.getsla": "6.0", "service.adddependencies": "6.0", "service.addtimes": "6.0",
                    "trigger.adddependencies": "6.2", "trigger.deletedependencies": "6.2",
                    "discoveryrule.copy": "7.2"}
        for method, release in expected.items():
            with self.subTest(method=method):
                self.assertEqual(METHOD_REMOVED[method][0], release)
                self.assertTrue(METHOD_REMOVED[method][1])
        # a raw call on a newer server gets the replacement, an older one passes
        self.assertIn("item.get", unavailable_reason("application.get", "7.4.14"))
        self.assertIsNone(unavailable_reason("application.get", "5.0.47"))
        self.assertIn("sla.getsli", unavailable_reason("service.getsla", "6.0.48"))
        self.assertIsNone(unavailable_reason("service.getsla", "5.4.12"))

    def test_only_on_8_0_and_later(self):
        from mcp.server.mcpserver.exceptions import ToolError
        for version in ("7.0.10", "7.4.14", "7.99", None, "", "garbage"):
            with self.subTest(version=version):
                _refuse_if_unavailable("host.massupdate", version)  # no raise
        for version in ("8.0.0", "8.0", "8.2.1", "9.0.0"):
            with self.subTest(version=version), self.assertRaises(ToolError) as ctx:
                _refuse_if_unavailable("host.massupdate", version)
            self.assertIn("removed in Zabbix 8.0", str(ctx.exception))
            self.assertIn("host.update", str(ctx.exception))
        _refuse_if_unavailable("host.update", "8.0.0")  # untouched method, no raise


class TestThroughRegisteredTools(unittest.TestCase):
    def setUp(self):
        from mcp.server.mcpserver import MCPServer
        cfg = AppConfig(server=ServerConfig(timezone="UTC"), zabbix_servers={"t": ZabbixServerConfig(
            name="t", url="http://localhost", api_token="x", read_only=False)})
        self.mgr = ClientManager(cfg)
        self.mcp = MCPServer(name="test")
        _register_tools(self.mcp, self.mgr)

    def _call(self, version, tool, args):
        sent = []

        def fake_call(server, method, params, *a, **k):
            sent.append(method)
            return {"hostids": ["1"]}
        with patch.object(self.mgr, "call", side_effect=fake_call), \
                patch.object(self.mgr, "get_version", return_value=version):
            res = asyncio.run(self.mcp.call_tool(tool, args))
        text = "\n".join(c.text for c in res.content if hasattr(c, "text"))
        return res.is_error, text, sent

    def test_removed_tools_are_refused_on_8_0_and_pass_on_7_4(self):
        for tool, args in REMOVED_TOOLS.items():
            with self.subTest(tool=tool):
                with self.assertRaises(Exception) as ctx:
                    self._call("8.0.0", tool, args)
                self.assertIn("removed in Zabbix 8.0", str(ctx.exception))
                err, _, sent = self._call("7.4.14", tool, args)
                self.assertFalse(err)
                self.assertEqual(len(sent), 1)

    def test_raw_api_call_is_covered_too(self):
        with self.assertRaises(Exception) as ctx:
            self._call("8.0.0", "zabbix_raw_api_call", {"method": "template.massupdate", "params": {}})
        self.assertIn("template.massadd", str(ctx.exception))
        err, _, sent = self._call("8.0.0", "zabbix_raw_api_call", {"method": "template.update", "params": {"templateid": "1"}})
        self.assertFalse(err)
        self.assertEqual(sent, ["template.update"])


if __name__ == "__main__":
    unittest.main()


class TestSinceTable(unittest.TestCase):
    """Methods a release does not have yet: refused with the release they need."""

    def setUp(self):
        from zabbix_mcp.api import versions
        self._patch = patch.dict(versions.METHOD_SINCE, {"proxygroup.get": "7.0", "templategroup.get": "6.2"})
        self._patch.start()

    def tearDown(self):
        self._patch.stop()

    def test_unavailable_reason(self):
        from zabbix_mcp.api.versions import unavailable_reason
        self.assertIn("requires Zabbix 7.0 or later", unavailable_reason("proxygroup.get", "6.4.12"))
        self.assertIsNone(unavailable_reason("proxygroup.get", "7.0.0"))
        self.assertIsNone(unavailable_reason("proxygroup.get", "7.4.14"))
        self.assertIsNone(unavailable_reason("proxygroup.get", None))
        self.assertIsNone(unavailable_reason("proxygroup.get", "weird"))
        self.assertIsNone(unavailable_reason("host.get", "5.0.47"))
        self.assertIn("removed in Zabbix 8.0", unavailable_reason("host.massupdate", "8.0.0"))
        self.assertIsNone(unavailable_reason("host.massupdate", "7.4.14"))

    def test_tool_and_raw_call_refused_on_old_release(self):
        from mcp.server.mcpserver import MCPServer
        cfg = AppConfig(server=ServerConfig(timezone="UTC"), zabbix_servers={"old": ZabbixServerConfig(
            name="old", url="http://localhost", api_token="x", read_only=False)})
        mgr = ClientManager(cfg)
        mcp = MCPServer(name="test")
        _register_tools(mcp, mgr)
        sent = []
        with patch.object(mgr, "call", side_effect=lambda s, m, p, *a, **k: sent.append(m) or []), \
                patch.object(mgr, "get_version", return_value="6.0.30"):
            with self.assertRaises(Exception) as ctx:
                asyncio.run(mcp.call_tool("proxygroup_get", {}))
            self.assertIn("requires Zabbix 7.0 or later (this server runs 6.0.30)", str(ctx.exception))
            with self.assertRaises(Exception) as ctx:
                asyncio.run(mcp.call_tool("zabbix_raw_api_call", {"method": "proxygroup.get", "params": {}}))
            self.assertIn("requires Zabbix 7.0", str(ctx.exception))
            asyncio.run(mcp.call_tool("host_get", {}))
            with self.assertRaises(Exception):
                asyncio.run(mcp.call_tool("templategroup_get", {}))  # 6.0 < 6.2
        self.assertEqual(sent, ["host.get"])


class TestToolsListAnnotation(unittest.TestCase):
    """tools/list tells the model what is missing where, and hides what exists nowhere."""

    def setUp(self):
        from zabbix_mcp.api import versions
        from mcp.server.mcpserver import MCPServer
        self._patch = patch.dict(versions.METHOD_SINCE, {"proxygroup.get": "7.0"})
        self._patch.start()
        cfg = AppConfig(server=ServerConfig(timezone="UTC"), zabbix_servers={
            "new": ZabbixServerConfig(name="new", url="http://localhost", api_token="x"),
            "old": ZabbixServerConfig(name="old", url="http://localhost", api_token="x"),
        })
        self.mgr = ClientManager(cfg)
        self.mcp = MCPServer(name="test")
        _register_tools(self.mcp, self.mgr)
        self.tools = self.mcp._tool_manager.list_tools()

    def tearDown(self):
        self._patch.stop()
        from zabbix_mcp.token_store import current_token_info
        current_token_info.set(None)

    def _names(self, tools):
        return {t.name: t for t in tools}

    def test_unknown_versions_leave_the_catalog_alone(self):
        from zabbix_mcp.server import _annotate_tools_by_version
        out = _annotate_tools_by_version(self.tools, self.mgr)
        self.assertIs(out, self.tools)

    def test_mixed_versions_annotate_and_never_mutate(self):
        from zabbix_mcp.server import _annotate_tools_by_version
        self.mgr._versions.update({"new": "7.4.14", "old": "6.0.30"})
        before = self._names(self.tools)["proxygroup_get"].description
        out = self._names(_annotate_tools_by_version(self.tools, self.mgr))
        self.assertIn("proxygroup_get", out)
        self.assertIn("Zabbix version note: not on 'old' - proxygroup.get requires Zabbix 7.0 or later (this server runs 6.0.30).", out["proxygroup_get"].description)
        self.assertTrue(out["proxygroup_get"].description.startswith(before))
        self.assertEqual(self._names(self.tools)["proxygroup_get"].description, before)  # original untouched
        self.assertNotIn("Zabbix version note", out["host_get"].description or "")

    def _with_versions(self, versions):
        self.mgr._versions.clear()
        self.mgr._versions.update(versions)
        return self.mgr

    def test_not_hidden_while_one_reachable_server_is_still_unknown(self):
        """'old' is 6.0, 'new' is down at boot: the 7.0 tool stays listed (with the note), never hidden."""
        from zabbix_mcp.server import _annotate_tools_by_version
        self._with_versions({"old": "6.0.30"})
        out = self._names(_annotate_tools_by_version(self.tools, self.mgr))
        self.assertIn("proxygroup_get", out)
        self.assertIn("not on 'old'", out["proxygroup_get"].description)

    def test_hidden_when_no_reachable_server_has_it(self):
        from zabbix_mcp.server import _annotate_tools_by_version
        self._with_versions({"new": "6.4.0", "old": "6.0.30"})
        out = self._names(_annotate_tools_by_version(self.tools, self.mgr))
        self.assertNotIn("proxygroup_get", out)
        self.assertIn("host_get", out)
        self.assertIn("zabbix_raw_api_call", out)  # extension / raw tools untouched

    def test_removed_on_8_0_is_noted_or_hidden(self):
        from zabbix_mcp.server import _annotate_tools_by_version
        self._with_versions({"new": "8.0.0", "old": "7.4.14"})
        out = self._names(_annotate_tools_by_version(self.tools, self.mgr))
        self.assertIn("not on 'new' - host.massupdate was removed in Zabbix 8.0", out["host_massupdate"].description)
        self._with_versions({"new": "8.0.0", "old": "8.0.0"})
        self.assertNotIn("host_massupdate", self._names(_annotate_tools_by_version(self.tools, self.mgr)))

    def test_token_scoped_to_one_server_sees_that_server_only(self):
        from zabbix_mcp.server import _annotate_tools_by_version
        from zabbix_mcp.token_store import TokenInfo, current_token_info
        self._with_versions({"new": "7.4.14", "old": "6.0.30"})
        current_token_info.set(TokenInfo(id="t", name="t", token_hash="sha256:x", allowed_servers=["new"]))
        out = self._names(_annotate_tools_by_version(self.tools, self.mgr))
        self.assertNotIn("Zabbix version note", out["proxygroup_get"].description)
        current_token_info.set(TokenInfo(id="t", name="t", token_hash="sha256:x", allowed_servers=["old"]))
        self.assertNotIn("proxygroup_get", self._names(_annotate_tools_by_version(self.tools, self.mgr)))


class TestHealthCheckAndWarmup(unittest.TestCase):
    def test_health_check_lists_version_and_unavailable_tools(self):
        from mcp.server.mcpserver import MCPServer
        cfg = AppConfig(server=ServerConfig(timezone="UTC"), zabbix_servers={"t": ZabbixServerConfig(
            name="t", url="http://localhost", api_token="x")})
        mgr = ClientManager(cfg)
        mcp = MCPServer(name="test")
        _register_tools(mcp, mgr)
        with patch.object(mgr, "check_connection", return_value={}), \
                patch.object(mgr, "get_version", return_value="8.0.0"), \
                patch.object(mgr, "get_zabbix_timezone", return_value="UTC"):
            res = asyncio.run(mcp.call_tool("health_check", {}))
        import json
        body = json.loads("\n".join(c.text for c in res.content if hasattr(c, "text")))
        srv = body["zabbix_servers"]["server_1"]
        self.assertEqual(srv["zabbix_version"], "8.0.0")
        self.assertEqual(srv["unavailable_tools"], ["host_massupdate", "hostgroup_massupdate",
                                                    "hostinterface_create", "hostinterface_delete",
                                                    "hostinterface_massadd", "hostinterface_massremove",
                                                    "hostinterface_replacehostinterfaces", "hostinterface_update",
                                                    "template_massupdate", "templategroup_massupdate"])
        self.assertEqual(srv["deprecated_tools"], ["correlation_create", "correlation_delete",
                                                   "correlation_get", "correlation_update"])

    def test_warm_versions_never_raises_and_fills_the_cache(self):
        cfg = AppConfig(server=ServerConfig(), zabbix_servers={
            "up": ZabbixServerConfig(name="up", url="http://localhost", api_token="x"),
            "down": ZabbixServerConfig(name="down", url="http://localhost", api_token="x"),
        })
        mgr = ClientManager(cfg)

        class _Client:
            def api_version(self):
                return "7.4.14"

        def fake_connect(name):
            if name == "down":
                raise ConnectionError("down")
            return _Client()
        with patch.object(mgr, "_connect", side_effect=fake_connect):
            mgr.warm_versions().join(timeout=5)
        self.assertEqual(mgr.cached_versions(), {"up": "7.4.14"})
        self.assertIn("up", mgr._clients)
        self.assertNotIn("down", mgr._clients)

    def test_warm_up_does_not_hold_the_lock_while_a_server_hangs(self):
        """A black-holed server in the warm-up must not stall the first call to a healthy one."""
        import threading
        import time
        cfg = AppConfig(server=ServerConfig(), zabbix_servers={
            "slow": ZabbixServerConfig(name="slow", url="http://localhost", api_token="x"),
            "fast": ZabbixServerConfig(name="fast", url="http://localhost", api_token="x"),
        })
        mgr = ClientManager(cfg)
        started = threading.Event()

        class _Client:
            def api_version(self):
                return "7.4.14"

        def fake_connect(name):
            if name == "slow":
                started.set()
                time.sleep(1.5)
            return _Client()
        with patch.object(mgr, "_connect", side_effect=fake_connect):
            t = mgr.warm_versions()
            self.assertTrue(started.wait(2))
            t0 = time.perf_counter()
            self.assertEqual(mgr.get_version("fast"), "7.4.14")
            self.assertLess(time.perf_counter() - t0, 0.5)
            t.join(timeout=5)
        self.assertEqual(set(mgr.cached_versions()), {"slow", "fast"})


if __name__ == "__main__":
    unittest.main()
