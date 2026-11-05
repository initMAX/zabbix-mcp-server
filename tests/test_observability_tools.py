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

"""The v1.41 tools: ``apiinfo_version`` (answered from the client's own version
probe, never sent with credentials), the Zabbix 8.0 objects (``apm*``,
``device``, ``serverinfo``), the business ``service_*`` tools with their
measured write contract, and the relative time inputs through a tool."""

import asyncio
import json
import sys
import unittest
from datetime import datetime
from unittest.mock import patch
from zoneinfo import ZoneInfo

sys.path.insert(0, "src")

from zabbix_mcp.api import ALL_METHODS  # noqa: E402
from zabbix_mcp.api.contracts import contract_for  # noqa: E402
from zabbix_mcp.api.versions import METHOD_SINCE  # noqa: E402
from zabbix_mcp.api.write_contracts import strip_for_write  # noqa: E402
from zabbix_mcp.client import ClientManager  # noqa: E402
from zabbix_mcp.config import AppConfig, ServerConfig, ZabbixServerConfig  # noqa: E402
from zabbix_mcp.server import _register_tools  # noqa: E402

NEW_80 = ("apmtrace.get", "apmspan.get", "apmlog.get", "apmmetric.get", "device.get", "device.offboard", "serverinfo.get",
          "ceprule.get", "ceprule.create", "ceprule.update", "ceprule.delete", "ceprule.resettimewindows")


class TestCatalog(unittest.TestCase):
    def test_every_documented_object_has_its_tools(self):
        methods = {m.api_method for m in ALL_METHODS}
        for method in NEW_80 + ("apiinfo.version", "service.get", "service.create", "service.update", "service.delete"):
            with self.subTest(method=method):
                self.assertIn(method, methods)

    def test_8_0_methods_are_dated(self):
        for method in NEW_80:
            self.assertEqual(METHOD_SINCE[method], "8.0")
        self.assertNotIn("apiinfo.version", METHOD_SINCE)
        self.assertNotIn("service.get", METHOD_SINCE)
        self.assertEqual(METHOD_SINCE["hostdashboard.get"], "7.0")
        # module.* answers on 6.0.48 and 6.2.9 although the reference lists it from 6.4
        for m in ("module.get", "module.create", "module.update", "module.delete"):
            self.assertEqual(METHOD_SINCE[m], "6.0")

    def test_get_contracts_cover_the_new_objects(self):
        service = contract_for("service.get")
        self.assertIn("selectChildren", service.selects)
        self.assertEqual(service.selects["selectChildren"].since, "6.0")
        self.assertEqual(service.selects["selectDependencies"].removed, "6.0")
        self.assertEqual(service.params["deep_parentids"].since, "6.0")
        for method in ("apmtrace.get", "apmspan.get", "apmlog.get", "apmmetric.get", "device.get", "serverinfo.get",
                       "ceprule.get", "hostdashboard.get"):
            self.assertIsNotNone(contract_for(method), method)
        cep = contract_for("ceprule.get")
        self.assertEqual(set(cep.selects), {"selectFilter", "selectWindow", "selectOperations"})
        self.assertEqual(cep.sortfield, ("cep_ruleid", "name", "stop", "sortorder", "status"))
        hd = contract_for("hostdashboard.get")
        self.assertIn("hostids", hd.params)
        self.assertEqual(hd.search_props, ("name",))
        self.assertIn("min_duration", contract_for("apmtrace.get").params)
        self.assertEqual(contract_for("device.get").sortfield, ("deviceid", "name"))

    def test_service_write_contract_is_measured(self):
        row = {"serviceid": "1", "name": "svc", "status": "-1", "readonly": "0", "created_at": "1792440000",
               "uuid": "abc", "algorithm": "1", "sortorder": "5", "problem_events": [],
               "parents": [{"serviceid": "2", "name": "parent", "status": "-1", "algorithm": "1"}],
               "tags": [{"tag": "env", "value": "live"}]}
        for version in ("6.0.48", "7.0.30", "7.4.14"):
            params = json.loads(json.dumps(row))
            dropped = strip_for_write("service.update", params, version)
            self.assertEqual(set(params), {"serviceid", "name", "algorithm", "sortorder", "parents", "tags", "uuid"})
            self.assertEqual(params["parents"], [{"serviceid": "2"}])
            self.assertIn("created_at", dropped)
        params = json.loads(json.dumps(row))
        strip_for_write("service.update", params, "6.2.9")
        self.assertNotIn("uuid", params)   # refused on 6.2 only


class TestThroughTools(unittest.TestCase):
    def setUp(self):
        from mcp.server.mcpserver import MCPServer
        cfg = AppConfig(server=ServerConfig(timezone="Europe/Prague"), zabbix_servers={"t": ZabbixServerConfig(
            name="t", url="http://localhost", api_token="x", read_only=False)})
        self.mgr = ClientManager(cfg)
        self.mcp = MCPServer(name="test")
        _register_tools(self.mcp, self.mgr)
        self.names = {t.name for t in self.mcp._tool_manager.list_tools()}

    def _call(self, version, tool, args, result=None):
        sent = []

        def fake_call(server, method, params, *a, **k):
            sent.append((method, params))
            return [] if result is None else result
        with patch.object(self.mgr, "call", side_effect=fake_call), \
                patch.object(self.mgr, "get_version", return_value=version):
            res = asyncio.run(self.mcp.call_tool(tool, args))
        text = "\n".join(c.text for c in res.content if hasattr(c, "text"))
        return res.is_error, text, sent

    def test_tools_are_registered(self):
        for name in ("apiinfo_version", "service_get", "service_create", "service_update", "service_delete",
                     "apmtrace_get", "apmspan_get", "apmlog_get", "apmmetric_get", "device_get", "device_offboard", "serverinfo_get",
                     "ceprule_get", "ceprule_create", "ceprule_update", "ceprule_delete", "ceprule_resettimewindows", "hostdashboard_get"):
            self.assertIn(name, self.names)

    def test_apiinfo_version_never_calls_the_api(self):
        err, text, sent = self._call("7.4.14", "apiinfo_version", {})
        self.assertFalse(err)
        self.assertIn("7.4.14", text)
        self.assertEqual(sent, [])

    def test_8_0_tools_are_refused_below_8_0_and_pass_on_8_0(self):
        cases = {
            "apmtrace_get": {"time_from": "now-1h", "time_till": "now"},
            "device_get": {},
            "device_offboard": {"uuid": "01a15647-6258-791c-b79e-a83823b19a8b"},
            "serverinfo_get": {"serverid": "01a15647-6258-791c-b79e-a83823b19a8b"},
            "ceprule_get": {},
            "ceprule_resettimewindows": {"cep_ruleid": "1"},
        }
        for tool, args in cases.items():
            with self.subTest(tool=tool):
                with self.assertRaises(Exception) as ctx:
                    self._call("7.4.14", tool, args)
                self.assertIn("requires Zabbix 8.0", str(ctx.exception))
                err, _, sent = self._call("8.0.0", tool, args, result={"ok": 1})
                self.assertFalse(err)
                self.assertEqual(len(sent), 1)

    def test_relative_time_reaches_zabbix_as_epoch_in_the_call_zone(self):
        tz = ZoneInfo("Europe/Prague")
        now = datetime(2026, 10, 20, 0, 24, 17, tzinfo=tz)
        with patch("zabbix_mcp.server.datetime", wraps=datetime) as dt:
            dt.now.side_effect = lambda z=None: now.astimezone(z) if z else now.replace(tzinfo=None)
            err, _, sent = self._call("8.0.0", "apmtrace_get", {"time_from": "now-1d/d", "time_till": "now/d", "limit": 5},
                                      result=[])
        self.assertFalse(err)
        params = sent[0][1]
        self.assertEqual(datetime.fromtimestamp(params["time_from"], tz).isoformat(), "2026-10-19T00:00:00+02:00")
        self.assertEqual(datetime.fromtimestamp(params["time_till"], tz).isoformat(), "2026-10-20T23:59:59+02:00")

    def test_service_round_trip_through_the_tools(self):
        row = {"serviceid": "1", "name": "svc", "status": "-1", "readonly": "0", "created_at": "1792440000",
               "algorithm": "1", "sortorder": "5", "weight": "0", "propagation_rule": "0", "propagation_value": "0",
               "description": "", "uuid": "u", "problem_events": [], "parents": [], "children": [],
               "tags": [{"tag": "env", "value": "live"}], "problem_tags": [{"tag": "scope", "operator": "0", "value": "x"}],
               "status_rules": []}
        err, _, sent = self._call("7.4.14", "service_update", {"params": row}, result={"serviceids": ["1"]})
        self.assertFalse(err)
        method, params = sent[0]
        self.assertEqual(method, "service.update")
        for key in ("status", "readonly", "created_at", "problem_events"):
            self.assertNotIn(key, params)
        self.assertEqual(params["tags"], [{"tag": "env", "value": "live"}])
        self.assertEqual(params["uuid"], "u")   # writable on 7.4

    def test_service_delete_takes_ids(self):
        err, _, sent = self._call("7.4.14", "service_delete", {"ids": ["1", "2"]}, result={"serviceids": ["1", "2"]})
        self.assertFalse(err)
        self.assertEqual(sent, [("service.delete", ["1", "2"])])


class TestCepRuleRoundTrip(unittest.TestCase):
    """A CEP rule copied from ceprule_get goes back through ceprule_update:
    the measured strip drops error / eval_formula, the hand rule drops
    formulaid outside a custom expression (in the rule filter and in every
    operation filter) and keeps it with evaltype 3."""

    def _send(self, rule):
        from mcp.server.mcpserver import MCPServer
        cfg = AppConfig(server=ServerConfig(), zabbix_servers={"t": ZabbixServerConfig(
            name="t", url="http://localhost", api_token="x", read_only=False)})
        mgr = ClientManager(cfg); mcp = MCPServer(name="test"); _register_tools(mcp, mgr)
        sent = []
        with patch.object(mgr, "call", side_effect=lambda s, m, p, *a, **k: sent.append(p) or {"cep_ruleids": ["7"]}), \
                patch.object(mgr, "get_version", return_value="8.0.0"):
            asyncio.run(mcp.call_tool("ceprule_update", {"params": rule}))
        return sent[0]

    def test_as_returned_by_get(self):
        rule = {"cep_ruleid": "7", "name": "rt", "stop": "0", "sortorder": "2", "description": "", "status": "0",
                "window_type": "0", "error": "",
                "filter": {"evaltype": "0", "eval_formula": "A", "formula": "",
                           "conditions": [{"type": "3", "operator": "2", "event_name": "probe", "formulaid": "A"}]},
                "window": {"duration": "10m", "capacity": "0", "tags": []},
                "operations": [{"sortorder": "1", "execute_when": "0", "type": "4", "severity": "3",
                                "filter": {"evaltype": "0", "eval_formula": "", "formula": "", "conditions": []}}]}
        sent = self._send(rule)
        self.assertNotIn("error", sent)
        self.assertNotIn("eval_formula", sent["filter"])
        self.assertNotIn("formulaid", sent["filter"]["conditions"][0])
        self.assertNotIn("eval_formula", sent["operations"][0]["filter"])
        self.assertEqual(sent["window"]["duration"], "10m")

    def test_operation_scope_filter_follows_the_same_rule(self):
        # 8.0.0 added scope / scope_filter to an operation; its filter is the same kind
        rule = {"cep_ruleid": "7", "operations": [
            {"sortorder": "1", "type": "11", "execute_when": "3", "tag": "t", "tag_value": "v", "scope": "2",
             "filter": {"evaltype": "0", "eval_formula": "", "formula": "", "conditions": []},
             "scope_filter": {"evaltype": "0", "eval_formula": "A and B", "formula": "",
                              "conditions": [{"type": "25", "operator": "0", "tag": "rt", "formulaid": "A"},
                                             {"type": "33", "operator": "10", "formulaid": "B"}]}},
            {"sortorder": "2", "type": "2", "execute_when": "2", "scope": "1",
             "scope_filter": {"evaltype": "3", "formula": "A", "eval_formula": "A",
                              "conditions": [{"type": "34", "operator": "11", "formulaid": "A"}]}}]}
        sent = self._send(rule)
        first, second = sent["operations"]
        self.assertNotIn("eval_formula", first["scope_filter"])
        self.assertEqual([set(c) for c in first["scope_filter"]["conditions"]],
                         [{"type", "operator", "tag"}, {"type", "operator"}])
        self.assertEqual(first["scope"], "2")
        self.assertNotIn("eval_formula", second["scope_filter"])
        self.assertEqual(second["scope_filter"]["conditions"][0]["formulaid"], "A")   # custom expression

    def test_custom_expression_keeps_formulaid(self):
        rule = {"cep_ruleid": "7", "filter": {"evaltype": 3, "formula": "A and B", "eval_formula": "A and B",
                                               "conditions": [{"type": 3, "operator": 2, "event_name": "x", "formulaid": "A"},
                                                              {"type": 4, "operator": 5, "severity": 1, "formulaid": "B"}]}}
        sent = self._send(rule)
        self.assertEqual([c["formulaid"] for c in sent["filter"]["conditions"]], ["A", "B"])
        self.assertNotIn("eval_formula", sent["filter"])


class TestTelemetryQueryItem(unittest.TestCase):
    """A telemetry query item (8.0, type 24) carries a filter inside ``query``
    that behaves like an LLD filter: ``eval_formula`` is refused, ``formulaid``
    is refused outside a custom expression (verified live on 8.0.0)."""

    def _send(self, tool, item):
        from mcp.server.mcpserver import MCPServer
        cfg = AppConfig(server=ServerConfig(), zabbix_servers={"t": ZabbixServerConfig(
            name="t", url="http://localhost", api_token="x", read_only=False)})
        mgr = ClientManager(cfg); mcp = MCPServer(name="test"); _register_tools(mcp, mgr)
        sent = []
        with patch.object(mgr, "call", side_effect=lambda s, m, p, *a, **k: sent.append(p) or {"itemids": ["1"]}), \
                patch.object(mgr, "get_version", return_value="8.0.0"):
            asyncio.run(mcp.call_tool(tool, {"params": item}))
        return sent[0]

    def test_filter_as_returned_by_get(self):
        item = {"itemid": "1", "query": {"signal_type": "0", "columns": [], "metric_point_type": "0",
                                         "aggregated_columns": [{"function": "4", "alias": "n", "column": "", "parameters": []}],
                                         "filter": {"evaltype": "0", "formula": "", "eval_formula": "A",
                                                    "conditions": [{"column": "ServiceName", "operator": "0", "value": "x",
                                                                    "attribute_key": "", "formulaid": "A"}]}}}
        sent = self._send("item_update", item)
        flt = sent["query"]["filter"]
        self.assertNotIn("eval_formula", flt)
        self.assertNotIn("formulaid", flt["conditions"][0])
        self.assertEqual(flt["conditions"][0]["column"], "ServiceName")

    def test_an_lld_rule_can_be_a_telemetry_query_too(self):
        # 8.0.0 added type 24 to the LLD rule and its prototype (source only, not on
        # the reference page); a live discoveryrule.update refused the query a
        # get had returned: unexpected parameter "eval_formula"
        import copy
        query = {"signal_type": "0", "columns": [], "metric_point_type": "0",
                 "aggregated_columns": [{"function": "4", "alias": "n", "column": "", "parameters": []}],
                 "filter": {"evaltype": "0", "formula": "", "eval_formula": "A",
                            "conditions": [{"column": "ServiceName", "operator": "0", "value": "x",
                                            "attribute_key": "", "formulaid": "A"}]}}
        for tool in ("discoveryrule_update", "discoveryrule_create",
                     "discoveryruleprototype_update", "discoveryruleprototype_create"):
            sent = self._send(tool, {"itemid": "1", "query": copy.deepcopy(query)})
            flt = sent["query"]["filter"]
            self.assertNotIn("eval_formula", flt, tool)
            self.assertNotIn("formulaid", flt["conditions"][0], tool)
        # a custom expression keeps its labels
        custom = copy.deepcopy(query)
        custom["filter"].update(evaltype="3", formula="A and B", eval_formula="A and B")
        custom["filter"]["conditions"].append({"column": "SpanName", "operator": "2", "value": "y",
                                               "attribute_key": "", "formulaid": "B"})
        sent = self._send("discoveryrule_update", {"itemid": "1", "query": custom})
        self.assertNotIn("eval_formula", sent["query"]["filter"])
        self.assertEqual([c["formulaid"] for c in sent["query"]["filter"]["conditions"]], ["A", "B"])
        self.assertEqual(sent["query"]["filter"]["formula"], "A and B")
        self.assertEqual(sent["query"]["aggregated_columns"][0]["alias"], "n")

    def test_custom_expression_and_prototype_and_create(self):
        query = {"signal_type": 0, "columns": [], "aggregated_columns": [{"function": 4, "alias": "n"}],
                 "filter": {"evaltype": 3, "formula": "A and B", "eval_formula": "A and B", "conditions": [
                     {"column": "ServiceName", "operator": 0, "value": "x", "formulaid": "A"},
                     {"column": "SpanName", "operator": 2, "value": "y", "formulaid": "B"}]}}
        for tool, extra in (("item_update", {"itemid": "1"}), ("itemprototype_update", {"itemid": "1"}),
                            ("item_create", {"hostid": "1", "name": "n", "key_": "k", "type": "TELEMETRY_QUERY",
                                             "value_type": "UNSIGNED", "delay": "1m"})):
            with self.subTest(tool=tool):
                sent = self._send(tool, dict(extra, query=json.loads(json.dumps(query))))
                flt = sent["query"]["filter"]
                self.assertNotIn("eval_formula", flt)
                self.assertEqual([c["formulaid"] for c in flt["conditions"]], ["A", "B"])
        self.assertEqual(sent["type"], 24)

    def test_items_without_a_query_are_untouched(self):
        sent = self._send("item_update", {"itemid": "1", "name": "x", "query_fields": [{"name": "a", "value": "b"}]})
        self.assertEqual(sent, {"itemid": "1", "name": "x", "query_fields": [{"name": "a", "value": "b"}]})


class TestHostDashboard(unittest.TestCase):
    def test_refused_below_7_0_and_sent_with_hostids(self):
        from mcp.server.mcpserver import MCPServer
        cfg = AppConfig(server=ServerConfig(), zabbix_servers={"t": ZabbixServerConfig(
            name="t", url="http://localhost", api_token="x", read_only=False)})
        mgr = ClientManager(cfg); mcp = MCPServer(name="test"); _register_tools(mcp, mgr)
        sent = []
        with patch.object(mgr, "call", side_effect=lambda s, m, p, *a, **k: sent.append((m, p)) or []), \
                patch.object(mgr, "get_version", return_value="6.4.21"):
            with self.assertRaises(Exception) as ctx:
                asyncio.run(mcp.call_tool("hostdashboard_get", {"hostids": ["10084"]}))
            self.assertIn("requires Zabbix 7.0", str(ctx.exception))
        with patch.object(mgr, "call", side_effect=lambda s, m, p, *a, **k: sent.append((m, p)) or []), \
                patch.object(mgr, "get_version", return_value="7.4.14"):
            asyncio.run(mcp.call_tool("hostdashboard_get", {"hostids": ["10084"], "extra_params": {"selectPages": "extend"}}))
        self.assertEqual(sent[-1][0], "hostdashboard.get")
        self.assertEqual(sent[-1][1]["hostids"], ["10084"])
        self.assertEqual(sent[-1][1]["selectPages"], "extend")


if __name__ == "__main__":
    unittest.main()
