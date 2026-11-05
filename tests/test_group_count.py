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

"""``groupCount``: a count split by the ID filter of the request.

Not on the reference pages, in the option table of two dozen ``get`` classes
and used by the frontend itself: ``item.get`` with ``countOutput``,
``groupCount`` and ``hostids`` answers one row per host with ``rowscount``.
Until 1.41 the tools refused it as "not a parameter of item.get; Zabbix would
silently ignore it", which is not what Zabbix does. The methods that take it
are the ones the source names and a live server honours on 6.0 to 8.0
(``scripts/audit_api_sources.py``); the validated methods refuse it.
"""

import asyncio
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from zabbix_mcp.api import ALL_METHODS  # noqa: E402
from zabbix_mcp.api.contracts import (  # noqa: E402
    CONTRACTS, GROUP_COUNT, GetParamError, contract_for, specialise_params, validate_get_params,
)
from zabbix_mcp.client import ClientManager  # noqa: E402
from zabbix_mcp.config import AppConfig, ServerConfig, ZabbixServerConfig  # noqa: E402
from zabbix_mcp.server import ZabbixMCPServer, _build_zabbix_params, _register_tools  # noqa: E402

TOOLS = {m.tool_name: m for m in ALL_METHODS}

# a list comes back instead of a number: measured on 6.0.48, 6.2.9, 6.4.21,
# 7.0.30, 7.2.15, 7.4.14 and 8.0.0 (discoveryruleprototype.get on the two
# releases that have it, 7.4.14 and 8.0.0)
ON_EVERY_RELEASE = {
    "alert.get", "correlation.get", "dcheck.get", "dhost.get", "discoveryrule.get",
    "discoveryruleprototype.get", "drule.get", "dservice.get", "graph.get", "graphprototype.get",
    "host.get", "hostinterface.get", "hostprototype.get", "httptest.get", "item.get",
    "itemprototype.get", "maintenance.get", "mediatype.get", "template.get", "templatedashboard.get",
    "trigger.get", "triggerprototype.get",
}
UNTIL = {"hostgroup.get": "6.2", "event.get": "7.0"}   # validated from that release on: refused
FROM = {"hostdashboard.get": "7.0"}


def _count(method: str, version: str, **params) -> None:
    validate_get_params(method, dict(params, countOutput=True, groupCount=True), version, typed=list(params))


class TestWhichMethodsTakeIt(unittest.TestCase):
    def test_the_measured_set_and_nothing_else(self):
        have = {c.method for c in CONTRACTS.values() if GROUP_COUNT in c.params}
        self.assertEqual(have, ON_EVERY_RELEASE | set(UNTIL) | set(FROM))

    def test_it_is_a_switch_without_a_release_where_it_always_works(self):
        for method in ON_EVERY_RELEASE:
            spec = contract_for(method).params[GROUP_COUNT]
            self.assertEqual((spec.type, spec.since, spec.removed), ("flag", None, None), method)
            self.assertIn("countOutput", contract_for(method).common, method)

    def test_the_two_methods_that_started_to_validate_their_input(self):
        _count("hostgroup.get", "6.0.48")
        with self.assertRaisesRegex(GetParamError, "removed in Zabbix 6.2"):
            _count("hostgroup.get", "6.2.9")
        _count("event.get", "6.4.21")
        with self.assertRaisesRegex(GetParamError, "removed in Zabbix 7.0"):
            _count("event.get", "7.0.30")

    def test_a_method_that_ignores_or_refuses_it_does_not_offer_it(self):
        # action.get and usermacro.get return the plain number, problem.get
        # and history.get answer 'unexpected parameter "groupCount"'
        for method in ("action.get", "usermacro.get", "usergroup.get", "problem.get", "history.get", "user.get"):
            with self.assertRaisesRegex(GetParamError, "is not a parameter of"):
                _count(method, "8.0.0")


class TestTheRequest(unittest.TestCase):
    def test_a_grouped_count(self):
        params = _build_zabbix_params(
            TOOLS["item_get"], {"output": "count", "hostids": ["10084"], "extra_params": {"groupCount": True}}, "8.0.0")
        self.assertIs(params["countOutput"], True)
        self.assertIs(params["groupCount"], True)
        self.assertEqual(params["hostids"], ["10084"])
        self.assertNotIn("output", params)
        self.assertNotIn("sortfield", params)
        validate_get_params("item.get", params, "8.0.0", typed=["hostids"])

    def test_false_is_not_sent(self):
        # a Zabbix switch: present is on
        params = _build_zabbix_params(TOOLS["item_get"], {"extra_params": {"groupCount": False}}, "8.0.0")
        self.assertNotIn("groupCount", params)

    def test_without_a_count_it_is_refused(self):
        # 8.0 answers "Database error occurred." and 6.0 an empty list
        params = _build_zabbix_params(TOOLS["item_get"], {"hostids": ["10084"], "extra_params": {"groupCount": True}}, "8.0.0")
        with self.assertRaisesRegex(GetParamError, "pass output='count'"):
            validate_get_params("item.get", params, "8.0.0", typed=["hostids"])

    def test_a_count_is_true_and_nothing_else(self):
        # PHP reads countOutput "0" as off; the grouped query would go out without the count
        for count in ("0", 0, "", None, "false", 1, "1"):
            with self.assertRaisesRegex(GetParamError, "pass output='count'", msg=repr(count)):
                validate_get_params("item.get", {"countOutput": count, "groupCount": True, "hostids": ["1"]},
                                    "8.0.0", typed=["hostids"])
        validate_get_params("item.get", {"countOutput": True, "groupCount": True}, "8.0.0", typed=[])

    def test_the_refusal_says_what_zabbix_would_do_with_it(self):
        # measured: ignored without an ID filter, a database error (8.0) or an empty list (6.0) with one
        with self.assertRaises(GetParamError) as refused:
            validate_get_params("item.get", {"groupCount": True}, "8.0.0", typed=[])
        self.assertIn("Zabbix ignores it or, next to an ID filter, answers with a database error or an empty list",
                      str(refused.exception))

    def test_the_rows_come_back_as_zabbix_sent_them(self):
        cfg = AppConfig(server=ServerConfig(timezone="UTC"),
                        zabbix_servers={"t": ZabbixServerConfig(name="t", url="http://localhost", api_token="x")})
        mgr = ClientManager(cfg)
        mcp = ZabbixMCPServer(name="test")
        _register_tools(mcp, mgr)
        rows = [{"rowscount": "302", "hostid": "10084"}, {"rowscount": "11", "hostid": "10710"}]
        sent = []
        with patch.object(mgr, "call", side_effect=lambda s, m, p, *a, **k: sent.append((m, p)) or rows), \
                patch.object(mgr, "get_version", return_value="8.0.0"):
            result = asyncio.run(mcp.call_tool(
                "item_get", {"output": "count", "hostids": ["10084", "10710"], "extra_params": {"groupCount": True}}))
        self.assertEqual(sent[0][0], "item.get")
        self.assertIs(sent[0][1]["groupCount"], True)
        self.assertFalse(result.is_error)
        # after the line that marks the answer as data
        self.assertEqual(json.loads(result.content[0].text.split("\n", 1)[1]), rows)


class TestItemThresholdSearch(unittest.TestCase):
    """The tool reads item rows: it cannot count, so it does not offer a grouped count."""

    @classmethod
    def setUpClass(cls):
        cfg = AppConfig(server=ServerConfig(timezone="UTC"),
                        zabbix_servers={"t": ZabbixServerConfig(name="t", url="http://localhost", api_token="x")})
        cls.mgr = ClientManager(cfg)
        cls.mcp = ZabbixMCPServer(name="test")
        _register_tools(cls.mcp, cls.mgr)
        cls.tool = {t.name: t for t in cls.mcp._tool_manager.list_tools()}["item_threshold_search"]

    def _call(self, args, mcp=None, mgr=None):
        from mcp.server.mcpserver.exceptions import ToolError
        mcp, mgr = mcp or self.mcp, mgr or self.mgr
        sent = []
        with patch.object(mgr, "call", side_effect=lambda s, m, p, *a, **k: sent.append((m, p)) or [{"itemid": "1", "lastvalue": "5"}]), \
                patch.object(mgr, "get_version", return_value="8.0.0"):
            try:
                asyncio.run(mcp.call_tool("item_threshold_search", args))
            except ToolError as error:
                return sent, str(error)
        return sent, None

    def test_it_is_not_offered(self):
        extra = self.tool.parameters["properties"]["extra_params"]
        self.assertNotIn("groupCount", json.dumps(extra))
        self.assertIn('"webitems"', json.dumps(extra))

    def test_it_is_refused_with_the_tool_s_own_reason(self):
        # not with "pass output='count'", which this tool cannot do either
        sent, error = self._call({"lastvalue_gt": 0, "hostids": ["10084"], "extra_params": {"groupCount": True}})
        self.assertEqual(sent, [])
        self.assertIn("extra_params 'groupCount' is not supported by item_threshold_search", error)
        self.assertNotIn("output='count'", error)

    def test_nor_does_it_get_through_with_the_validation_switched_off(self):
        cfg = AppConfig(server=ServerConfig(timezone="UTC"),
                        zabbix_servers={"t": ZabbixServerConfig(name="t", url="http://localhost", api_token="x")})
        mgr = ClientManager(cfg)
        mcp = ZabbixMCPServer(name="test")
        _register_tools(mcp, mgr, validate_get=False)
        sent, error = self._call({"lastvalue_gt": 0, "hostids": ["10084"], "extra_params": {"groupCount": True}}, mcp, mgr)
        self.assertEqual(sent, [])
        self.assertIn("not supported by item_threshold_search", error)

    def test_a_false_switch_is_left_out_as_the_description_says(self):
        # item.get reads webitems as "present": false would add the web items
        self.assertIn("false is the same as leaving it out", self.tool.parameters["properties"]["extra_params"]["description"])
        sent, error = self._call({"lastvalue_gt": 0, "extra_params": {"webitems": False, "limit": 5}})
        self.assertIsNone(error)
        self.assertNotIn("webitems", sent[0][1])
        self.assertEqual(sent[0][1]["limit"], 5)
        sent, error = self._call({"lastvalue_gt": 0, "extra_params": {"webitems": True}})
        self.assertIs(sent[0][1]["webitems"], True)
        # 0 is the same "no" (the get tools drop it too)
        sent, error = self._call({"lastvalue_gt": 0, "extra_params": {"webitems": 0}})
        self.assertNotIn("webitems", sent[0][1])
        # a boolean keeps its false
        sent, error = self._call({"lastvalue_gt": 0, "extra_params": {"templated": False}})
        self.assertIs(sent[0][1]["templated"], False)

    def test_a_refused_key_is_not_offered_in_the_hint_of_another(self):
        sent, error = self._call({"lastvalue_gt": 0, "extra_params": {"selectFoo": "extend"}})
        self.assertEqual(sent, [])
        self.assertIn("'selectFoo' is not a parameter of item.get", error)
        for key in ("countOutput", "preservekeys", "groupCount"):
            self.assertNotIn(key, error)
        self.assertIn("webitems", error)


class TestWhatAClientIsTold(unittest.TestCase):
    @staticmethod
    def _extra(tool: str) -> str:
        return next(p.description for p in specialise_params(TOOLS[tool]) if p.name == "extra_params")

    def test_the_description_says_what_it_needs_and_returns(self):
        text = self._extra("item_get")
        self.assertIn("groupCount goes with output='count'", text)
        self.assertIn("one row per ID with 'rowscount'", text)
        self.assertIn("groupCount (removed in 7.0) goes with output='count'", self._extra("event_get"))
        self.assertNotIn("groupCount", self._extra("action_get"))

    def test_the_schema_lists_it_as_a_key_of_extra_params(self):
        cfg = AppConfig(server=ServerConfig(timezone="UTC"),
                        zabbix_servers={"t": ZabbixServerConfig(name="t", url="http://localhost", api_token="x")})
        mcp = ZabbixMCPServer(name="test")
        _register_tools(mcp, ClientManager(cfg))
        schema = {t.name: json.dumps(t.parameters["properties"]["extra_params"])
                  for t in mcp._tool_manager.list_tools() if "extra_params" in t.parameters.get("properties", {})}
        self.assertIn('"groupCount"', schema["item_get"])
        self.assertIn('"groupCount"', schema["host_get"])
        self.assertNotIn('"groupCount"', schema["action_get"])
        self.assertNotIn('"groupCount"', schema["problem_get"])


if __name__ == "__main__":
    unittest.main()
