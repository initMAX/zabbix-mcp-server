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

"""The get contracts as JSON Schema in ``tools/list`` (issue #106).

What a description says a parameter takes, the schema says too: a client
that builds the call from the schema alone (structured output, a JSON
Schema validator) cannot produce ``problem_get(sortfield="clock")``.
"""

import asyncio
import json
import re
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, "src")

import jsonschema  # noqa: E402  (a dependency of the MCP SDK)
from mcp.server.mcpserver import MCPServer  # noqa: E402

from zabbix_mcp.api import ALL_METHODS  # noqa: E402
from zabbix_mcp.api import schema_constraints as sc  # noqa: E402
from zabbix_mcp.api.contracts import (  # noqa: E402
    OBJECTS, GetParamError, contract_for, filter_props, search_props, specialise_params, validate_get_params,
)
from zabbix_mcp.api.versions import parse_version  # noqa: E402
from zabbix_mcp.api.extensions import _parse_period  # noqa: E402
from zabbix_mcp.client import ClientManager  # noqa: E402
from zabbix_mcp.config import AppConfig, ServerConfig, ZabbixServerConfig  # noqa: E402
from zabbix_mcp.server import _PERIOD_SCHEMA, _build_zabbix_params, _register_tools  # noqa: E402

BY_TOOL = {m.tool_name: m for m in ALL_METHODS}
GET_TOOLS = [m for m in ALL_METHODS if contract_for(m.api_method)]


def _catalog(**kwargs):
    cfg = AppConfig(server=ServerConfig(timezone="UTC"),
                    zabbix_servers={"t": ZabbixServerConfig(name="t", url="http://localhost", api_token="x", read_only=False)})
    mgr = ClientManager(cfg)
    mcp = MCPServer(name="test")
    _register_tools(mcp, mgr, **kwargs)
    return mcp, mgr, {t.name: t for t in mcp._tool_manager.list_tools()}


MCP, MGR, TOOLS = _catalog()
_, _, TOOLS_OFF = _catalog(schema_constraints=False)


def _value_schema(tool: str, param: str, tools=TOOLS) -> list[dict]:
    """The non-null branches of an optional parameter's schema."""
    prop = tools[tool].parameters["properties"][param]
    return [b for b in prop.get("anyOf", [prop]) if b.get("type") != "null"]


def _listed_in(description: str, after: str) -> list[str]:
    """The names a description lists after *after*, release markers removed."""
    tail = description.split(after, 1)[1]
    tail = re.sub(r"\s*\([^)]*\)", "", tail)   # (7.0+), (deprecated in 7.4, use X)
    return [n.strip() for n in tail.split(".")[0].split(",") if n.strip()]


def _valid(tool: str, args: dict, tools=TOOLS) -> bool:
    try:
        jsonschema.Draft202012Validator(tools[tool].parameters).validate(args)
        return True
    except jsonschema.ValidationError:
        return False


def _hidden(method, names):
    """Names an enum may carry beyond the description: what left in 6.0 or
    earlier, which a 5.x server still takes and the description no longer lists."""
    contract = contract_for(method.api_method)
    obj = OBJECTS.get(contract.object)
    specs = dict(contract.params)
    specs.update(contract.selects)
    specs.update(contract.sort_specs)
    if obj is not None:
        for name, spec in obj.props.items():
            specs.setdefault(name, spec)
    return all(specs.get(n) is not None and specs[n].removed and parse_version(specs[n].removed) <= (6, 0)
               for n in names)


class TestSchemaIsWhatTheDescriptionSays(unittest.TestCase):
    """Schema and text come from the same contract; this compares the two
    as a client receives them. The enum starts with the names the
    description lists, in its order; anything after that is 5.x only."""

    def _same_or_legacy_tail(self, method, enum, listed, where):
        self.assertEqual(enum[:len(listed)], listed, where)
        self.assertTrue(_hidden(method, enum[len(listed):]), (where, enum[len(listed):]))

    def test_sortfield_enum_is_the_list_in_the_description(self):
        seen = 0
        for m in GET_TOOLS:
            props = TOOLS[m.tool_name].parameters["properties"]
            if "sortfield" not in props or "Sort by one or more of:" not in props["sortfield"]["description"]:
                continue
            text = props["sortfield"]["description"].split(" (a list for several")[0] + "."
            names = _listed_in(text, "Sort by one or more of:")
            one, several = _value_schema(m.tool_name, "sortfield")
            self.assertEqual(one["type"], "string")
            self._same_or_legacy_tail(m, one["enum"], names, m.tool_name)
            self.assertEqual(several["items"]["enum"], one["enum"], m.tool_name)
            seen += 1
        self.assertGreater(seen, 50)

    def test_output_enum_is_the_list_in_the_description(self):
        seen = 0
        for m in GET_TOOLS:
            props = TOOLS[m.tool_name].parameters["properties"]
            if "output" not in props or "Properties:" not in props["output"]["description"]:
                continue
            text = props["output"]["description"]
            names = _listed_in(text, "Properties:")
            words, listed = _value_schema(m.tool_name, "output")
            self._same_or_legacy_tail(m, listed["items"]["enum"], names, m.tool_name)
            self.assertEqual("count" in words["enum"], "'count'" in text, m.tool_name)
            self.assertIn("a list of property names", text)
            self.assertNotIn("comma-separated", text)
            seen += 1
        self.assertGreater(seen, 60)

    def test_filter_and_search_keys_are_the_lists_in_the_description(self):
        seen = 0
        for m in GET_TOOLS:
            props = TOOLS[m.tool_name].parameters["properties"]
            for param in ("filter", "search"):
                text = (props.get(param) or {}).get("description", "")
                marker = "Only these keys are accepted:" if "Only these keys are accepted:" in text else "Keys:"
                if marker not in text:
                    continue
                (branch,) = _value_schema(m.tool_name, param)
                self._same_or_legacy_tail(m, branch["propertyNames"]["enum"], _listed_in(text, marker),
                                          (m.tool_name, param))
                self.assertEqual(branch["type"], "object")
                seen += 1
        self.assertGreater(seen, 100)

    def test_extra_params_keys_cover_the_natives_and_selects_it_describes(self):
        for m in GET_TOOLS:
            props = TOOLS[m.tool_name].parameters["properties"]
            if "extra_params" not in props:
                continue
            text = props["extra_params"]["description"]
            (branch,) = _value_schema(m.tool_name, "extra_params")
            if "propertyNames" not in branch:
                # nothing to pass: said in the text, and closed in the schema
                self.assertEqual(branch, {"type": "object", "additionalProperties": False}, m.tool_name)
                self.assertNotIn("Parameters:", text, m.tool_name)
                continue
            keys = branch["propertyNames"]["enum"]
            for marker in ("Parameters:", "Sub-object selects (value 'extend', 'count' or a list of property names):"):
                if marker in text:
                    for name in _listed_in(text, marker):
                        self.assertIn(name, keys, (m.tool_name, name))
            # nothing the tool types itself: the typed parameter is the place for it
            self.assertFalse(set(keys) & set(props) - {"extra_params"}, m.tool_name)

    def test_every_name_the_schema_offers_passes_validation(self):
        """The schema never offers what ``validate_get_params`` refuses."""
        for m in GET_TOOLS:
            typed = [p.name for p in specialise_params(m)]
            props = TOOLS[m.tool_name].parameters["properties"]
            for param in ("filter", "search"):
                if param in props and "propertyNames" in _value_schema(m.tool_name, param)[0]:
                    for key in _value_schema(m.tool_name, param)[0]["propertyNames"]["enum"]:
                        validate_get_params(m.api_method, {param: {key: "1"}}, None, typed=typed)
            if "sortfield" in props and "enum" in _value_schema(m.tool_name, "sortfield")[0]:
                validate_get_params(
                    m.api_method, {"sortfield": _value_schema(m.tool_name, "sortfield")[0]["enum"]}, None, typed=typed)
            if "output" in props and len(_value_schema(m.tool_name, "output")) == 2:
                validate_get_params(
                    m.api_method, {"output": _value_schema(m.tool_name, "output")[1]["items"]["enum"]}, None, typed=typed)
            if "extra_params" in props and "propertyNames" in _value_schema(m.tool_name, "extra_params")[0]:
                for key in _value_schema(m.tool_name, "extra_params")[0]["propertyNames"]["enum"]:
                    # groupCount is offered for a count and refused without one
                    request = {key: True, "countOutput": True} if key == "groupCount" else {key: "extend"}
                    validate_get_params(m.api_method, request, None, typed=typed)

    def test_the_schema_is_never_narrower_than_the_validation(self):
        """The other direction: whatever the server lets through on some
        release, the schema lets through as well. A schema that refused a
        legitimate call would be worse than no schema."""
        for m in GET_TOOLS:
            contract = contract_for(m.api_method)
            obj = OBJECTS.get(contract.object)
            props = TOOLS[m.tool_name].parameters["properties"]
            where = m.tool_name
            if "sortfield" in props and contract.sortfield:
                self.assertEqual(set(_value_schema(m.tool_name, "sortfield")[0]["enum"]), set(contract.sortfield), where)
            if "output" in props and obj is not None and len(_value_schema(m.tool_name, "output")) == 2:
                takes = {p.name for p in obj.props.values() if not p.no_output}
                self.assertEqual(set(_value_schema(m.tool_name, "output")[1]["items"]["enum"]), takes, where)
            for param, pick in (("filter", filter_props), ("search", search_props)):
                if param in props and "propertyNames" in _value_schema(m.tool_name, param)[0]:
                    self.assertEqual(set(_value_schema(m.tool_name, param)[0]["propertyNames"]["enum"]),
                                     {p.name for p in pick(contract)}, (where, param))
            if "extra_params" in props:
                # every key the handler forwards and the validation knows, minus the typed ones
                takes = (set(contract.common) | set(contract.params) | set(contract.selects)) - set(props)
                (branch,) = _value_schema(m.tool_name, "extra_params")
                offered = set(branch["propertyNames"]["enum"]) if "propertyNames" in branch else set()
                self.assertEqual(offered, takes, where)


class TestAsAClientSeesIt(unittest.TestCase):
    def test_every_tool_schema_is_valid_json_schema(self):
        for name, tool in TOOLS.items():
            jsonschema.Draft202012Validator.check_schema(tool.parameters)
            json.dumps(tool.parameters)   # the hook left nothing unserialisable behind

    def test_no_combinator_at_the_top_level(self):
        """Several model APIs refuse ``anyOf`` / ``oneOf`` / ``allOf`` at the
        top level of a tool's input schema; "one of two arguments" stays text."""
        for name, tool in TOOLS.items():
            self.assertFalse({"anyOf", "oneOf", "allOf", "not", "$ref", "$defs"} & set(tool.parameters), name)
            self.assertEqual(tool.parameters.get("type"), "object", name)

    def test_the_call_from_the_issue_is_refused_by_the_schema(self):
        self.assertFalse(_valid("problem_get", {"sortfield": "clock", "sortorder": "ASC"}))
        self.assertTrue(_valid("problem_get", {"sortfield": "eventid", "sortorder": "ASC"}))
        self.assertFalse(_valid("problem_get", {"sortorder": "ascending"}))

    def test_output_filter_search_extra_params(self):
        self.assertTrue(_valid("problem_get", {"output": "extend"}))
        self.assertTrue(_valid("problem_get", {"output": "count"}))
        self.assertTrue(_valid("problem_get", {"output": ["eventid", "name", "severity"]}))
        self.assertFalse(_valid("problem_get", {"output": ["eventid", "hostname"]}))
        self.assertFalse(_valid("problem_get", {"output": "eventid,name"}))
        self.assertFalse(_valid("problem_get", {"output": []}))
        self.assertTrue(_valid("problem_get", {"filter": {"severity": [4, 5]}}))
        self.assertFalse(_valid("problem_get", {"filter": {"hostname": "web"}}))
        self.assertTrue(_valid("problem_get", {"search": {"name": "disk"}}))
        self.assertFalse(_valid("problem_get", {"search": {"severity": "4"}}))
        self.assertTrue(_valid("problem_get", {"extra_params": {"selectTags": "extend", "severities": [4, 5]}}))
        self.assertFalse(_valid("problem_get", {"extra_params": {"selectHosts": "extend"}}))
        self.assertTrue(_valid("host_get", {"sortfield": ["name", "status"], "output": ["hostid", "host"]}))
        self.assertFalse(_valid("host_get", {"sortfield": ["name", "lastaccess"]}))
        # a list is fine also where only one field sorts, and one order per field
        self.assertTrue(_valid("problem_get", {"sortfield": ["eventid"]}))
        self.assertTrue(_valid("host_get", {"sortfield": ["name", "status"], "sortorder": ["ASC", "DESC"]}))
        self.assertFalse(_valid("host_get", {"sortorder": ["ASC", "down"]}))
        # a method with nothing beyond its typed parameters takes no extra key at all
        self.assertTrue(_valid("trend_get", {"extra_params": {}}))
        self.assertFalse(_valid("trend_get", {"extra_params": {"selectHosts": "extend"}}))
        # a name only a 5.x server takes is not refused by the schema
        self.assertTrue(_valid("host_get", {"extra_params": {"selectApplications": "extend"}}))
        # null stays allowed: every one of them is optional
        self.assertTrue(_valid("problem_get", {"sortfield": None, "output": None, "filter": None}))

    def test_typed_integer_with_a_documented_value_set(self):
        self.assertEqual(_value_schema("history_get", "history"), [{"type": "integer", "enum": [0, 1, 2, 3, 4, 5, 6]}])
        self.assertFalse(_valid("history_get", {"history": 9}))
        self.assertTrue(_valid("history_get", {"history": 0}))

    def test_single_object_methods_do_not_offer_count(self):
        for tool in ("settings_get", "housekeeping_get", "authentication_get", "task_get"):
            words = _value_schema(tool, "output")[0]
            self.assertEqual(words["enum"], ["extend"], tool)
            self.assertNotIn("'count'", TOOLS[tool].parameters["properties"]["output"]["description"], tool)
        self.assertEqual(_value_schema("trend_get", "output")[0]["enum"], ["extend", "count"])   # has countOutput


class TestTheServerStaysLenient(unittest.TestCase):
    """The listed schema is stricter than the handler: what callers sent
    before still works."""

    def test_string_and_list_forms_build_the_same_request(self):
        host_get = BY_TOOL["host_get"]
        as_text = _build_zabbix_params(host_get, {"output": "hostid,name", "sortfield": "name,hostid"}, "7.4.0")
        as_list = _build_zabbix_params(host_get, {"output": ["hostid", "name"], "sortfield": ["name", "hostid"]}, "7.4.0")
        self.assertEqual(as_text, as_list)
        self.assertEqual(as_list["output"], ["hostid", "name"])
        self.assertEqual(as_list["sortfield"], ["name", "hostid"])

    def test_both_forms_reach_zabbix_through_the_tool(self):
        sent = []
        with patch.object(MGR, "call", side_effect=lambda s, m, p, *a, **k: sent.append((m, p)) or []), \
                patch.object(MGR, "get_version", return_value="7.4.14"):
            asyncio.run(MCP.call_tool("host_get", {"output": ["hostid", "name"], "sortfield": ["name", "status"]}))
            asyncio.run(MCP.call_tool("host_get", {"output": "hostid,name", "sortfield": "name", "sortorder": "DESC"}))
        self.assertEqual(sent[0][1]["output"], ["hostid", "name"])
        self.assertEqual(sent[0][1]["sortfield"], ["name", "status"])
        self.assertEqual(sent[1][1]["output"], ["hostid", "name"])

    def test_a_list_is_validated_like_a_string(self):
        with patch.object(MGR, "call", return_value=[]), patch.object(MGR, "get_version", return_value="7.4.14"):
            with self.assertRaises(Exception) as ctx:
                asyncio.run(MCP.call_tool("problem_get", {"sortfield": ["clock"]}))
        self.assertIn("cannot sort by clock", str(ctx.exception))
        with self.assertRaises(GetParamError):
            validate_get_params("host.get", {"output": ["hostid", "nosuch"]}, "7.4.0")


class TestOutputCount(unittest.TestCase):
    """Zabbix has no ``output="count"``: 37 get methods of 8.0.0 answer
    'value must be "extend"', the rest read it as a property name and return
    bare IDs. The number of matches is ``countOutput``."""

    def test_count_is_sent_as_countoutput(self):
        for tool in ("host_get", "problem_get", "trend_get", "user_get"):
            params = _build_zabbix_params(BY_TOOL[tool], {"output": "count"}, "8.0.0")
            self.assertIs(params.get("countOutput"), True, tool)
            self.assertNotIn("output", params, tool)

    def test_count_keeps_the_rest_of_the_request(self):
        params = _build_zabbix_params(BY_TOOL["host_get"], {"output": "count", "filter": {"status": 0}}, "8.0.0")
        self.assertEqual(params, {"countOutput": True, "filter": {"status": 0}})

    def test_a_method_without_countoutput_says_so(self):
        for tool in ("settings_get", "task_get"):
            with self.assertRaises(ValueError) as ctx:
                _build_zabbix_params(BY_TOOL[tool], {"output": "count"}, "8.0.0")
            self.assertIn("cannot count", str(ctx.exception))

    def test_through_the_tool(self):
        sent = []
        with patch.object(MGR, "call", side_effect=lambda s, m, p, *a, **k: sent.append((m, p)) or "7"), \
                patch.object(MGR, "get_version", return_value="8.0.0"):
            asyncio.run(MCP.call_tool("host_get", {"output": "count"}))
        self.assertEqual(sent[0], ("host.get", {"countOutput": True}))

    def test_count_wins_over_a_countoutput_false_sent_along(self):
        # asked for in so many words; without this the request went out with
        # neither and Zabbix answered with every row
        params = _build_zabbix_params(BY_TOOL["problem_get"], {"output": "count", "countOutput": False}, "8.0.0")
        self.assertIs(params["countOutput"], True)
        self.assertNotIn("output", params)

    def test_count_of_monitored_problems_counts_after_the_filter(self):
        """problem_get(monitored=true) drops problems of disabled triggers and
        hosts after the call; a count taken by Zabbix would include them."""
        sent = []

        def fake_call(server, method, params, *a, **k):
            sent.append((method, params))
            if method == "problem.get":
                return [{"eventid": "1", "objectid": "11"}, {"eventid": "2", "objectid": "12"},
                        {"eventid": "3", "objectid": "13"}]
            if method == "trigger.get":   # trigger 12 is disabled, 13 sits on a disabled host
                return [{"triggerid": "11", "status": "0", "hosts": [{"hostid": "1", "host": "a", "name": "a", "status": "0"}]},
                        {"triggerid": "13", "status": "0", "hosts": [{"hostid": "3", "host": "c", "name": "c", "status": "1"}]}]
            return []

        with patch.object(MGR, "call", side_effect=fake_call), patch.object(MGR, "get_version", return_value="8.0.0"):
            for args in ({"output": "count", "monitored": True}, {"countOutput": True, "monitored": True, "limit": 2}):
                sent.clear()
                result = asyncio.run(MCP.call_tool("problem_get", dict(args, raw_json=False)))
                text = "".join(getattr(c, "text", "") for c in getattr(result, "content", result))
                self.assertEqual(text.strip().splitlines()[-1].strip('"'), "1", args)
                method, params = sent[0]
                self.assertEqual(method, "problem.get")
                self.assertNotIn("countOutput", params)
                self.assertNotIn("limit", params)          # a count is of all of them
                self.assertEqual(params["output"], ["eventid", "objectid"])
            # without the flag Zabbix counts, as before
            sent.clear()
            asyncio.run(MCP.call_tool("problem_get", {"output": "count"}))
            self.assertEqual(sent[0][1], {"countOutput": True})
            # monitored with an output that leaves objectid out: the filter needs
            # it (the result used to be empty); asked for, used, taken out again
            sent.clear()
            result = asyncio.run(MCP.call_tool("problem_get", {"monitored": True, "output": ["eventid"], "raw_json": False}))
            text = "".join(getattr(c, "text", "") for c in getattr(result, "content", result))
            self.assertEqual(sent[0][1]["output"], ["eventid", "objectid"])
            rows = json.loads(text.split("\n", 1)[1])   # after the [System: ...] line
            self.assertEqual(rows, [{"eventid": "1"}])
            # asked for by the caller, it stays
            result = asyncio.run(MCP.call_tool("problem_get", {"monitored": True, "output": ["eventid", "objectid"]}))
            text = "".join(getattr(c, "text", "") for c in getattr(result, "content", result))
            self.assertIn('"objectid"', text)


class TestExtensionTools(unittest.TestCase):
    def test_item_threshold_search_carries_the_item_contract(self):
        item = contract_for("item.get")
        words, listed = _value_schema("item_threshold_search", "output")
        self.assertEqual(words["enum"], ["extend"])   # the tool counts itself and refuses 'count'
        self.assertEqual(listed["items"]["enum"], sc.output_schema(item)["anyOf"][1]["items"]["enum"])
        self.assertEqual(_value_schema("item_threshold_search", "filter")[0], sc.filter_schema(item))
        self.assertEqual(_value_schema("item_threshold_search", "search")[0], sc.search_schema(item))
        keys = _value_schema("item_threshold_search", "extra_params")[0]["propertyNames"]["enum"]
        self.assertIn("selectHosts", keys)
        # the tool types neither of these, so extra_params is where they go ...
        for key in ("limit", "sortfield", "sortorder", "searchWildcardsEnabled"):
            self.assertIn(key, keys)
        # ... and it cannot work with a count or a keyed result
        for key in ("countOutput", "preservekeys", "groupCount", "search", "filter", "hostids", "output"):
            self.assertNotIn(key, keys)
        self.assertTrue(_valid("item_threshold_search", {"output": ["itemid", "key_"], "search": {"key_": "pused"},
                                                         "extra_params": {"limit": 500}}))
        self.assertFalse(_valid("item_threshold_search", {"search": {"hostname": "web"}}))
        self.assertFalse(_valid("item_threshold_search", {"extra_params": {"countOutput": True}}))

    def test_item_threshold_search_refuses_what_it_cannot_work_with(self):
        from zabbix_mcp.api.extensions import item_threshold_search
        with patch.object(MGR, "call", return_value="7") as call:
            for key in ("countOutput", "preservekeys"):
                out = json.loads(item_threshold_search(MGR, "t", extra_params={key: True}, lastvalue_ge=1))
                self.assertIn(f"extra_params '{key}' is not supported", out["error"])
        call.assert_not_called()

    def test_item_threshold_search_takes_a_list_of_properties(self):
        from zabbix_mcp.api.extensions import item_threshold_search
        sent = []
        with patch.object(MGR, "call", side_effect=lambda s, m, p, *a, **k: sent.append(p) or []):
            item_threshold_search(MGR, "t", output=["itemid", "name"], lastvalue_ge=80)
            item_threshold_search(MGR, "t", output="itemid, name", lastvalue_ge=80)
            item_threshold_search(MGR, "t", lastvalue_ge=80)
        self.assertEqual(sent[0]["output"], ["itemid", "name", "lastvalue"])
        self.assertEqual(sent[1]["output"], ["itemid", "name", "lastvalue"])
        self.assertEqual(sent[2]["output"], ["itemid", "name", "key_", "lastvalue"])

    def test_problem_active_get_sort(self):
        self.assertEqual(_value_schema("problem_active_get", "sortfield"), [{"type": "string", "enum": ["eventid"]}])
        self.assertEqual(_value_schema("problem_active_get", "sortorder"), [sc.SORTORDER_ONE])
        self.assertFalse(_valid("problem_active_get", {"sortfield": "clock"}))

    def test_period_pattern_is_what_the_parser_takes(self):
        pattern = re.compile(_PERIOD_SCHEMA["pattern"])
        for value in ("1h", "6h", "1d", "7d", "30d", "90d", "3m", "2H", " 7d", "7d ", "0d", "7 d", "1w", "d", "7",
                      "1h30m", "-1d", ""):
            try:
                _parse_period(value)
                parses = True
            except ValueError:
                parses = False
            if value == "0d":   # well-formed, refused for its value
                self.assertTrue(pattern.match(value))
                continue
            self.assertEqual(bool(pattern.match(value)), parses, value)
        for tool in ("graph_render", "anomaly_detect", "capacity_forecast", "item_history_summary_get"):
            self.assertEqual(_value_schema(tool, "period"), [_PERIOD_SCHEMA], tool)


class TestIdentifiersAreNotGuessed(unittest.TestCase):
    """What has to be resolved before the call is said where a planner reads
    it (issue #106, parts 1 and 5)."""

    def _text(self, tool: str) -> str:
        t = TOOLS[tool]
        return (t.description or "") + " " + json.dumps(t.parameters)

    def test_item_keys_come_from_item_get(self):
        for tool in ("item_history_summary_get", "anomaly_detect", "capacity_forecast", "item_threshold_search"):
            text = self._text(tool)
            self.assertIn("item_get", text, tool)
            self.assertIn("key_", text, tool)
        for tool in ("item_history_summary_get", "anomaly_detect", "capacity_forecast"):
            self.assertIn("never an invented one", self._text(tool), tool)

    def test_history_and_trend_say_where_item_ids_come_from(self):
        for tool in ("history_get", "trend_get"):
            self.assertIn("item_get", TOOLS[tool].description, tool)
            self.assertIn("never guessed", TOOLS[tool].parameters["properties"]["itemids"]["description"], tool)
        self.assertIn("value_type", TOOLS["history_get"].description)

    def test_one_of_two_arguments_is_stated(self):
        props = TOOLS["hostgroup_overview_get"].parameters["properties"]
        self.assertIn("One of groupid or group", props["groupid"]["description"])
        self.assertIn("no hostgroup_get call is needed", props["group"]["description"])
        self.assertIn("One of host_id or host", TOOLS["host_status_get"].parameters["properties"]["host_id"]["description"])
        self.assertIn("Either itemid or (host + key)", TOOLS["item_history_summary_get"].parameters["properties"]["itemid"]["description"])


class TestSwitch(unittest.TestCase):
    """[server].schema_constraints = false: plain types, as before."""

    def test_off_keeps_plain_types_and_the_old_wording(self):
        plain = [{"type": "string"}]
        self.assertEqual(_value_schema("problem_get", "sortfield", TOOLS_OFF), plain)
        self.assertEqual(_value_schema("problem_get", "sortorder", TOOLS_OFF), plain)
        self.assertEqual(_value_schema("problem_get", "output", TOOLS_OFF), plain)
        self.assertEqual(_value_schema("capacity_forecast", "period", TOOLS_OFF), plain)
        self.assertEqual(_value_schema("problem_active_get", "sortfield", TOOLS_OFF), plain)
        self.assertEqual(_value_schema("history_get", "history", TOOLS_OFF), [{"type": "integer"}])
        for param in ("filter", "search", "extra_params"):
            self.assertEqual(_value_schema("problem_get", param, TOOLS_OFF), [{"additionalProperties": True, "type": "object"}])
        text = TOOLS_OFF["problem_get"].parameters["properties"]
        self.assertIn("comma-separated list of property names", text["output"]["description"])
        self.assertIn("comma-separated for several", text["sortfield"]["description"])
        self.assertTrue(_valid("problem_get", {"sortfield": "clock"}, TOOLS_OFF))

    def test_off_leaves_no_constraint_keyword_in_the_catalog(self):
        dump = json.dumps([t.parameters for t in TOOLS_OFF.values()])
        for keyword in ("propertyNames", '"pattern"', '"enum"', '"minItems"', '"additionalProperties": false'):
            self.assertNotIn(keyword, dump)

    def test_off_is_the_catalog_as_it_was_for_the_extension_tools_too(self):
        props = TOOLS_OFF["item_threshold_search"].parameters["properties"]
        self.assertEqual(_value_schema("item_threshold_search", "output", TOOLS_OFF), [{"type": "string"}])
        self.assertEqual(props["output"]["default"], "itemid,name,key_,lastvalue")
        self.assertIn("comma-separated names", props["output"]["description"])
        for param in ("filter", "search", "extra_params"):
            self.assertEqual(_value_schema("item_threshold_search", param, TOOLS_OFF),
                             [{"additionalProperties": True, "type": "object"}])
        # no parameter takes a list of names where it took a string
        for name, tool in TOOLS_OFF.items():
            for param in ("output", "sortfield", "sortorder"):
                if param in tool.parameters["properties"]:
                    self.assertEqual(_value_schema(name, param, TOOLS_OFF), [{"type": "string"}], (name, param))

    def test_same_tools_either_way(self):
        self.assertEqual(set(TOOLS), set(TOOLS_OFF))
        for name in TOOLS:
            self.assertEqual(set(TOOLS[name].parameters["properties"]), set(TOOLS_OFF[name].parameters["properties"]), name)

    def test_config(self):
        import tempfile
        import textwrap
        from zabbix_mcp.config import ConfigError, load_config

        def load(line: str):
            with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as f:
                f.write(textwrap.dedent(f"""
                    [server]
                    {line}
                    [zabbix.t]
                    url = "http://localhost"
                    api_token = "x"
                """))
            return load_config(f.name)

        self.assertTrue(load("").server.schema_constraints)
        self.assertFalse(load("schema_constraints = false").server.schema_constraints)
        with self.assertRaises(ConfigError):
            load('schema_constraints = "no"')


if __name__ == "__main__":
    unittest.main()
