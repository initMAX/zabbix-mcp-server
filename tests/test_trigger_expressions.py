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

"""A trigger read with ``trigger_get`` and sent back keeps its user macros.

v1.40 and v1.41 asked Zabbix to expand the expression (``expandExpression``),
and Zabbix expands the user macros with it: ``avg(/h/k,10m)>{$UTIL.MAX}`` came
back as ``avg(/h/k,10m)>75`` and went back into Zabbix that way. The server
now builds the editable form itself, from the stored expression and the
trigger's functions, and leaves the macros where they are.
"""

import asyncio
import copy
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from zabbix_mcp.api import trigger_expressions as te  # noqa: E402
from zabbix_mcp.client import ClientManager  # noqa: E402
from zabbix_mcp.config import AppConfig, ServerConfig, ZabbixServerConfig  # noqa: E402
from zabbix_mcp.server import ZabbixMCPServer, _register_tools  # noqa: E402

FUNCTIONS = {
    "33791": {"functionid": "33791", "itemid": "22183", "function": "avg", "parameter": "$,10m"},
    "33792": {"functionid": "33792", "itemid": "22184", "function": "last", "parameter": "$"},
    "33793": {"functionid": "33793", "itemid": "22183", "function": "count", "parameter": '$,#1,"eq","{$CRIT}"'},
}
ITEMS = {
    "22183": {"itemid": "22183", "hostid": "10047", "key_": "zabbix[process,poller,avg,busy]"},
    "22184": {"itemid": "22184", "hostid": "10084", "key_": 'web.page.get["{$SCHEME}://{$HOST}"]'},
}
HOSTS = {"10047": "Zabbix server health", "10084": "Zabbix server"}


def rebuild(raw: str) -> str:
    return te.editable_expression(raw, FUNCTIONS, ITEMS, HOSTS)


class TestTheEditableForm(unittest.TestCase):
    def test_a_function_is_written_out_and_the_macro_stays(self):
        self.assertEqual(rebuild('{33791}>{$UTIL.MAX:"poller"}'),
                         'avg(/Zabbix server health/zabbix[process,poller,avg,busy],10m)>{$UTIL.MAX:"poller"}')

    def test_a_macro_in_a_parameter_and_in_an_item_key_stays_too(self):
        # Zabbix's own expansion puts the values in here as well
        self.assertEqual(rebuild("{33793}=1"),
                         'count(/Zabbix server health/zabbix[process,poller,avg,busy],#1,"eq","{$CRIT}")=1')
        self.assertEqual(rebuild("{33792}=0"), 'last(/Zabbix server/web.page.get["{$SCHEME}://{$HOST}"])=0')

    def test_everything_else_is_left_as_stored(self):
        self.assertEqual(rebuild("({33791}+{33792})/2>=5 and not {33792}=0 or {TRIGGER.VALUE}=1"),
                         "(avg(/Zabbix server health/zabbix[process,poller,avg,busy],10m)"
                         '+last(/Zabbix server/web.page.get["{$SCHEME}://{$HOST}"]))/2>=5 and not '
                         'last(/Zabbix server/web.page.get["{$SCHEME}://{$HOST}"])=0 or {TRIGGER.VALUE}=1')
        self.assertEqual(rebuild("5>3"), "5>3")
        self.assertEqual(rebuild(""), "")

    def test_a_macro_context_is_part_of_the_macro(self):
        # a quote inside an unquoted context must not open a string, braces inside a quoted one are not a function
        self.assertEqual(rebuild('{33792}>{$M:a"b} and {33792}<{$N:c"d}'),
                         'last(/Zabbix server/web.page.get["{$SCHEME}://{$HOST}"])>{$M:a"b} and '
                         'last(/Zabbix server/web.page.get["{$SCHEME}://{$HOST}"])<{$N:c"d}')
        self.assertEqual(rebuild('{33792}>{$M:"x}y{33791}"}'),
                         'last(/Zabbix server/web.page.get["{$SCHEME}://{$HOST}"])>{$M:"x}y{33791}"}')
        self.assertEqual(rebuild('{33792}>{$M:regex:"^a{2}$"} or {33792}>{$FS:{#FSNAME}}'),
                         'last(/Zabbix server/web.page.get["{$SCHEME}://{$HOST}"])>{$M:regex:"^a{2}$"} or '
                         'last(/Zabbix server/web.page.get["{$SCHEME}://{$HOST}"])>{$FS:{#FSNAME}}')

    def test_a_number_in_braces_inside_a_string_is_not_a_function(self):
        self.assertEqual(rebuild('{33792}="{33791}" and {33792}<>"a \\" {33791} b"'),
                         'last(/Zabbix server/web.page.get["{$SCHEME}://{$HOST}"])="{33791}" and '
                         'last(/Zabbix server/web.page.get["{$SCHEME}://{$HOST}"])<>"a \\" {33791} b"')

    def test_pieces_that_do_not_add_up_are_said_not_guessed(self):
        for raw, functions, items, hosts in (
            ("{99999}>1", FUNCTIONS, ITEMS, HOSTS),                                     # not one of the trigger's
            ("{33791}>1", FUNCTIONS, {}, HOSTS),                                        # an item the caller cannot read
            ("{33791}>1", FUNCTIONS, ITEMS, {}),                                        # its host
            ("{33791}>1", {"33791": dict(FUNCTIONS["33791"], parameter="10m")}, ITEMS, HOSTS),   # no item placeholder
            ("{33791}>1", {"33791": {"functionid": "33791", "itemid": "22183", "parameter": "$"}}, ITEMS, HOSTS),
        ):
            with self.assertRaises(te.NotRebuilt):
                te.editable_expression(raw, functions, items, hosts)


class TestWhenItApplies(unittest.TestCase):
    def test_the_two_trigger_methods_on_a_release_with_the_current_syntax(self):
        for method in ("trigger.get", "triggerprototype.get"):
            for version in ("5.4.0", "6.0.48", "7.4.14", "8.0.0", "8.0.0rc2"):
                self.assertTrue(te.wanted(method, {}, version), (method, version))
        self.assertFalse(te.wanted("item.get", {}, "8.0.0"))
        self.assertFalse(te.wanted("trigger.update", {}, "8.0.0"))

    def test_not_before_5_4_and_not_without_a_version(self):
        # the old syntax {host:key.func()} is not rebuilt: Zabbix's expansion as before
        for version in ("5.0.47", "5.2.7", None, "", "garbage"):
            self.assertFalse(te.wanted("trigger.get", {}, version), version)

    def test_not_when_the_caller_chose(self):
        for chosen in (True, False, 0, 1):
            self.assertFalse(te.wanted("trigger.get", {"extra_params": {"expandExpression": chosen}}, "8.0.0"), chosen)
            self.assertFalse(te.wanted("trigger.get", {"expandExpression": chosen}, "8.0.0"), chosen)
        self.assertTrue(te.wanted("trigger.get", {"extra_params": {"selectHosts": "extend"}, "expandExpression": None}, "8.0.0"))


def _pieces(triggerid: str) -> dict:
    return {"triggerid": triggerid, "functions": list(FUNCTIONS.values()), "items": list(ITEMS.values()),
            "hosts": [{"hostid": k, "host": v} for k, v in HOSTS.items()]}


class TestRewrite(unittest.TestCase):
    def test_the_rows_are_rewritten_in_place_with_one_more_call(self):
        rows = [{"triggerid": "1", "expression": "{33791}>{$MAX}", "recovery_expression": "{33791}<{$MIN}", "priority": "3"},
                {"triggerid": "2", "expression": "{33792}=0", "recovery_expression": ""}]
        calls = []

        def call(method, params):
            calls.append((method, params))
            return [_pieces(i) for i in params["triggerids"]]

        self.assertEqual(te.rewrite(rows, "trigger.get", call), [])
        self.assertEqual(rows[0]["expression"], "avg(/Zabbix server health/zabbix[process,poller,avg,busy],10m)>{$MAX}")
        self.assertEqual(rows[0]["recovery_expression"], "avg(/Zabbix server health/zabbix[process,poller,avg,busy],10m)<{$MIN}")
        self.assertEqual(rows[0]["priority"], "3")
        self.assertEqual(rows[1]["recovery_expression"], "")
        self.assertEqual(len(calls), 1)
        method, params = calls[0]
        self.assertEqual(method, "trigger.get")
        self.assertEqual(params["triggerids"], ["1", "2"])
        self.assertEqual(params["output"], ["triggerid"])
        self.assertEqual(params["selectFunctions"], "extend")      # by name Zabbix leaves "function" out
        self.assertNotIn("expandExpression", params)

    def test_nothing_to_do_is_no_call(self):
        def call(method, params):
            raise AssertionError("no call expected")

        for result in ([], {}, "151", 151, None, [{"triggerid": "1", "description": "x"}],
                       [{"triggerid": "1", "expression": "", "recovery_expression": ""}], [{"expression": "{1}>0"}]):
            self.assertEqual(te.rewrite(copy.deepcopy(result), "trigger.get", call), [], result)

    def test_a_keyed_answer(self):
        rows = {"1": {"triggerid": "1", "expression": "{33792}=0"}}
        te.rewrite(rows, "triggerprototype.get", lambda m, p: {i: _pieces(i) for i in p["triggerids"]})
        self.assertEqual(rows["1"]["expression"], 'last(/Zabbix server/web.page.get["{$SCHEME}://{$HOST}"])=0')

    def test_many_triggers_are_asked_for_in_chunks(self):
        rows = [{"triggerid": str(n), "expression": "{33792}=0"} for n in range(1, 1202)]
        sizes = []

        def call(method, params):
            sizes.append(len(params["triggerids"]))
            return [_pieces(i) for i in params["triggerids"]]

        te.rewrite(rows, "trigger.get", call)
        self.assertEqual(sizes, [500, 500, 201])
        self.assertTrue(all(r["expression"].startswith("last(/Zabbix server/") for r in rows))

    def test_what_cannot_be_rebuilt_keeps_the_stored_form(self):
        # unreadable, and refused by trigger.update: Zabbix's own expansion would read
        # well and take the macros with it when written back
        rows = [{"triggerid": "1", "expression": "{33791}>1", "recovery_expression": "{33791}<1"},
                {"triggerid": "2", "expression": "{33791}>1", "recovery_expression": "{77777}>1"},
                {"triggerid": "3", "expression": "{33792}=0"}]
        calls = []

        def call(method, params):
            calls.append(params)
            return [_pieces(i) for i in params["triggerids"] if i != "3"]     # nothing comes back for 3

        self.assertEqual(te.rewrite(rows, "trigger.get", call), ["2", "3"])
        self.assertEqual(rows[0]["expression"], "avg(/Zabbix server health/zabbix[process,poller,avg,busy],10m)>1")
        # both fields or neither: a half-rebuilt trigger would be the worst of the two
        self.assertEqual((rows[1]["expression"], rows[1]["recovery_expression"]), ("{33791}>1", "{77777}>1"))
        self.assertEqual(rows[2]["expression"], "{33792}=0")
        self.assertEqual(len(calls), 1)
        self.assertFalse(any("expandExpression" in c for c in calls))


class TestThroughTheTools(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cfg = AppConfig(server=ServerConfig(timezone="UTC"), zabbix_servers={"t": ZabbixServerConfig(
            name="t", url="http://localhost", api_token="x", read_only=False)})
        cls.mgr = ClientManager(cfg)
        cls.mcp = ZabbixMCPServer(name="test")
        _register_tools(cls.mcp, cls.mgr)

    def _call(self, tool, args, version="8.0.0", stored=None):
        sent = []
        stored = stored if stored is not None else [{"triggerid": "13568", "expression": "{33791}>{$MAX}",
                                                     "recovery_expression": "{33791}<{$MIN}", "description": "Poller"}]

        def fake_call(server, method, params, *a, **k):
            sent.append((method, copy.deepcopy(params)))
            if method.endswith(".update"):
                return {"triggerids": ["13568"]}
            if params.get("countOutput"):
                return "151"
            if "selectFunctions" in params and params.get("output") == ["triggerid"]:
                return [_pieces(i) for i in params["triggerids"]]
            if params.get("expandExpression"):
                return [dict(r, expression="avg(/Zabbix server health/zabbix[process,poller,avg,busy],10m)>75") for r in copy.deepcopy(stored)]
            return copy.deepcopy(stored)

        with patch.object(self.mgr, "call", side_effect=fake_call), patch.object(self.mgr, "get_version", return_value=version):
            result = asyncio.run(self.mcp.call_tool(tool, args))
        return sent, json.loads(result.content[0].text.split("\n", 1)[1])

    def test_the_default_answer_keeps_the_macro(self):
        for tool, method in (("trigger_get", "trigger.get"), ("triggerprototype_get", "triggerprototype.get")):
            sent, rows = self._call(tool, {"triggerids": ["13568"], "output": ["triggerid", "expression", "recovery_expression"]})
            self.assertEqual(rows[0]["expression"], "avg(/Zabbix server health/zabbix[process,poller,avg,busy],10m)>{$MAX}", tool)
            self.assertEqual(rows[0]["recovery_expression"], "avg(/Zabbix server health/zabbix[process,poller,avg,busy],10m)<{$MIN}", tool)
            self.assertEqual([m for m, _ in sent], [method, method], tool)
            self.assertNotIn("expandExpression", sent[0][1], tool)

    def test_what_the_caller_asked_for_is_what_reaches_zabbix(self):
        sent, _ = self._call("trigger_get", {"triggerids": ["13568"], "output": ["triggerid", "expression"]})
        self.assertEqual(sent[0][1]["output"], ["triggerid", "expression"])
        self.assertNotIn("selectFunctions", sent[0][1])        # the pieces come from the second call

    def test_zabbix_s_own_expansion_when_asked_for(self):
        sent, rows = self._call("trigger_get", {"triggerids": ["13568"], "extra_params": {"expandExpression": True}})
        self.assertEqual(len(sent), 1)
        self.assertIs(sent[0][1]["expandExpression"], True)
        self.assertTrue(rows[0]["expression"].endswith(">75"))

    def test_the_stored_form_when_asked_for(self):
        sent, rows = self._call("trigger_get", {"triggerids": ["13568"], "output": ["triggerid", "expression"],
                                                "extra_params": {"expandExpression": False}})
        self.assertEqual(len(sent), 1)
        self.assertNotIn("expandExpression", sent[0][1])
        self.assertEqual(rows[0]["expression"], "{33791}>{$MAX}")

    def test_a_count_and_an_answer_without_expressions_cost_nothing_more(self):
        sent, rows = self._call("trigger_get", {"output": "count"})
        self.assertEqual((len(sent), int(rows)), (1, 151))
        sent, rows = self._call("trigger_get", {"triggerids": ["1"], "output": ["triggerid", "description"]},
                                stored=[{"triggerid": "1", "description": "x"}])
        self.assertEqual(len(sent), 1)

    def test_before_5_4_zabbix_expands_as_before(self):
        sent, _ = self._call("trigger_get", {"triggerids": ["13568"]}, version="5.0.47")
        self.assertEqual(len(sent), 1)
        self.assertIs(sent[0][1]["expandExpression"], True)

    def test_read_and_sent_back_the_macro_is_still_there(self):
        _, rows = self._call("trigger_get", {"triggerids": ["13568"], "output": "extend"})
        sent, _ = self._call("trigger_update", {"params": rows[0]})
        method, params = sent[-1]
        self.assertEqual(method, "trigger.update")
        self.assertEqual(params["expression"], "avg(/Zabbix server health/zabbix[process,poller,avg,busy],10m)>{$MAX}")
        self.assertEqual(params["recovery_expression"], "avg(/Zabbix server health/zabbix[process,poller,avg,busy],10m)<{$MIN}")


if __name__ == "__main__":
    unittest.main()
