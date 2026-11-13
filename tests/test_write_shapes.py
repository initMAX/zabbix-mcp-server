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

"""host_create with an SNMP interface, as a model writes it.

A live demo on Zabbix 8.0 with a full catalog: the model wrote ``groups`` as a
list of IDs (the tool description said "array of host group IDs"), then an
agent interface (type 1) on port 161 with SNMP settings under invented names,
and repeated the refused calls. Zabbix answered "an array is expected" and
"Incorrect arguments passed to function", from which the right form cannot be
told. The same request written correctly worked through the same server.
"""

import asyncio
import json
import re
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from zabbix_mcp.api.write_shapes import select_problems, problems, snmp_keys  # noqa: E402
from zabbix_mcp.client import ClientManager  # noqa: E402
from zabbix_mcp.config import AppConfig, ServerConfig, ZabbixServerConfig  # noqa: E402
from zabbix_mcp.server import ZabbixMCPServer, _register_tools, _server_instructions  # noqa: E402

RELEASES = ("6.0.48", "6.2.9", "6.4.21", "7.0.30", "7.2.15", "7.4.14", "8.0.0")

# The regression payload (placeholder IDs).
CORRECT = {
    "host": "mcp-snmp-contract-test",
    "status": 1,
    "groups": [{"groupid": "42"}],
    "templates": [{"templateid": "12345"}],
    "interfaces": [{"type": 2, "main": 1, "useip": 1, "ip": "192.0.2.10", "dns": "", "port": "161",
                    "details": {"version": 2, "bulk": 1, "community": "{$SNMP_COMMUNITY}"}}],
    "macros": [{"macro": "{$SNMP_COMMUNITY}", "value": "DEMO_COMMUNITY"}],
}


def with_interface(**changes):
    payload = json.loads(json.dumps(CORRECT))
    payload["interfaces"][0].update(changes)
    return payload


class TestTheShapesZabbixDoesNotExplain(unittest.TestCase):
    def test_the_correct_snmp_host_passes_on_every_release(self):
        for release in RELEASES + (None,):
            self.assertEqual(problems("host.create", CORRECT, release), [], release)
        # symbolic type, numbers as strings, SNMPv3, a v1 host
        self.assertEqual(problems("host.create", with_interface(type="SNMP"), "8.0.0"), [])
        self.assertEqual(problems("host.create", with_interface(type="2", details={"version": "2", "community": "x"}), "6.0.48"), [])
        v3 = {"version": 3, "securityname": "zbx", "securitylevel": 2, "authprotocol": 1, "authpassphrase": "{$A}",
              "privprotocol": 1, "privpassphrase": "{$P}", "contextname": "", "bulk": 1}
        self.assertEqual(problems("host.create", with_interface(details=v3), "7.0.30"), [])

    def test_groups_written_as_ids(self):
        payload = dict(CORRECT, groups=["42"])
        found = problems("host.create", payload, "8.0.0")
        self.assertEqual(len(found), 1)
        self.assertIn('params.groups[0]: an object with its ID, {"groupid": "42"}', found[0])
        self.assertIn('Write groups as [{"groupid": "<id>"}, ...]', found[0])
        # the same for templates, for a list of payloads, and for the mass methods
        self.assertIn("params.templates[1]", problems("host.create", dict(CORRECT, templates=[{"templateid": "1"}, "2"]))[0])
        self.assertIn("params[1].groups[0]", problems("host.create", [CORRECT, dict(CORRECT, groups=[42])])[0])
        self.assertIn("params.hosts[0]", problems("host.massadd", {"hosts": ["10084"], "groups": [{"groupid": "2"}]})[0])
        self.assertIn("params.usrgrps[0]", problems("user.create", {"username": "u", "usrgrps": ["7"]})[0])
        # a single object instead of a list is what Zabbix accepts too
        self.assertEqual(problems("host.create", dict(CORRECT, groups={"groupid": "42"})), [])

    def test_snmp_settings_on_an_agent_interface(self):
        payload = with_interface(type=1, details={"snmp_community": "public", "snmp_oid": "1.3.6.1", "snmp_port": 161, "snmp_v2c": True})
        found = problems("host.create", payload, "8.0.0")
        self.assertEqual(len(found), 1)
        self.assertIn("params.interfaces[0]: details (snmp_community, snmp_oid, snmp_port, snmp_v2c) belong to an SNMP interface", found[0])
        self.assertIn("For SNMP use type 2", found[0])
        # the type is not changed for the caller: the agent interface is still type 1
        self.assertEqual(payload["interfaces"][0]["type"], 1)
        # an agent interface on any port without details is somebody's choice
        self.assertEqual(problems("host.create", with_interface(type=1, port="161", details={}), "8.0.0"), [])
        self.assertEqual(problems("host.create", {**CORRECT, "interfaces": [{"type": "AGENT", "main": 1, "useip": 1, "ip": "192.0.2.10", "dns": "", "port": "10050"}]}, "8.0.0"), [])

    def test_snmp_settings_under_other_names(self):
        found = problems("host.create", with_interface(type="SNMP", details={"snmp_version": "v2c", "snmp_community": "public"}), "8.0.0")
        self.assertIn("params.interfaces[0].details: 'snmp_version', 'snmp_community' are not an SNMP setting on Zabbix 8.0.0", found[0])
        self.assertIn("the keys are version, bulk, community", found[0])
        self.assertTrue(any("details.version: 1, 2 (SNMPv2c) or 3" in f for f in found))

    def test_an_snmp_interface_without_settings(self):
        self.assertIn("an SNMP interface needs its SNMP settings",
                      problems("host.create", {**CORRECT, "interfaces": [{"type": 2, "main": 1, "useip": 1, "ip": "192.0.2.10", "dns": "", "port": "161"}]})[0])
        self.assertIn("needs a community", problems("host.create", with_interface(details={"version": 2}), "8.0.0")[0])
        self.assertIn("details.version", problems("host.create", with_interface(details={"version": 4, "community": "x"}))[0])

    def test_the_settings_follow_the_release(self):
        self.assertNotIn("max_repetitions", snmp_keys("6.0.48"))
        self.assertNotIn("max_repetitions", snmp_keys("6.2.9"))
        self.assertIn("max_repetitions", snmp_keys("6.4.21"))
        self.assertNotIn("retries", snmp_keys("7.4.14"))
        self.assertIn("retries", snmp_keys("8.0.0"))
        self.assertIn("retries", snmp_keys(None))           # unknown release: nothing refused that exists somewhere
        with_mr = with_interface(details={"version": 2, "community": "x", "max_repetitions": 10})
        self.assertTrue(problems("host.create", with_mr, "6.0.48"))
        self.assertEqual(problems("host.create", with_mr, "6.4.21"), [])

    def test_updates_and_the_interface_tools(self):
        # an update that names neither the type nor the settings is left to Zabbix
        self.assertEqual(problems("host.update", {"hostid": "1", "interfaces": [{"interfaceid": "5", "ip": "192.0.2.11"}]}, "8.0.0"), [])
        self.assertEqual(problems("hostinterface.update", {"interfaceid": "5", "port": "1161"}, "7.0.30"), [])
        self.assertTrue(problems("hostinterface.update", {"interfaceid": "5", "details": {"snmp_community": "x"}, "type": 2}, "7.0.30"))
        self.assertTrue(problems("hostinterface.create", {"hostid": "1", "type": 2, "main": 1, "useip": 1, "ip": "192.0.2.10", "dns": "", "port": "161"}))

    def test_reads_and_other_methods_are_not_touched(self):
        self.assertEqual(problems("host.get", {"groups": ["1"], "interfaces": [{"type": 1, "details": {"x": 1}}]}), [])
        self.assertEqual(problems("item.create", {"groups": ["1"]}), [])
        self.assertEqual(problems("host.massremove", {"hostids": ["1"], "groupids": ["2"]}), [])


def _server():
    cfg = AppConfig(server=ServerConfig(timezone="UTC"),
                    zabbix_servers={"t": ZabbixServerConfig(name="t", url="http://localhost", api_token="x", read_only=False)})
    mgr = ClientManager(cfg)
    mcp = ZabbixMCPServer(name="test")
    _register_tools(mcp, mgr)
    return mgr, mcp


def _refusal(mcp, name, args):
    """The text of a refused call (in process a refusal is a ToolError), or None."""
    from mcp.server.mcpserver.exceptions import ToolError
    try:
        asyncio.run(mcp.call_tool(name, args))
    except ToolError as exc:
        return str(exc)
    return None


class TestThroughTheServer(unittest.TestCase):
    def _create(self, params, release="8.0.0"):
        mgr, mcp = _server()
        sent = []
        with patch.object(mgr, "call", side_effect=lambda s, m, p, *a, **k: sent.append((m, p)) or {"hostids": ["10900"]}), \
                patch.object(mgr, "get_version", return_value=release):
            refused = _refusal(mcp, "host_create", {"params": params})
        return refused, sent

    def test_the_correct_host_is_sent_as_written(self):
        for release in RELEASES:
            refused, sent = self._create(json.loads(json.dumps(CORRECT)), release)
            self.assertIsNone(refused, release)
            self.assertEqual(len(sent), 1, release)
            method, params = sent[0]
            self.assertEqual(method, "host.create")
            self.assertEqual(params["interfaces"][0]["details"], CORRECT["interfaces"][0]["details"])
            self.assertEqual(params["groups"], [{"groupid": "42"}])
            self.assertEqual(params["templates"], [{"templateid": "12345"}])
            self.assertEqual(params["macros"], CORRECT["macros"])

    def test_a_wrong_shape_is_refused_before_anything_is_sent(self):
        for params in (dict(CORRECT, groups=["42"]),
                       with_interface(type=1, details={"snmp_community": "public"}),
                       with_interface(details={"snmp_v2c": True})):
            text, sent = self._create(params)
            self.assertIsNotNone(text)
            self.assertEqual(sent, [])
            self.assertIn("host_create was not sent", text)
            self.assertIn("the same call unchanged is refused again", text)

    def test_the_same_refused_call_twice_is_refused_twice(self):
        for _ in range(2):
            refused, sent = self._create(dict(CORRECT, groups=["42"]))
            self.assertIn("was not sent", refused)
            self.assertEqual(sent, [])

    def test_a_read_after_a_successful_write_still_works(self):
        mgr, mcp = _server()
        with patch.object(mgr, "call", side_effect=lambda s, m, p, *a, **k: {"hostids": ["1"]} if m == "host.create" else [{"hostid": "1"}]), \
                patch.object(mgr, "get_version", return_value="8.0.0"):
            created = _refusal(mcp, "host_create", {"params": json.loads(json.dumps(CORRECT))})
            read = [_refusal(mcp, "host_get", {"filter": {"host": ["mcp-snmp-contract-test"]}}) for _ in range(2)]
        self.assertIsNone(created)
        self.assertEqual(read, [None, None])

    def test_a_read_only_server_still_refuses_first(self):
        cfg = AppConfig(server=ServerConfig(timezone="UTC"),
                        zabbix_servers={"t": ZabbixServerConfig(name="t", url="http://localhost", api_token="x", read_only=True)})
        mgr = ClientManager(cfg)
        mcp = ZabbixMCPServer(name="test")
        _register_tools(mcp, mgr)
        sent = []
        with patch.object(mgr, "call", side_effect=lambda s, m, p, *a, **k: sent.append(m)), \
                patch.object(mgr, "get_version", return_value="8.0.0"):
            refused = _refusal(mcp, "host_create", {"params": json.loads(json.dumps(CORRECT))})
        self.assertIn("read-only", refused)
        self.assertEqual(sent, [])


class TestEnumFieldsOfAWrite(unittest.TestCase):
    """An item of type "web" (a later live session): Zabbix answers "/1/type: an integer is
    expected"; HTTP agent is 19. The params object now says which values there are."""

    def test_an_unknown_name_is_refused_with_the_values(self):
        found = problems("item.create", {"hostid": "1", "name": "x", "key_": "x", "type": "web", "value_type": 4}, "8.0.0")
        self.assertEqual(len(found), 1)
        self.assertIn('params.type: "web" is no type of item.create', found[0])
        self.assertIn("19 HTTP_AGENT", found[0])
        self.assertTrue(problems("item.update", {"itemid": "1", "value_type": "string"}))
        self.assertTrue(problems("trigger.create", {"description": "x", "expression": "1", "priority": "urgent"}))

    def test_names_and_numbers_still_pass(self):
        for value in (19, "19", "HTTP_AGENT", "http_agent"):
            self.assertEqual(problems("item.create", {"type": value, "value_type": "TEXT"}), [], value)
        self.assertEqual(problems("itemprototype.create", {"type": "SNMP_AGENT", "value_type": 3}), [])

    def test_the_schema_types_the_enum_fields_and_keeps_every_other_key(self):
        tools = {t.name: t for t in _server()[1]._tool_manager.list_tools()}
        params = tools["item_create"].parameters["properties"]["params"]
        self.assertIs(params["additionalProperties"], True)
        integer, names = params["properties"]["type"]["anyOf"]
        self.assertIn(19, integer["enum"])
        self.assertIn("HTTP_AGENT", names["enum"])
        self.assertIn("19 HTTP_AGENT", params["properties"]["type"]["description"])
        self.assertIn("value_type", params["properties"])
        # reads are not touched
        self.assertNotIn("properties", tools["item_get"].parameters["properties"].get("params", {}))

    def test_through_the_server_nothing_is_sent(self):
        mgr, mcp = _server()
        sent = []
        with patch.object(mgr, "call", side_effect=lambda s, m, p, *a, **k: sent.append(m) or {"itemids": ["1"]}), \
                patch.object(mgr, "get_version", return_value="7.0.30"):
            refused = _refusal(mcp, "item_create", {"params": {"hostid": "1", "name": "x", "key_": "x", "type": "web", "value_type": 4}})
            ok = _refusal(mcp, "item_create", {"params": {"hostid": "1", "name": "x", "key_": "x", "type": "HTTP_AGENT",
                                                          "value_type": 4, "url": "http://192.0.2.1/", "delay": "1m"}})
        self.assertIn("19 HTTP_AGENT", refused)
        self.assertIsNone(ok)
        self.assertEqual(sent, ["item.create"])


class TestSelectOfARead(unittest.TestCase):
    """host_get after a successful host_create (7.0, live session): selectGroups = "name".
    Zabbix answers 'Invalid parameter "/output": value must be "extend"' three times over."""

    def test_a_single_name_is_refused_with_the_list_form(self):
        found = select_problems({"output": ["hostid"], "selectHostGroups": "name", "selectInterfaces": ["ip"]})
        self.assertEqual(len(found), 1)
        self.assertIn('selectHostGroups: "name"', found[0])
        self.assertIn('["name"]', found[0])

    def test_extend_count_and_lists_pass(self):
        self.assertEqual(select_problems({"selectInterfaces": "extend", "selectTags": "count",
                                          "selectParentTemplates": ["host"], "output": "extend"}), [])

    def test_through_the_server(self):
        mgr, mcp = _server()
        sent = []
        with patch.object(mgr, "call", side_effect=lambda s, m, p, *a, **k: sent.append(p) or []), \
                patch.object(mgr, "get_version", return_value="7.0.30"):
            refused = _refusal(mcp, "host_get", {"hostids": ["1"], "extra_params": {"selectHostGroups": "name"}})
            ok = _refusal(mcp, "host_get", {"hostids": ["1"], "extra_params": {"selectHostGroups": ["name"]}})
        self.assertIn('["name"]', refused)
        self.assertIsNone(ok)
        self.assertEqual(len(sent), 1)


class TestRemovedNamesSayWhatInstead(unittest.TestCase):
    """host_get with selectGroups on 8.0 (live session): the refusal named the release, not the successor."""

    def test_the_successor_is_named(self):
        from zabbix_mcp.api.contracts import GetParamError, validate_get_params
        for method, version, successor in (("host.get", "8.0.0", "selectHostGroups"), ("template.get", "7.4.0", "selectTemplateGroups")):
            with self.assertRaises(GetParamError) as caught:
                validate_get_params(method, {"selectGroups": "extend"}, version)
            self.assertIn(f"Use {successor}.", str(caught.exception))
        validate_get_params("host.get", {"selectGroups": "extend"}, "7.0.0")   # still there before 7.2


class TestCopiesOfAGetAnswer(unittest.TestCase):
    """Clones by a model acting on 7.2 to 8.0 (agent runs): the copy's own ID, the IDs inside
    its lists and its uuid were refused one call at a time."""

    def test_own_and_nested_ids_are_in_the_measured_contract(self):
        from zabbix_mcp.api.write_contracts import strip_for_write
        item = {"itemid": "1", "hostid": "2", "name": "u", "key_": "k", "type": "0", "value_type": "3", "templateid": "0"}
        strip_for_write("item.create", item, "8.0.0")
        self.assertNotIn("itemid", item); self.assertEqual(item["hostid"], "2")
        host = {"host": "h", "groups": [{"groupid": "2"}], "macros": [{"hostmacroid": "5", "macro": "{$A}", "value": "1"}]}
        strip_for_write("host.create", host, "8.0.0")
        self.assertEqual(host["macros"], [{"macro": "{$A}", "value": "1"}])
        trig = {"triggerid": "9", "description": "x", "expression": "1"}
        strip_for_write("trigger.create", trig, "7.4.0")
        self.assertNotIn("triggerid", trig)

    def test_a_uuid_collision_says_to_leave_the_uuid_out(self):
        from zabbix_mcp.server import _api_error_text
        class E(Exception):
            code, message, data = -32602, "Invalid params.", 'Invalid parameter "/1": item with the same UUID already exists.'
        self.assertIn("leave uuid out", _api_error_text("item.create", E()))

    def test_mass_methods_without_tags_say_so(self):
        found = problems("host.massadd", {"hosts": [{"hostid": "1"}], "tags": [{"tag": "a", "value": "b"}]})
        self.assertEqual(len(found), 1)
        self.assertIn("host_update", found[0])
        self.assertEqual(problems("host.massadd", {"hosts": [{"hostid": "1"}], "groups": [{"groupid": "2"}]}), [])
        self.assertEqual(problems("host.update", {"hostid": "1", "tags": [{"tag": "a", "value": "b"}]}), [])


class TestGetNamesSentBack(unittest.TestCase):
    """A get answer's "hostgroups" / "parentTemplates" (agent runs, 6.0 to 8.0): a create
    copy takes them as groups / templates; an update leaves them out and says so (the
    review: on an update they are an echo, perhaps cut by limitSelects, and replacing the
    links with them would unlink without anybody asking)."""

    def test_a_create_copy_takes_them_as_the_write_lists(self):
        from zabbix_mcp.api.write_shapes import rename_get_lists
        p = {"host": "h2", "hostgroups": [{"groupid": "22", "name": "Demo"}], "parentTemplates": [{"templateid": "7", "host": "T"}]}
        self.assertEqual(sorted(rename_get_lists("host.create", p)), ["hostgroups -> groups", "parentTemplates -> templates"])
        self.assertEqual(p["groups"], [{"groupid": "22", "name": "Demo"}])
        t = {"host": "T2", "templategroups": [{"groupid": "1"}]}
        rename_get_lists("template.create", t)
        self.assertEqual(t["groups"], [{"groupid": "1"}])
        both = {"host": "h3", "hostgroups": [{"groupid": "22"}], "groups": [{"groupid": "5"}]}
        rename_get_lists("host.create", both)
        self.assertEqual(both["groups"], [{"groupid": "5"}])          # the write name wins

    def test_an_update_never_relinks_from_a_get_name(self):
        from zabbix_mcp.api.write_shapes import get_names_left_out, rename_get_lists
        for p in ({"hostid": "1", "parentTemplates": []},
                  {"hostid": "1", "parentTemplates": [{"templateid": "10"}], "templates": [{"templateid": "10"}, {"templateid": "11"}]},
                  {"hostid": "1", "hostgroups": [{"groupid": "22"}], "groups": [{"groupid": "22"}, {"groupid": "2"}]}):
            before = json.loads(json.dumps(p))
            self.assertEqual(rename_get_lists("host.update", p), [])
            self.assertEqual(p, before)
        self.assertEqual(get_names_left_out("host.update", {"hostid": "1", "hostgroups": []}), [("hostgroups", "groups")])
        self.assertEqual(get_names_left_out("host.update", {"hostid": "1", "hostgroups": [], "groups": []}), [])

    def test_through_the_server(self):
        mgr, mcp = _server()
        sent = []
        with patch.object(mgr, "call", side_effect=lambda s, m, p, *a, **k: sent.append((m, p)) or {"hostids": ["1"]}), \
                patch.object(mgr, "get_version", return_value="7.0.30"):
            text = asyncio.run(mcp.call_tool("host_update", {"params": {"hostid": "1", "name": "n", "hostgroups": [{"groupid": "22"}]}})).content[0].text
            asyncio.run(mcp.call_tool("host_update", {"params": {"hostid": "1", "parentTemplates": [], "templates": [{"templateid": "7"}, {"templateid": "8"}]}}))
            copy = asyncio.run(mcp.call_tool("host_create", {"params": {"host": "h2", "hostgroups": [{"groupid": "22", "name": "D"}],
                                                                        "items": [{"itemid": "1"}]}})).content[0].text
        self.assertIn("Not applied: hostgroups", text)
        self.assertNotIn("groups", sent[0][1])
        self.assertEqual(sent[1][1]["templates"], [{"templateid": "7"}, {"templateid": "8"}])
        self.assertNotIn("parentTemplates", sent[1][1])
        self.assertEqual(sent[2][1]["groups"], [{"groupid": "22"}])
        self.assertIn("Not copied: items (1)", copy)

    def test_odd_dashboard_input_does_not_crash(self):
        for pages in (5, [3], [{"widgets": 3}], [{"widgets": [{"fields": 7}]}], [{"widgets": [{"fields": [None, 4]}]}]):
            self.assertEqual(problems("dashboard.create", {"name": "x", "pages": pages}, "6.0.49"), [], pages)

    def test_template_mass_methods_point_to_the_host_side(self):
        self.assertIn("host_massadd", problems("template.massadd", {"templates": [{"templateid": "1"}], "hosts": [{"hostid": "2"}]})[0])
        self.assertIn("host_massremove", problems("template.massremove", {"templateids": ["1"], "hostids": ["2"]})[0])


class TestWhatACopyLeavesOut(unittest.TestCase):
    """template_create with a template_get answer (agent run, 6.2): the items and triggers
    were dropped and the answer was a bare templateids, so the clone looked complete."""

    def _create(self, tool, params, version="7.0.30"):
        mgr, mcp = _server()
        with patch.object(mgr, "call", side_effect=lambda s, m, p, *a, **k: {"templateids": ["11"], "hostids": ["12"]}), \
                patch.object(mgr, "get_version", return_value=version):
            result = asyncio.run(mcp.call_tool(tool, {"params": params}))
        return result.content[0].text

    def test_the_answer_says_what_was_not_copied(self):
        text = self._create("template_create", {"host": "T2", "groups": [{"groupid": "1"}], "parentTemplates": [],
                                                "items": [{"itemid": "1"}, {"itemid": "2"}], "triggers": [{"triggerid": "3"}]})
        self.assertIn("Not copied: items (2), triggers (1)", text)
        self.assertNotIn("Template linkage", text)          # nothing was inherited, nothing to say

    def test_a_plain_create_has_no_note(self):
        self.assertNotIn("Not copied", self._create("template_create", {"host": "T2", "groups": [{"groupid": "1"}]}))

    def test_delete_tools_name_their_argument_first(self):
        tools = {t.name: t for t in _server()[1]._tool_manager.list_tools()}
        self.assertTrue(tools["host_delete"].description.startswith('Takes "ids"'))
        self.assertFalse(tools["host_create"].description.startswith('Takes "ids"'))

    def test_version_gates_name_the_older_way(self):
        from zabbix_mcp.api.versions import unavailable_reason
        self.assertIn("use hostgroup_get", unavailable_reason("templategroup.get", "6.0.49"))
        self.assertNotIn("hostgroup", unavailable_reason("connector.get", "6.0.49") or "")


class TestShapesThatChangedBetweenReleases(unittest.TestCase):
    """Agent run on 6.0: a problems widget with "groupids.0" (the 7.0 form) was stored and
    showed every group; hostgroup_rights was refused bare."""

    WIDGET = {"name": "x", "pages": [{"widgets": [{"type": "problems", "fields": [
        {"type": 2, "name": "groupids.0", "value": "20"}]}]}]}

    def test_indexed_widget_fields_before_7_0(self):
        for version in ("6.0.49", "6.2.9", "6.4.21"):
            found = problems("dashboard.create", self.WIDGET, version)
            self.assertEqual(len(found), 1, version)
            self.assertIn('names it "groupids"', found[0])
        for version in ("7.0.30", "8.0.0", None):
            self.assertEqual(problems("dashboard.create", self.WIDGET, version), [], version)
        plain = {"name": "x", "pages": [{"widgets": [{"type": "problems", "fields": [{"type": 2, "name": "groupids", "value": "20"}]}]}]}
        self.assertEqual(problems("dashboard.create", plain, "6.0.49"), [])

    def test_group_rights_before_6_2(self):
        self.assertIn("one list 'rights'", problems("usergroup.create", {"name": "g", "hostgroup_rights": []}, "6.0.49")[0])
        self.assertEqual(problems("usergroup.create", {"name": "g", "hostgroup_rights": []}, "6.2.9"), [])


class TestReadsAgentsTripped(unittest.TestCase):
    def test_item_filter_takes_the_host_name(self):
        # measured on 6.0 and 7.4: filter host gives that host's rows; usermacro.get ignores it
        from zabbix_mcp.api.contracts import GetParamError, validate_get_params
        for method in ("item.get", "trigger.get", "graph.get", "discoveryrule.get", "itemprototype.get"):
            validate_get_params(method, {"filter": {"host": "demo2"}}, "7.0.30")
        with self.assertRaises(GetParamError):
            validate_get_params("usermacro.get", {"filter": {"host": "demo2"}}, "7.0.30")

    def test_global_macros_default_to_their_own_fields(self):
        mgr, mcp = _server()
        sent = []
        with patch.object(mgr, "call", side_effect=lambda s, m, p, *a, **k: sent.append(p) or []), \
                patch.object(mgr, "get_version", return_value="7.0.30"):
            self.assertIsNone(_refusal(mcp, "usermacro_get", {"extra_params": {"globalmacro": True}}))
            self.assertIsNone(_refusal(mcp, "usermacro_get", {"globalmacro": True, "output": ["globalmacroid", "macro"]}))
            refused = _refusal(mcp, "usermacro_get", {"globalmacro": True, "output": ["hostid"]})
        self.assertEqual(sent[0]["output"], ["globalmacroid", "macro", "value"])
        self.assertIn("not a global macro property", refused)


class TestWhatTheModelIsTold(unittest.TestCase):
    TOOLS = {t.name: t for t in _server()[1]._tool_manager.list_tools()}

    def test_no_description_calls_an_object_list_a_list_of_ids(self):
        bad = re.compile(r"'?(groups|templates|hosts|usrgrps|users)'? \((array|list) of [a-z ]*\bIDs?\)")
        for tool in self.TOOLS.values():
            text = (tool.description or "") + json.dumps(tool.parameters)
            self.assertIsNone(bad.search(text), tool.name)

    def test_host_create_names_the_forms_within_what_clients_keep(self):
        text = self.TOOLS["host_create"].description
        head = text[:700]             # a client seen in the field cut tool descriptions at 700 characters
        for form in ('[{"groupid": "2"}]', '[{"templateid": "10515"}]', "'details'", '"community"', "2 SNMP"):
            self.assertIn(form, head, form)
        params = self.TOOLS["host_create"].parameters["properties"]["params"]["description"]
        self.assertIn('"groups": [{"groupid": "4"}]', params[:220])   # and schema descriptions at 220

    def test_the_examples_in_the_descriptions_are_accepted(self):
        text = self.TOOLS["host_create"].description
        start = text.index("'details': ") + len("'details': ")
        details, _ = json.JSONDecoder().raw_decode(text[start:])
        snmp = {"type": 2, "main": 1, "useip": 1, "ip": "192.0.2.10", "dns": "", "port": "161", "details": details}
        for release in RELEASES:
            self.assertEqual(problems("host.create", {"host": "x", "groups": [{"groupid": "2"}], "interfaces": [snmp]}, release), [])

    def test_the_interface_tools_explain_snmp(self):
        for name in ("hostinterface_create", "hostinterface_update"):
            self.assertIn('"community"', self.TOOLS[name].description)

    def test_the_instructions_say_it_once_for_every_write(self):
        text = _server_instructions(set(self.TOOLS))
        self.assertIn('References are objects, not IDs: groups [{"groupid": "2"}]', text)
        self.assertLessEqual(len(text), 2000)


if __name__ == "__main__":
    unittest.main()
