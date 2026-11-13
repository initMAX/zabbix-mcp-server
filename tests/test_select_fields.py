"""The fields a selectXxx takes, in the schema and checked per release (#106).

The lists are measured (scripts/audit_select_fields_live.py): only the selects a
release checks itself are in api/select_fields.json, with that release's own list
("value must be one of ..."). So the server refuses only what Zabbix would refuse,
and says the fields first.
"""

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from zabbix_mcp.api import select_fields  # noqa: E402
from zabbix_mcp.api.contracts import GetParamError, validate_get_params  # noqa: E402


class TestTheMeasuredLists(unittest.TestCase):
    def test_a_strict_select_per_release(self):
        f62 = select_fields.fields_on("hostgroup.get", "selectHosts", "6.2.9")
        f80 = select_fields.fields_on("hostgroup.get", "selectHosts", "8.0.0")
        self.assertIn("proxy_hostid", f62)
        self.assertNotIn("proxy_hostid", f80)
        self.assertIn("proxyid", f80)
        self.assertNotIn("active_available", f80)      # returned by "extend", refused in a list

    def test_a_select_that_fails_on_unknown_names_is_checked_too(self):
        # 6.0: selectTags fails the whole read on a name it lacks ("field host_tag.x does
        # not exist", an internal error); measured from what it returns
        self.assertEqual(select_fields.fields_on("host.get", "selectTags", "6.0.49"), ["tag", "value"])
        with self.assertRaises(GetParamError) as caught:
            validate_get_params("host.get", {"selectTags": ["tag", "value", "automatic"]}, "6.0.49")
        self.assertIn("'automatic'", str(caught.exception))
        validate_get_params("host.get", {"selectTags": ["tag", "value", "automatic"]}, "7.0.30")

    def test_the_schema_lists_only_fields_a_checking_release_takes(self):
        # what "extend" returns on 5.x is not offered: 7.0 refuses "status" in the list
        self.assertNotIn("status", select_fields.any_release("host.get", "selectParentTemplates"))

    def test_names_an_unchecked_release_leaves_out_are_found(self):
        self.assertEqual(select_fields.left_out("host.get", "selectInterfaces", "7.0.30", ["interfaceid", "bogusfield"]),
                         ["bogusfield"])
        self.assertEqual(select_fields.left_out("host.get", "selectInterfaces", "7.0.30", ["interfaceid", "ip"]), [])
        self.assertEqual(select_fields.left_out("host.get", "selectInterfaces", None, ["bogusfield"]), [])

    def test_unknown_or_unmeasured_is_open(self):
        self.assertIsNone(select_fields.fields_on("hostgroup.get", "selectHosts", None))
        self.assertIsNone(select_fields.fields_on("hostgroup.get", "selectHosts", "4.0.0"))
        self.assertIsNone(select_fields.fields_on("action.get", "selectOperations", "8.0.0"))   # takes any name

    def test_every_entry_is_well_formed(self):
        data = json.loads((Path(select_fields.__file__).parent / "select_fields.json").read_text())
        for method, selects in data["methods"].items():
            for name, entry in selects.items():
                self.assertTrue(name.startswith("select"), (method, name))
                self.assertTrue(entry["releases"], (method, name))
                self.assertTrue(entry["fields"], (method, name))
                for where in entry["fields"].values():
                    self.assertTrue(set(where) <= set(entry["releases"]), (method, name))


class TestTheCheck(unittest.TestCase):
    def test_its_own_fields_pass_on_every_release(self):
        data = json.loads((Path(select_fields.__file__).parent / "select_fields.json").read_text())
        for method, selects in data["methods"].items():
            for name, entry in selects.items():
                for release in entry["releases"]:
                    fields = select_fields.fields_on(method, name, release + ".0")
                    validate_get_params(method, {name: fields}, release + ".0")
                    validate_get_params(method, {name: "extend"}, release + ".0")

    def test_a_field_the_release_does_not_take_is_refused_with_the_list(self):
        with self.assertRaises(GetParamError) as caught:
            validate_get_params("hostgroup.get", {"selectHosts": ["host", "active_available"]}, "8.0.0")
        self.assertIn("'active_available' cannot be asked for by name on Zabbix 8.0.0", str(caught.exception))
        self.assertIn("hostid", str(caught.exception))
        with self.assertRaises(GetParamError):
            validate_get_params("hostgroup.get", {"selectHosts": ["proxy_hostid"]}, "8.0.0")
        validate_get_params("hostgroup.get", {"selectHosts": ["proxy_hostid"]}, "6.2.9")

    def test_a_near_miss_parameter_name_is_suggested(self):
        with self.assertRaises(GetParamError) as caught:
            validate_get_params("host.get", {"selectHostgroups": "extend"}, "7.0.30")
        self.assertIn("Did you mean 'selectHostGroups'?", str(caught.exception))

    def test_open_selects_and_unknown_releases_are_not_checked(self):
        validate_get_params("action.get", {"selectOperations": ["anything"]}, "8.0.0")
        validate_get_params("hostgroup.get", {"selectHosts": ["anything"]}, None)


class TestTheNote(unittest.TestCase):
    def test_the_answer_says_what_zabbix_left_out(self):
        import asyncio
        import test_write_shapes as t
        mgr, mcp = t._server()
        with patch.object(mgr, "call", side_effect=lambda *a, **k: [{"hostid": "1", "interfaces": [{"interfaceid": "5"}]}]), \
                patch.object(mgr, "get_version", return_value="7.0.30"):
            text = asyncio.run(mcp.call_tool("host_get", {"hostids": ["1"], "extra_params": {
                "selectInterfaces": ["interfaceid", "bogusfield"]}})).content[0].text
            plain = asyncio.run(mcp.call_tool("host_get", {"hostids": ["1"], "extra_params": {
                "selectInterfaces": ["interfaceid", "ip"]}})).content[0].text
        first = text.split("\n", 1)[0]
        self.assertIn("Note: Zabbix left out names it does not return under selectInterfaces: bogusfield", first)
        self.assertTrue(first.endswith("]"))           # still one bracketed line before the data
        self.assertNotIn("Note:", plain.split("\n", 1)[0])


class TestTheSchema(unittest.TestCase):
    def test_extra_params_types_the_measured_selects(self):
        import test_write_shapes as t
        tools = {x.name: x for x in t._server()[1]._tool_manager.list_tools()}
        extra = tools["hostgroup_get"].parameters["properties"]["extra_params"]
        branches = extra.get("anyOf", [extra])
        obj = next(b for b in branches if b.get("type") == "object")
        sel = obj["properties"]["selectHosts"]["anyOf"]
        self.assertEqual(sel[0]["enum"], ["extend", "count"])
        self.assertIn("proxyid", sel[1]["items"]["enum"])
        self.assertIn("proxy_hostid", sel[1]["items"]["enum"])     # some release takes it
        self.assertIn("selectHosts", obj["propertyNames"]["enum"])
        # a select that takes any name stays open
        act = next(b for b in tools["action_get"].parameters["properties"]["extra_params"].get("anyOf", []) if b.get("type") == "object")
        self.assertNotIn("selectOperations", act.get("properties", {}))


if __name__ == "__main__":
    unittest.main()
