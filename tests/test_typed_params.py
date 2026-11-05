"""What a typed tool parameter becomes on its way to Zabbix.

Three kinds of silent wrong answer, all found against the PHP sources and
running servers (scripts/audit_api_sources.py, audit_get_flags_live.py):

* a parameter typed under a name Zabbix does not have was ignored (every
  row came back) or refused,
* ``false`` for a Zabbix "flag" switched the filter ON,
* the methods with a signature of their own lacked parameters the server
  takes.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from zabbix_mcp.api import ALL_METHODS  # noqa: E402
from zabbix_mcp.api.contracts import (  # noqa: E402
    CONTRACTS, GetParamError, contract_for, false_means_unset, filter_props,
    specialise_params, validate_get_params,
)
from zabbix_mcp.server import _build_zabbix_params  # noqa: E402

TOOLS = {m.tool_name: m for m in ALL_METHODS}


def build(tool: str, args: dict, version: str = "8.0.0"):
    return _build_zabbix_params(TOOLS[tool], dict(args), version)


class TestNamesZabbixHas(unittest.TestCase):
    def test_proxygroupids_travels_as_proxy_groupids(self):
        params = build("proxygroup_get", {"proxygroupids": ["3"]})
        self.assertEqual(params["proxy_groupids"], ["3"])
        self.assertNotIn("proxygroupids", params)

    def test_with_unacknowledged_events_travels_under_the_native_name(self):
        params = build("trigger_get", {"with_unacknowledged_events": True})
        self.assertIs(params["withUnacknowledgedEvents"], True)
        self.assertNotIn("with_unacknowledged_events", params)

    def test_action_eventsource_is_a_filter(self):
        self.assertEqual(build("action_get", {"eventsource": 3})["filter"], {"eventsource": 3})
        merged = build("action_get", {"eventsource": 0, "filter": {"status": 0}})
        self.assertEqual(merged["filter"], {"status": 0, "eventsource": 0})
        self.assertNotIn("eventsource", merged)

    def test_report_dashboardids_is_a_filter(self):
        params = build("report_get", {"dashboardids": ["1", "2"]})
        self.assertEqual(params["filter"], {"dashboardid": ["1", "2"]})
        self.assertNotIn("dashboardids", params)

    def test_the_same_value_twice_is_fine_two_values_are_refused(self):
        self.assertEqual(build("action_get", {"eventsource": 3, "filter": {"eventsource": [3]}})["filter"],
                         {"eventsource": 3})
        with self.assertRaises(ValueError) as caught:
            build("action_get", {"eventsource": 3, "filter": {"eventsource": 0}})
        self.assertIn("filter.eventsource", str(caught.exception))

    def test_a_filter_sent_through_extra_params_is_extended_not_lost(self):
        params = build("action_get", {"eventsource": 3, "extra_params": {"filter": {"status": 0}}})
        self.assertEqual(params["filter"], {"status": 0, "eventsource": 3})
        with self.assertRaises(ValueError):
            build("action_get", {"eventsource": 3, "extra_params": {"filter": {"eventsource": 1}}})

    def test_what_is_sent_passes_the_validation(self):
        for tool, args in (("proxygroup_get", {"proxygroupids": ["3"]}),
                           ("trigger_get", {"with_unacknowledged_events": True}),
                           ("action_get", {"eventsource": 3}),
                           ("report_get", {"dashboardids": ["1"]})):
            method = TOOLS[tool]
            typed = [p.sent_as for p in specialise_params(method) if not p.sent_as.startswith("filter.")]
            validate_get_params(method.api_method, build(tool, args), "8.0.0", typed=typed)

    def test_every_translated_name_exists_in_the_contract(self):
        seen = 0
        for method in ALL_METHODS:
            contract = contract_for(method.api_method)
            for p in method.params:
                if p.api_name is None:
                    continue
                seen += 1
                self.assertIsNotNone(contract, method.tool_name)
                if p.api_name.startswith("filter."):
                    prop = p.api_name[len("filter."):]
                    self.assertIn(prop, [s.name for s in filter_props(contract)], f"{method.tool_name}.{p.name}")
                else:
                    self.assertIn(p.api_name, contract.params, f"{method.tool_name}.{p.name}")
        self.assertEqual(seen, 4)

    def test_the_invented_parameters_are_gone(self):
        self.assertNotIn("with_hosts", [p.name for p in TOOLS["proxy_get"].params])
        self.assertNotIn("with_users", [p.name for p in TOOLS["usergroup_get"].params])
        self.assertNotIn("proxyids", [p.name for p in TOOLS["task_get"].params])
        # and the validation refuses them instead of letting Zabbix ignore them
        for tool, name in (("proxy_get", "with_hosts"), ("usergroup_get", "with_users")):
            method = TOOLS[tool]
            typed = [p.sent_as for p in specialise_params(method)]
            with self.assertRaises(GetParamError):
                validate_get_params(method.api_method, {name: True}, "8.0.0", typed=typed)

    def test_a_typed_get_parameter_is_one_the_method_has(self):
        # the rule the six wrong names broke: whatever a get tool types by
        # hand is a parameter of the method (or says where it goes)
        from zabbix_mcp.api.contracts import COMMON_GET_PARAMETERS, MCP_SIDE_PARAMS
        own = {"extra_params", "severity_min"}   # severity_min becomes severities
        for method in ALL_METHODS:
            contract = contract_for(method.api_method)
            if contract is None or not method.api_method.lower().endswith(".get"):
                continue
            for p in method.params:
                if p.name in COMMON_GET_PARAMETERS or p.name in own or (contract.method, p.name) in MCP_SIDE_PARAMS:
                    continue
                if p.sent_as.startswith("filter."):
                    continue
                self.assertTrue(p.sent_as in contract.params or p.sent_as in contract.selects,
                                f"{method.tool_name}.{p.name} is not a parameter of {contract.method}")


class TestFlags(unittest.TestCase):
    def test_false_for_a_flag_is_not_sent(self):
        params = build("trigger_get", {"only_true": False, "monitored": False, "active": True,
                                       "with_unacknowledged_events": False})
        self.assertNotIn("only_true", params)
        self.assertNotIn("monitored", params)
        self.assertNotIn("withUnacknowledgedEvents", params)
        self.assertIs(params["active"], True)

    def test_a_flag_in_extra_params_too(self):
        params = build("host_get", {"with_items": False,
                                    "extra_params": {"templated_hosts": False, "with_monitored_items": 0}})
        for name in ("with_items", "templated_hosts", "with_monitored_items"):
            self.assertNotIn(name, params)

    def test_a_boolean_keeps_its_false(self):
        # false means "the ones that are not", not "any"
        self.assertIs(build("trigger_get", {"extra_params": {"templated": False}})["templated"], False)
        self.assertIs(build("item_get", {"with_triggers": False})["with_triggers"], False)
        problem = build("problem_get", {"acknowledged": False, "suppressed": False})
        self.assertIs(problem["acknowledged"], False)
        self.assertIs(problem["suppressed"], False)
        self.assertIs(build("host_get", {"extra_params": {"inheritedTags": False}})["inheritedTags"], False)

    def test_expand_expression_false_wins_over_the_default(self):
        # before 5.4 (the old expression syntax) Zabbix's expansion is still the default
        self.assertIs(build("trigger_get", {}, "5.0.47")["expandExpression"], True)
        self.assertNotIn("expandExpression", build("trigger_get", {"extra_params": {"expandExpression": False}}, "5.0.47"))
        # from 5.4 the server rebuilds the expression itself and asks for nothing
        self.assertNotIn("expandExpression", build("trigger_get", {}))
        self.assertNotIn("expandExpression", build("trigger_get", {"extra_params": {"expandExpression": False}}))
        self.assertIs(build("trigger_get", {"extra_params": {"expandExpression": True}})["expandExpression"], True)

    def test_hostgroup_with_parameters_were_flags_in_6_0(self):
        params = build("hostgroup_get", {"with_hosts": False, "extra_params": {"with_items": False}}, "6.0.48")
        self.assertNotIn("with_hosts", params)
        self.assertNotIn("with_items", params)
        self.assertIs(build("hostgroup_get", {"with_hosts": True}, "7.0.30")["with_hosts"], True)

    def test_which_parameters_are_flags(self):
        trigger = CONTRACTS["trigger.get"]
        for name in ("only_true", "monitored", "active", "skipDependent", "withUnacknowledgedEvents"):
            self.assertTrue(false_means_unset(trigger, name), name)
        for name in ("templated", "inherited", "dependent", "maintenance", "triggerids", "nonsense"):
            self.assertFalse(false_means_unset(trigger, name), name)
        self.assertTrue(false_means_unset(CONTRACTS["hostgroup.get"], "with_monitored_items"))
        self.assertFalse(false_means_unset(CONTRACTS["item.get"], "with_triggers"))

    def test_the_description_names_the_switches(self):
        text = next(p.description for p in specialise_params(TOOLS["trigger_get"]) if p.name == "extra_params")
        self.assertIn("Switches (true turns one on, false is the same as leaving it out)", text)
        self.assertIn("skipDependent", text.split("Switches")[1].split(".")[0])
        self.assertNotIn("templated", text.split("Switches")[1].split(".")[0])


class TestMethodsWithTheirOwnSignature(unittest.TestCase):
    def test_scripts_by_hosts_objects_from_7_0_plain_ids_before(self):
        self.assertEqual(build("script_getscriptsbyhosts", {"hostids": ["1", "2"]}, "6.4.21"), ["1", "2"])
        self.assertEqual(build("script_getscriptsbyhosts", {"hostids": ["1", "2"]}, "7.0.30"),
                         [{"hostid": "1"}, {"hostid": "2"}])
        self.assertEqual(
            build("script_getscriptsbyhosts", {"hostids": ["1"], "scriptid": "5", "manualinput": "x"}),
            [{"hostid": "1", "scriptid": "5", "manualinput": "x"}])

    def test_scripts_by_events(self):
        self.assertEqual(build("script_getscriptsbyevents", {"eventids": ["9"]}, "6.0.48"), ["9"])
        self.assertEqual(build("script_getscriptsbyevents", {"eventids": ["9"], "scriptid": "5"}),
                         [{"eventid": "9", "scriptid": "5"}])

    def test_script_execute_manualinput(self):
        self.assertEqual(build("script_execute", {"scriptid": "1", "hostid": "2", "manualinput": "abc"}),
                         {"scriptid": "1", "hostid": "2", "manualinput": "abc"})

    def test_event_acknowledge_suppress_until_and_cause(self):
        params = build("event_acknowledge", {"eventids": ["1"], "action": 32,
                                             "suppress_until": "2026-12-01T00:00:00Z"})
        self.assertEqual(params["suppress_until"], 1796083200)
        self.assertEqual(build("event_acknowledge", {"eventids": ["1"], "action": 256, "cause_eventid": "7"}),
                         {"eventids": ["1"], "action": 256, "cause_eventid": "7"})

    def test_user_checkauthentication_token(self):
        self.assertEqual(build("user_checkauthentication", {"token": "abc", "extend": False}),
                         {"token": "abc", "extend": False})

    def test_sla_getsli_periods(self):
        self.assertEqual(build("sla_getsli", {"slaid": "1", "periods": 3}), {"slaid": "1", "periods": 3})


if __name__ == "__main__":
    unittest.main()
