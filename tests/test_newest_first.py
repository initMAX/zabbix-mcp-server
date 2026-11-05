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

"""A log read with a limit and no sort returns its newest rows.

Zabbix answers a get without ``sortfield`` in the order of the database:
``history_get`` with ``limit: 3`` returned three values a month old, and
``problem_get`` / ``event_get`` / ``auditlog_get`` the oldest rows or a slice
from the middle (measured on 6.0 to 8.0). The five log methods are sorted
descending unless the caller sorts.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from zabbix_mcp.api import ALL_METHODS  # noqa: E402
from zabbix_mcp.api.contracts import (  # noqa: E402
    NEWEST_FIRST, NEWEST_FIRST_NEEDS, contract_for, default_sort, specialise_params, validate_get_params,
)
from zabbix_mcp.server import _build_zabbix_params  # noqa: E402

TOOLS = {m.tool_name: m for m in ALL_METHODS}
BY_METHOD = {m.api_method: m for m in ALL_METHODS}
RELEASES = ("5.0.47", "6.0.48", "6.2.9", "6.4.21", "7.0.30", "7.2.15", "7.4.14", "8.0.0")


def build(tool: str, args: dict, version: str = "8.0.0") -> dict:
    return _build_zabbix_params(TOOLS[tool], dict(args), version)


def description(tool: str, param: str) -> str:
    return next(p.description for p in specialise_params(TOOLS[tool]) if p.name == param)


class TestDefaultSort(unittest.TestCase):
    def test_the_five_logs_come_newest_first(self):
        for tool, args, field in (("history_get", {"itemids": ["1"], "history": 0, "limit": 3}, "clock"),
                                  ("problem_get", {"limit": 3}, "eventid"),
                                  ("event_get", {"limit": 3}, "eventid"),
                                  ("alert_get", {"limit": 3}, "alertid"),
                                  ("auditlog_get", {"limit": 3}, "auditid")):
            params = build(tool, args)
            self.assertEqual((params["sortfield"], params["sortorder"]), (field, "DESC"), tool)

    def test_a_sort_of_the_caller_is_left_alone(self):
        params = build("event_get", {"sortfield": "clock"})
        self.assertEqual(params["sortfield"], "clock")
        self.assertNotIn("sortorder", params)
        params = build("history_get", {"itemids": ["1"], "sortfield": "itemid", "sortorder": "ASC"})
        self.assertEqual((params["sortfield"], params["sortorder"]), ("itemid", "ASC"))
        params = build("alert_get", {"extra_params": {"sortfield": ["clock", "alertid"]}})
        self.assertEqual(params["sortfield"], ["clock", "alertid"])
        self.assertNotIn("sortorder", params)

    def test_a_sortorder_alone_keeps_its_direction(self):
        # "the oldest first" in one argument
        params = build("problem_get", {"sortorder": "ASC"})
        self.assertEqual((params["sortfield"], params["sortorder"]), ("eventid", "ASC"))

    def test_a_count_is_not_sorted(self):
        for args in ({"output": "count"}, {"extra_params": {"countOutput": True}}):
            params = build("event_get", args)
            self.assertNotIn("sortfield", params, args)
            self.assertNotIn("sortorder", params, args)

    def test_history_is_sorted_for_named_items_only(self):
        # the values of one item are in time order in the database; sorting
        # those of every item reads the table
        for args in ({"history": 0, "limit": 3}, {"hostids": ["10084"], "history": 0}, {"itemids": []}):
            params = build("history_get", args)
            self.assertNotIn("sortfield", params, args)
            self.assertNotIn("sortorder", params, args)

    def test_other_get_tools_are_untouched(self):
        for tool in ("host_get", "item_get", "trigger_get", "trend_get", "maintenance_get"):
            params = build(tool, {"limit": 3})
            self.assertNotIn("sortfield", params, tool)
            self.assertNotIn("sortorder", params, tool)

    def test_default_sort_function(self):
        self.assertEqual(default_sort("problem.get", {}), "eventid")
        self.assertIsNone(default_sort("problem.get", {"sortfield": "eventid"}))
        self.assertIsNone(default_sort("problem.get", {"countOutput": True}))
        self.assertEqual(default_sort("problem.get", {"sortfield": ""}), "eventid")
        self.assertIsNone(default_sort("history.get", {}))
        self.assertEqual(default_sort("history.get", {"itemids": ["1"]}), "clock")
        self.assertIsNone(default_sort("host.get", {}))


class TestTheContractAllowsIt(unittest.TestCase):
    def test_the_field_is_sortable_on_every_release(self):
        for method, field in NEWEST_FIRST.items():
            contract = contract_for(method)
            self.assertIsNotNone(contract, method)
            for release in RELEASES:
                self.assertIn(field, contract.sortable(release), (method, release))

    def test_the_tools_type_sortfield_and_sortorder(self):
        for method in NEWEST_FIRST:
            names = [p.name for p in specialise_params(BY_METHOD[method])]
            self.assertIn("sortfield", names, method)
            self.assertIn("sortorder", names, method)
        for method, needs in NEWEST_FIRST_NEEDS.items():
            self.assertIn(method, NEWEST_FIRST)
            self.assertIn(needs, [p.name for p in BY_METHOD[method].params], method)

    def test_what_is_sent_passes_the_validation_on_every_release(self):
        for method in NEWEST_FIRST:
            tool = BY_METHOD[method]
            args = {"itemids": ["1"]} if method in NEWEST_FIRST_NEEDS else {}
            typed = [p.sent_as for p in specialise_params(tool) if not p.sent_as.startswith("filter.")]
            for release in RELEASES:
                params = _build_zabbix_params(tool, dict(args), release)
                self.assertEqual(params["sortorder"], "DESC", (method, release))
                validate_get_params(method, params, release, typed=typed)


class TestTheDescriptionsSaySo(unittest.TestCase):
    def test_sortfield_and_sortorder(self):
        for method, field in NEWEST_FIRST.items():
            tool = BY_METHOD[method].tool_name
            text = description(tool, "sortfield")
            self.assertIn(f"sorted by {field} with the newest first", text, tool)
            self.assertIn("'DESC' while 'sortfield' is omitted", description(tool, "sortorder"), tool)
        self.assertIn("When omitted and 'itemids' is given", description("history_get", "sortfield"))
        self.assertIn("Without 'itemids' nothing is sorted", description("history_get", "sortfield"))
        self.assertIn("When omitted, the result is sorted", description("problem_get", "sortfield"))

    def test_the_tool_descriptions(self):
        for method in NEWEST_FIRST:
            self.assertIn("come first unless a sort is given", BY_METHOD[method].description, method)
        # trend.get has no sort at all, and says what a limit keeps
        self.assertIn("cannot sort", TOOLS["trend_get"].description)
        self.assertNotIn("sortfield", [p.name for p in specialise_params(TOOLS["trend_get"])])

    def test_a_tool_without_the_default_does_not_claim_it(self):
        for tool in ("host_get", "item_get", "trigger_get"):
            self.assertNotIn("newest first", description(tool, "sortfield"), tool)
            self.assertNotIn("newest first", description(tool, "sortorder"), tool)


if __name__ == "__main__":
    unittest.main()
