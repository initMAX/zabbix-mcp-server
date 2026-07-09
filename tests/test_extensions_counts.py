#
# Zabbix MCP Server
# Copyright (C) 2026 initMAX s.r.o.
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License as published by the Free
# Software Foundation, version 3.
#

"""Issue #54: infrastructure_summary_get count fields.

``output="count"`` is not a valid Zabbix API value - the server ignores
it and returns a list of id objects, which the old code silently
converted to 0. The counts must be requested via ``countOutput: true``
(returns the count as a string) on every supported Zabbix version.
"""

from __future__ import annotations

import json
import unittest
from unittest.mock import MagicMock

from zabbix_mcp.api.extensions import infrastructure_summary_get


def _fake_call(server: str, method: str, params: dict):
    """Emulate real Zabbix semantics for the params each call sends."""
    if params.get("countOutput") is True:
        # Zabbix returns the count as a string.
        counts = {
            "host.get": "131",
            "item.get": "5000",
            "trigger.get": "900",
            "template.get": "42",
        }
        if method == "host.get" and params.get("filter") == {"status": 0}:
            return "120"
        return counts.get(method, "0")
    if params.get("output") == "count":
        # Real Zabbix IGNORES output="count" and returns a row list -
        # reproducing this is the point of issue #54.
        return [{"hostid": "1"}, {"hostid": "2"}]
    if method == "problem.get":
        return []
    if method == "trigger.get":
        return []
    if method == "host.get":
        return []
    return []


class TestInfrastructureSummaryCounts(unittest.TestCase):

    def test_counts_use_countoutput_and_return_real_numbers(self):
        cm = MagicMock()
        cm.call.side_effect = _fake_call
        out = json.loads(infrastructure_summary_get(cm, "main"))
        self.assertEqual(out["host_count"], 131)
        self.assertEqual(out["enabled_host_count"], 120)
        self.assertEqual(out["item_count"], 5000)
        self.assertEqual(out["trigger_count"], 900)
        self.assertEqual(out["template_count"], 42)

    def test_no_call_uses_invalid_output_count(self):
        cm = MagicMock()
        cm.call.side_effect = _fake_call
        infrastructure_summary_get(cm, "main")
        for call in cm.call.call_args_list:
            params = call.args[2] if len(call.args) > 2 else call.kwargs.get("params", {})
            self.assertNotEqual(
                params.get("output"), "count",
                f"{call.args[1]} still sends the invalid output='count'",
            )


if __name__ == "__main__":
    unittest.main()
