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

"""Deprecated is not removed: the method or the select still works, the
model is told to prefer the successor.

Zabbix 8.0 deprecates event correlation in favour of complex event
processing; 7.4 deprecated the per-object discovery selects
(``selectItemDiscovery``, ``selectHostDiscovery``, ``selectDiscoveries`` ...)
in favour of ``selectDiscoveryData`` / ``selectDiscoveryRules``. The version
table carries the first, the get contracts the second, and ``tools/list``
shows both where they apply."""

import asyncio
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, "src")

from mcp.types import Tool  # noqa: E402

from zabbix_mcp.api.contracts import Spec, contract_for, describe_extra_params  # noqa: E402
from zabbix_mcp.api.versions import (  # noqa: E402
    METHOD_DEPRECATED, METHOD_REMOVED, deprecated_reason, unavailable_reason,
)
from zabbix_mcp.client import ClientManager  # noqa: E402
from zabbix_mcp.config import AppConfig, ServerConfig, ZabbixServerConfig  # noqa: E402
from zabbix_mcp.server import _annotate_tools_by_version, _register_tools  # noqa: E402


class TestMethodDeprecation(unittest.TestCase):
    def test_correlation_is_deprecated_from_8_0(self):
        self.assertEqual({m for m, (rel, _) in METHOD_DEPRECATED.items() if rel == "8.0"},
                         {"correlation.get", "correlation.create", "correlation.update", "correlation.delete"})
        for version in ("5.0.47", "7.0.30", "7.4.14", None, "garbage"):
            self.assertIsNone(deprecated_reason("correlation.get", version))
        for version in ("8.0.0", "8.0", "8.2.1"):
            reason = deprecated_reason("correlation.get", version)
            self.assertIn("deprecated since Zabbix 8.0", reason)
            self.assertIn("ceprule.get", reason)
        self.assertIsNone(deprecated_reason("host.get", "8.0.0"))

    def test_deprecated_is_not_removed(self):
        self.assertFalse(set(METHOD_DEPRECATED) & set(METHOD_REMOVED))


class TestSelectDeprecation(unittest.TestCase):
    CASES = {
        "host.get": {"selectHostDiscovery": "selectDiscoveryData", "selectDiscoveries": "selectDiscoveryRules"},
        "hostgroup.get": {"selectGroupDiscoveries": "selectDiscoveryData"},
        "item.get": {"selectItemDiscovery": "selectDiscoveryData"},
        "trigger.get": {"selectTriggerDiscovery": "selectDiscoveryData"},
        "graph.get": {"selectGraphDiscovery": "selectDiscoveryData"},
        "template.get": {"selectDiscoveries": "selectDiscoveryRules"},
    }

    def test_contract_carries_the_mark_and_the_successor(self):
        for method, selects in self.CASES.items():
            contract = contract_for(method)
            for name, successor in selects.items():
                with self.subTest(method=method, select=name):
                    spec = contract.selects[name]
                    self.assertEqual(spec.deprecated, "7.4")
                    self.assertEqual(spec.replaced_by, successor)
                    self.assertEqual(contract.selects[successor].since, "7.4")
                    # still offered and still accepted on every release that has it
                    self.assertTrue(spec.available("8.0.0"))
                    self.assertTrue(spec.available("7.4.14"))
                    self.assertIsNone(spec.removed)

    def test_marker_text(self):
        self.assertEqual(Spec(name="x", deprecated="7.4", replaced_by="y").marker(), " (deprecated in 7.4, use y)")
        self.assertEqual(Spec(name="x", since="7.0", deprecated="7.4").marker(), " (7.0+, deprecated in 7.4)")
        self.assertEqual(Spec(name="x").marker(), "")

    def test_tool_description_says_so(self):
        text = describe_extra_params(contract_for("item.get"), [])
        self.assertIn("selectItemDiscovery (deprecated in 7.4, use selectDiscoveryData)", text)
        text = describe_extra_params(contract_for("host.get"), [])
        self.assertIn("selectDiscoveries (deprecated in 7.4, use selectDiscoveryRules)", text)
        self.assertIn("selectDiscoveryData (7.4+)", text)


class TestToolsListNote(unittest.TestCase):
    def setUp(self):
        from mcp.server.mcpserver import MCPServer
        cfg = AppConfig(server=ServerConfig(), zabbix_servers={
            "old": ZabbixServerConfig(name="old", url="http://old", api_token="t" * 64, read_only=False),
            "new": ZabbixServerConfig(name="new", url="http://new", api_token="t" * 64, read_only=False)})
        self.mgr = ClientManager(cfg)
        mcp = MCPServer(name="test")
        _register_tools(mcp, self.mgr)
        self.tools = [Tool(name=t.name, description=t.description, inputSchema=t.parameters)
                      for t in mcp._tool_manager.list_tools()]

    def _annotated(self, versions):
        with patch.object(self.mgr, "cached_versions", return_value=versions):
            return {t.name: t.description for t in _annotate_tools_by_version(self.tools, self.mgr)}

    def test_deprecated_tool_stays_with_a_note_naming_the_server(self):
        out = self._annotated({"old": "7.4.14", "new": "8.0.0"})
        note = out["correlation_get"].split("Zabbix version note:")[1]
        self.assertIn("on 'new' - correlation.get is deprecated since Zabbix 8.0", note)
        self.assertIn("ceprule.get", note)
        self.assertNotIn("'old'", note)

    def test_no_note_where_nothing_is_deprecated(self):
        out = self._annotated({"old": "7.0.30", "new": "7.4.14"})
        self.assertNotIn("Zabbix version note", out["correlation_get"])

    def test_removed_tool_next_to_a_deprecated_one(self):
        out = self._annotated({"old": "7.4.14", "new": "8.0.0"})
        note = out["hostinterface_update"].split("Zabbix version note:")[1]
        self.assertIn("not on 'new' - hostinterface.update was removed in Zabbix 8.0", note)
        self.assertIn("host.update", note)
        # removed everywhere reachable: dropped, the successor stays
        both_new = self._annotated({"old": "8.0.0", "new": "8.0.0"})
        self.assertNotIn("hostinterface_update", both_new)
        self.assertIn("hostinterface_get", both_new)
        self.assertIn("host_update", both_new)
        self.assertIn("correlation_get", both_new)

    def test_one_tool_missing_on_one_server_and_deprecated_on_the_other(self):
        """Both halves of the note on the same tool: the method does not exist
        yet on the old server and is already on its way out on the new one."""
        from zabbix_mcp.api import versions
        with patch.dict(versions.METHOD_SINCE, {"correlation.get": "7.0"}):
            out = self._annotated({"old": "6.4.21", "new": "8.0.0"})
        note = out["correlation_get"].split("Zabbix version note:")[1]
        self.assertIn("not on 'old' - correlation.get requires Zabbix 7.0 or later", note)
        self.assertIn("on 'new' - correlation.get is deprecated since Zabbix 8.0", note)
        self.assertLess(note.index("not on 'old'"), note.index("on 'new' -"))

    def test_release_candidate_of_the_removing_release_is_not_refused(self):
        """8.0.0rc2 still had the host interface write methods that 8.0.0
        dropped; the number alone does not say, and an unknown never blocks."""
        from zabbix_mcp.api.versions import is_removed
        for version in ("8.0.0rc2", "8.0.0alpha1", "8.0.0beta3", "8.0.0-rc1"):
            self.assertIsNone(unavailable_reason("hostinterface.update", version), version)
            self.assertFalse(is_removed(version, "8.0"), version)
        for version in ("8.0.0", "8.0.1", "8.0.1rc1", "8.2.0rc1", "9.0.0alpha1"):
            self.assertIsNotNone(unavailable_reason("hostinterface.update", version), version)
        # what an earlier release removed stays removed on a later pre-release
        self.assertIsNotNone(unavailable_reason("trigger.adddependencies", "8.0.0rc2"))
        out = self._annotated({"old": "8.0.0rc2", "new": "8.0.0rc2"})
        self.assertIn("hostinterface_update", out)


class TestEnums(unittest.TestCase):
    def test_8_0_symbolic_names(self):
        from zabbix_mcp.server import _normalize_enum_fields
        self.assertEqual(_normalize_enum_fields({"type": "TELEMETRY_QUERY"}, "item.create")["type"], 24)
        self.assertEqual(_normalize_enum_fields({"type": "TELEMETRY_QUERY"}, "itemprototype.create")["type"], 24)
        self.assertEqual(_normalize_enum_fields({"value_type": "JSON"}, "item.create")["value_type"], 6)
        self.assertEqual(_normalize_enum_fields({"type": "PUSH"}, "mediatype.create")["type"], 5)


if __name__ == "__main__":
    unittest.main()
