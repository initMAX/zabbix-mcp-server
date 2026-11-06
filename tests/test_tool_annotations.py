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

"""What ``tools/list`` tells a client about a tool before it is called.

Until 1.42 only the delete tools and ``script_execute`` said they were
destructive and nothing said it was not, so every create tool was announced
with the specification's default (destructive); the ``idempotentHint`` branch
could not be reached, and every tool claimed to reach an open world.
"""

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mcp.server.mcpserver import MCPServer  # noqa: E402

from zabbix_mcp.api import ALL_METHODS  # noqa: E402
from zabbix_mcp.api.annotations import OPEN_WORLD, WRITE_VERBS, annotations_for, verb  # noqa: E402
from zabbix_mcp.client import ClientManager  # noqa: E402
from zabbix_mcp.config import AppConfig, ServerConfig, ZabbixServerConfig  # noqa: E402
from zabbix_mcp.server import (  # noqa: E402
    _build_write_tools_set, _register_tools, _report_generate_annotations,
)

BY_TOOL = {m.tool_name: m for m in ALL_METHODS}


def _hints(tool: str) -> dict:
    return annotations_for(tool, BY_TOOL[tool].read_only)


def _registered() -> dict:
    cfg = AppConfig(server=ServerConfig(timezone="UTC"),
                    zabbix_servers={"t": ZabbixServerConfig(name="t", url="http://localhost", api_token="x", read_only=False)})
    mcp = MCPServer(name="test")
    _register_tools(mcp, ClientManager(cfg))
    return {t.name: t.annotations for t in mcp._tool_manager.list_tools()}


REGISTERED = _registered()


class TestClassification(unittest.TestCase):
    def test_every_write_verb_is_classified_on_purpose(self):
        # a new verb must not slide into the worst-case fallback unnoticed
        for method in ALL_METHODS:
            if not method.read_only:
                self.assertIn(verb(method.tool_name), WRITE_VERBS, method.tool_name)

    def test_no_classified_verb_is_left_without_a_tool(self):
        used = {verb(m.tool_name) for m in ALL_METHODS if not m.read_only}
        self.assertEqual(set(WRITE_VERBS) - used, set())

    def test_a_create_only_adds(self):
        for tool in ("host_create", "usermacro_createglobal", "history_push", "task_create", "host_massadd"):
            hints = _hints(tool)
            self.assertIs(hints["readOnlyHint"], False, tool)
            self.assertIs(hints["destructiveHint"], False, tool)
            self.assertIs(hints["idempotentHint"], False, tool)

    def test_an_update_overwrites_and_can_be_repeated(self):
        for tool in ("host_update", "host_massupdate", "usermacro_updateglobal", "settings_update",
                     "hostgroup_propagate", "configuration_import", "user_provision"):
            hints = _hints(tool)
            self.assertIs(hints["destructiveHint"], True, tool)
            self.assertIs(hints["idempotentHint"], True, tool)

    def test_a_delete_removes_and_a_repeat_removes_nothing_more(self):
        for tool in ("host_delete", "usermacro_deleteglobal", "host_massremove", "history_clear",
                     "user_resettotp", "device_offboard"):
            hints = _hints(tool)
            self.assertIs(hints["destructiveHint"], True, tool)
            self.assertIs(hints["idempotentHint"], True, tool)

    def test_what_happens_once_more_on_every_call(self):
        for tool in ("script_execute", "event_acknowledge", "token_generate"):
            hints = _hints(tool)
            self.assertIs(hints["destructiveHint"], True, tool)
            self.assertIs(hints["idempotentHint"], False, tool)

    def test_a_read_says_only_that_it_reads(self):
        for tool in ("host_get", "configuration_export", "sla_getsli", "apiinfo_version", "user_checkauthentication"):
            self.assertEqual(_hints(tool), {"readOnlyHint": True, "openWorldHint": False}, tool)

    def test_a_login_leaves_a_session_behind(self):
        # a write since 1.42.2: it tries a password against Zabbix and opens a session
        self.assertFalse(BY_TOOL["user_login"].read_only)
        self.assertEqual(_hints("user_login"), {"readOnlyHint": False, "destructiveHint": False,
                                                "idempotentHint": False, "openWorldHint": False})

    def test_a_directory_test_is_not_for_a_read_only_token(self):
        # Zabbix adds the stored bind password and connects to the host given in the call
        self.assertFalse(BY_TOOL["userdirectory_test"].read_only)
        self.assertEqual(_hints("userdirectory_test"), {"readOnlyHint": False, "destructiveHint": False,
                                                        "idempotentHint": True, "openWorldHint": True})

    def test_only_what_makes_zabbix_reach_outside_is_open_world(self):
        for name in OPEN_WORLD:
            self.assertIn(name, BY_TOOL)
        opened = {m.tool_name for m in ALL_METHODS if _hints(m.tool_name)["openWorldHint"]}
        self.assertEqual(opened, {"script_execute", "userdirectory_test"})

    def test_an_unknown_verb_is_the_worst_case(self):
        self.assertEqual(annotations_for("host_frobnicate", False),
                         {"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False,
                          "openWorldHint": False})


class TestAsRegistered(unittest.TestCase):
    def test_no_tool_is_left_to_the_defaults(self):
        for name, hints in REGISTERED.items():
            self.assertIsNotNone(hints, name)
            self.assertIsNotNone(hints.read_only_hint, name)
            self.assertIsNotNone(hints.open_world_hint, name)
            if hints.read_only_hint is False:
                self.assertIsNotNone(hints.destructive_hint, name)
                self.assertIsNotNone(hints.idempotent_hint, name)

    def test_the_catalog_tools_carry_their_classification(self):
        for method in ALL_METHODS:
            want = _hints(method.tool_name)
            got = REGISTERED[method.tool_name]
            self.assertEqual(got.read_only_hint, want["readOnlyHint"], method.tool_name)
            self.assertEqual(got.destructive_hint, want.get("destructiveHint"), method.tool_name)
            self.assertEqual(got.idempotent_hint, want.get("idempotentHint"), method.tool_name)
            self.assertEqual(got.open_world_hint, want["openWorldHint"], method.tool_name)

    def test_the_extension_tools(self):
        for name in ("health_check", "problem_active_get", "host_status_get", "item_history_summary_get",
                     "anomaly_detect", "capacity_forecast", "graph_render", "action_prepare"):
            self.assertIs(REGISTERED[name].read_only_hint, True, name)
            self.assertIs(REGISTERED[name].open_world_hint, False, name)
        raw = REGISTERED["zabbix_raw_api_call"]   # any method
        self.assertEqual((raw.read_only_hint, raw.destructive_hint, raw.idempotent_hint, raw.open_world_hint),
                         (False, True, False, True))
        confirm = REGISTERED["action_confirm"]    # any prepared method, once
        self.assertEqual((confirm.read_only_hint, confirm.destructive_hint, confirm.idempotent_hint,
                          confirm.open_world_hint), (False, True, True, True))

    def test_the_hint_agrees_with_what_a_read_only_token_is_shown(self):
        # a tool hidden from a read-only token says it writes, and the other
        # way round; the preview half of the approval flow is the deliberate difference
        writes = _build_write_tools_set()
        for name, hints in REGISTERED.items():
            if name == "action_prepare":
                continue
            self.assertEqual(hints.read_only_hint is False, name in writes, name)
        self.assertIn("user_login", writes)
        self.assertIn("userdirectory_test", writes)
        self.assertIn("action_prepare", writes)


class TestReportGenerate(unittest.TestCase):
    """The tool is not registered without weasyprint; its hints are a function."""

    @staticmethod
    def _reporting(output_dir="", mail=False):
        return SimpleNamespace(output_dir=output_dir, email=SimpleNamespace(enabled=mail))

    def test_a_link_only_setup_reads(self):
        self.assertEqual(_report_generate_annotations(self._reporting()),
                         {"readOnlyHint": True, "openWorldHint": False})

    def test_a_report_directory_makes_it_a_write_that_adds(self):
        self.assertEqual(_report_generate_annotations(self._reporting(output_dir="/var/reports")),
                         {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False,
                          "openWorldHint": False})

    def test_mail_delivery_reaches_outside(self):
        hints = _report_generate_annotations(self._reporting(mail=True))
        self.assertIs(hints["readOnlyHint"], False)
        self.assertIs(hints["openWorldHint"], True)


if __name__ == "__main__":
    unittest.main()
