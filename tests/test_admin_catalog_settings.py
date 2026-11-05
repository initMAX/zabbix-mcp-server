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

"""The admin portal's Tools section carries the five catalog switches
(``register_write_tools``, ``strip_write_params``, ``validate_get_params``,
``schema_constraints``, ``reject_unknown_arguments``) as checkboxes: present = true,
absent = false, and ``load_config`` reads back what the form wrote."""

import sys
import unittest

sys.path.insert(0, "src")
sys.path.insert(0, "tests")

from test_admin_timezone import _Base, _Req, _run  # noqa: E402

from zabbix_mcp.admin.views import settings as settings_views  # noqa: E402
from zabbix_mcp.config import load_config  # noqa: E402

KEYS = ("register_write_tools", "strip_write_params", "validate_get_params", "schema_constraints",
        "reject_unknown_arguments")


class TestCatalogSwitches(_Base):
    def _save(self, **form):
        base = {"tools": "", "disabled_tools": "", "_cfg_mtime": ""}
        base.update(form)
        return _run(settings_views.settings_update(_Req(self.app, base, path_params={"section": "tools"})))

    def test_keys_are_allowed_booleans_that_need_a_restart(self):
        for key in KEYS:
            self.assertIn(key, settings_views.SECTION_CONFIG["tools"]["allowed_keys"])
            self.assertIn(key, settings_views.BOOL_KEYS)
            self.assertIn(key, settings_views.RESTART_REQUIRED)

    def test_unchecked_boxes_write_false_and_checked_write_true(self):
        resp = self._save()   # every box absent
        self.assertEqual(resp.status_code, 303)
        cfg = load_config(self.path)
        self.assertFalse(cfg.server.register_write_tools)
        self.assertFalse(cfg.server.strip_write_params)
        self.assertFalse(cfg.server.validate_get_params)
        self.assertFalse(cfg.server.schema_constraints)
        self.assertFalse(cfg.server.reject_unknown_arguments)
        self._save(register_write_tools="true", strip_write_params="true", validate_get_params="true",
                   schema_constraints="true", reject_unknown_arguments="true")
        cfg = load_config(self.path)
        self.assertTrue(cfg.server.register_write_tools)
        self.assertTrue(cfg.server.strip_write_params)
        self.assertTrue(cfg.server.validate_get_params)
        self.assertTrue(cfg.server.schema_constraints)
        self.assertTrue(cfg.server.reject_unknown_arguments)

    def test_settings_view_exposes_the_switches(self):
        self._save(register_write_tools="true")
        _run(settings_views.settings_view(_Req(self.app, {}, method="GET")))
        ctx = self.app.render.call_args.args[2]
        self.assertTrue(ctx["settings"]["register_write_tools"])
        self.assertFalse(ctx["settings"]["strip_write_params"])


class TestToolBubbles(_Base):
    def test_settings_bubbles_come_from_tool_groups(self):
        """The drag-and-drop tool list was a copy of TOOL_GROUPS in the template
        and missed every v1.41 prefix; it is rendered from the catalog now."""
        from zabbix_mcp.config import TOOL_GROUPS
        _run(settings_views.settings_view(_Req(self.app, {}, method="GET")))
        ctx = self.app.render.call_args.args[2]
        data = {g["name"]: g["tools"] for g in ctx["tool_data"]}
        self.assertEqual(set(data), set(TOOL_GROUPS))
        for prefix in ("service", "apmtrace", "apmmetric"):
            self.assertIn(prefix, data["monitoring"])
        for prefix in ("apiinfo", "serverinfo", "device"):
            self.assertIn(prefix, data["administration"])


if __name__ == "__main__":
    unittest.main()
