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

"""Plugin loader discovery + manifest validation tests (issue #47)."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path


_GOOD_MANIFEST = {
    "id": "zabbix",
    "name": "Zabbix",
    "version": "1.31",
    "transport": "stdio",
    "tool_prefix": "",
}


class TestManifestValidator(unittest.TestCase):
    """Schema contract: required fields + format guards."""

    def _validate(self, data, path=Path("/dev/null")):
        from zabbix_mcp.plugin_loader import _validate_manifest
        return _validate_manifest(data, path)

    def test_good_manifest_passes(self):
        record = self._validate(_GOOD_MANIFEST.copy())
        self.assertEqual(record.id, "zabbix")
        self.assertEqual(record.version, "1.31")

    def test_missing_required_id_fails(self):
        from zabbix_mcp.plugin_loader import PluginManifestError
        bad = _GOOD_MANIFEST.copy()
        bad.pop("id")
        with self.assertRaises(PluginManifestError):
            self._validate(bad)

    def test_bad_id_charset_fails(self):
        from zabbix_mcp.plugin_loader import PluginManifestError
        for bad_id in ("Zabbix", "1zabbix", "zabbix$", "zabbix/sub", ""):
            bad = _GOOD_MANIFEST.copy()
            bad["id"] = bad_id
            with self.assertRaises(PluginManifestError):
                self._validate(bad)

    def test_invalid_transport_fails(self):
        from zabbix_mcp.plugin_loader import PluginManifestError
        bad = _GOOD_MANIFEST.copy()
        bad["transport"] = "http"
        with self.assertRaises(PluginManifestError):
            self._validate(bad)

    def test_bad_tool_prefix_fails(self):
        from zabbix_mcp.plugin_loader import PluginManifestError
        bad = _GOOD_MANIFEST.copy()
        bad["tool_prefix"] = "Zabbix"   # uppercase letter
        with self.assertRaises(PluginManifestError):
            self._validate(bad)

    def test_empty_tool_prefix_allowed(self):
        # The bundled Zabbix module ships with tool_prefix="" so
        # tools surface unprefixed (host_get, problem_get, ...).
        record = self._validate(_GOOD_MANIFEST.copy())
        self.assertEqual(record.tool_prefix, "")

    def test_missing_optional_fields_default(self):
        record = self._validate(_GOOD_MANIFEST.copy())
        self.assertEqual(record.description, "")
        self.assertEqual(record.author, "")
        self.assertEqual(record.tool_groups, [])
        self.assertEqual(record.write_patterns, [])
        self.assertEqual(record.report_templates, [])

    def test_optional_lists_passed_through(self):
        data = _GOOD_MANIFEST.copy()
        data["tool_groups"] = ["monitoring", "alerts"]
        data["report_templates"] = ["availability", "capacity_host"]
        record = self._validate(data)
        self.assertEqual(record.tool_groups, ["monitoring", "alerts"])
        self.assertEqual(record.report_templates, ["availability", "capacity_host"])

    def test_non_dict_manifest_fails(self):
        from zabbix_mcp.plugin_loader import PluginManifestError
        with self.assertRaises(PluginManifestError):
            self._validate(["not", "a", "dict"])


class TestPluginDiscovery(unittest.TestCase):
    """End-to-end: a tmp plugins/ tree is walked and validated."""

    def test_bundled_zabbix_manifest_loads(self):
        # The real plugin.json that ships in the repo. Confirms the
        # bundled manifest stays schema-valid as fields evolve.
        from zabbix_mcp.plugin_loader import discover
        records = discover()
        ids = {r.id for r in records}
        self.assertIn("zabbix", ids)
        zbx = next(r for r in records if r.id == "zabbix")
        self.assertTrue(zbx.bundled)
        self.assertEqual(zbx.transport, "stdio")

    def test_bad_manifest_skipped_not_crash(self):
        from zabbix_mcp.plugin_loader import _discover_in
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            # Good plugin in subdir.
            good_dir = root / "okplugin"
            good_dir.mkdir()
            (good_dir / "plugin.json").write_text(json.dumps(_GOOD_MANIFEST))
            # Broken plugin in subdir.
            bad_dir = root / "badplugin"
            bad_dir.mkdir()
            (bad_dir / "plugin.json").write_text("not json")
            # Missing-id plugin in subdir.
            half_dir = root / "halfplugin"
            half_dir.mkdir()
            (half_dir / "plugin.json").write_text('{"name": "x"}')
            records = _discover_in(root)
            ids = {r.id for r in records}
            self.assertEqual(ids, {"zabbix"})  # only the good one


class TestFindByPluginId(unittest.TestCase):
    def test_find_zabbix(self):
        from zabbix_mcp.plugin_loader import find
        r = find("zabbix")
        self.assertIsNotNone(r)
        self.assertEqual(r.id, "zabbix")

    def test_find_unknown_returns_none(self):
        from zabbix_mcp.plugin_loader import find
        self.assertIsNone(find("does-not-exist"))


if __name__ == "__main__":
    unittest.main()
