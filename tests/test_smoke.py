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

"""Smoke tests — no live Zabbix server required."""

import asyncio
import os
import tempfile
import unittest

from zabbix_mcp import __version__
from zabbix_mcp.config import (
    AppConfig,
    ConfigError,
    ServerConfig,
    ZabbixServerConfig,
    load_config,
)
from zabbix_mcp.client import ClientManager, RateLimitError, ReadOnlyError, _RateLimiter
from zabbix_mcp.server import (
    _auto_wrap_arrays,
    _BearerTokenVerifier,
    _build_zabbix_params,
    _normalize_enum_fields,
    _normalize_import_rules,
    _normalize_nested_dchecks,
    _normalize_nested_interfaces,
    _normalize_preprocessing,
    _normalize_timestamps,
    _register_tools,
    _resolve_source_file,
    _snake_to_camel,
    _validate_import_uuids,
)
from zabbix_mcp.api import ALL_METHODS
from zabbix_mcp.api.types import MethodDef, ParamDef


def _make_config(**server_overrides):
    srv = ServerConfig(**server_overrides)
    return AppConfig(
        server=srv,
        zabbix_servers={
            "test": ZabbixServerConfig(
                name="test", url="http://localhost", api_token="dummy"
            )
        },
    )


class TestVersion(unittest.TestCase):
    def test_version_is_string(self):
        self.assertIsInstance(__version__, str)
        self.assertTrue(len(__version__) > 0)


class TestConfig(unittest.TestCase):
    def test_load_minimal_config(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write('[zabbix.prod]\nurl = "http://z"\napi_token = "tok"\n')
            f.flush()
            cfg = load_config(f.name)
        os.unlink(f.name)
        self.assertEqual(cfg.default_server, "prod")
        self.assertEqual(cfg.zabbix_servers["prod"].url, "http://z")
        self.assertTrue(cfg.zabbix_servers["prod"].read_only)

    def test_missing_file_raises(self):
        with self.assertRaises(ConfigError):
            load_config("/nonexistent/path.toml")

    def test_no_zabbix_section_raises(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write('[server]\ntransport = "stdio"\n')
            f.flush()
            with self.assertRaises(ConfigError):
                load_config(f.name)
        os.unlink(f.name)

    def test_env_var_resolution(self):
        os.environ["_TEST_TOKEN"] = "secret123"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write('[zabbix.prod]\nurl = "http://z"\napi_token = "${_TEST_TOKEN}"\n')
            f.flush()
            cfg = load_config(f.name)
        os.unlink(f.name)
        del os.environ["_TEST_TOKEN"]
        self.assertEqual(cfg.zabbix_servers["prod"].api_token, "secret123")

    def test_missing_env_var_raises(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write('[zabbix.prod]\nurl = "http://z"\napi_token = "${_NONEXISTENT_VAR}"\n')
            f.flush()
            with self.assertRaises(ConfigError):
                load_config(f.name)
        os.unlink(f.name)

    def test_defaults(self):
        cfg = _make_config()
        self.assertEqual(cfg.server.transport, "stdio")
        self.assertEqual(cfg.server.host, "127.0.0.1")
        self.assertEqual(cfg.server.port, 8080)
        self.assertEqual(cfg.server.rate_limit, 300)
        self.assertIsNone(cfg.server.auth_token)
        self.assertIsNone(cfg.server.log_file)
        self.assertIsNone(cfg.server.tls_cert_file)
        self.assertIsNone(cfg.server.tls_key_file)
        self.assertIsNone(cfg.server.cors_origins)
        self.assertIsNone(cfg.server.allowed_import_dirs)
        self.assertIsNone(cfg.server.allowed_hosts)

    def test_multiple_servers(self):
        cfg = AppConfig(
            zabbix_servers={
                "a": ZabbixServerConfig(name="a", url="http://a", api_token="t1"),
                "b": ZabbixServerConfig(name="b", url="http://b", api_token="t2"),
            }
        )
        self.assertEqual(cfg.default_server, "a")
        self.assertEqual(len(cfg.zabbix_servers), 2)


class TestClientManager(unittest.TestCase):
    def test_resolve_server_default(self):
        mgr = ClientManager(_make_config())
        self.assertEqual(mgr.resolve_server(None), "test")

    def test_resolve_server_explicit(self):
        mgr = ClientManager(_make_config())
        self.assertEqual(mgr.resolve_server("test"), "test")

    def test_resolve_unknown_server_raises(self):
        mgr = ClientManager(_make_config())
        with self.assertRaises(ValueError):
            mgr.resolve_server("nonexistent")

    def test_check_write_readonly(self):
        mgr = ClientManager(_make_config())
        with self.assertRaises(ReadOnlyError):
            mgr.check_write("test")

    def test_check_write_readwrite(self):
        cfg = AppConfig(
            zabbix_servers={
                "rw": ZabbixServerConfig(
                    name="rw", url="http://z", api_token="t", read_only=False
                )
            }
        )
        mgr = ClientManager(cfg)
        mgr.check_write("rw")  # should not raise


class TestRateLimiter(unittest.TestCase):
    def test_allows_within_limit(self):
        rl = _RateLimiter(5)
        for _ in range(5):
            rl.check()

    def test_blocks_over_limit(self):
        rl = _RateLimiter(3)
        for _ in range(3):
            rl.check()
        with self.assertRaises(RateLimitError):
            rl.check()

    def test_disabled_when_zero(self):
        rl = _RateLimiter(0)
        for _ in range(1000):
            rl.check()


class TestAuth(unittest.TestCase):
    def test_valid_token(self):
        v = _BearerTokenVerifier("abc")
        result = asyncio.run(v.verify_token("abc"))
        self.assertIsNotNone(result)
        self.assertEqual(result.client_id, "mcp-client")

    def test_invalid_token(self):
        v = _BearerTokenVerifier("abc")
        result = asyncio.run(v.verify_token("wrong"))
        self.assertIsNone(result)


class TestAPIRegistry(unittest.TestCase):
    def test_methods_not_empty(self):
        self.assertGreater(len(ALL_METHODS), 200)

    def test_unique_tool_names(self):
        names = [m.tool_name for m in ALL_METHODS]
        self.assertEqual(len(names), len(set(names)))

    def test_unique_api_methods(self):
        methods = [m.api_method for m in ALL_METHODS]
        self.assertEqual(len(methods), len(set(methods)))


class TestToolRegistration(unittest.TestCase):
    def test_register_all_tools(self):
        from mcp.server.fastmcp import FastMCP

        cfg = _make_config()
        mgr = ClientManager(cfg)
        mcp = FastMCP(name="test")
        count = _register_tools(mcp, mgr)
        tools = mcp._tool_manager.list_tools()
        self.assertEqual(len(tools), count)
        # ALL_METHODS + raw_api_call + extensions (report_generate, action_prepare/confirm, etc.)
        self.assertGreaterEqual(count, len(ALL_METHODS) + 2)

    def test_key_tools_present(self):
        from mcp.server.fastmcp import FastMCP

        cfg = _make_config()
        mgr = ClientManager(cfg)
        mcp = FastMCP(name="test")
        _register_tools(mcp, mgr)
        names = {t.name for t in mcp._tool_manager.list_tools()}
        for expected in [
            "host_get", "problem_get", "trigger_get", "item_get",
            "event_acknowledge", "template_get", "user_get",
            "zabbix_raw_api_call", "health_check",
        ]:
            self.assertIn(expected, names)

    def test_tools_have_descriptions(self):
        from mcp.server.fastmcp import FastMCP

        cfg = _make_config()
        mgr = ClientManager(cfg)
        mcp = FastMCP(name="test")
        _register_tools(mcp, mgr)
        for tool in mcp._tool_manager.list_tools():
            self.assertTrue(tool.description, f"Tool {tool.name} has no description")

    def test_tools_have_parameters(self):
        from mcp.server.fastmcp import FastMCP

        cfg = _make_config()
        mgr = ClientManager(cfg)
        mcp = FastMCP(name="test")
        _register_tools(mcp, mgr)
        for tool in mcp._tool_manager.list_tools():
            self.assertIn("properties", tool.parameters)


class TestImportRulesNormalization(unittest.TestCase):
    def test_snake_to_camel_basic(self):
        self.assertEqual(_snake_to_camel("discovery_rules"), "discoveryRules")
        self.assertEqual(_snake_to_camel("value_maps"), "valueMaps")
        self.assertEqual(_snake_to_camel("template_dashboards"), "templateDashboards")
        self.assertEqual(_snake_to_camel("template_linkage"), "templateLinkage")
        self.assertEqual(_snake_to_camel("media_types"), "mediaTypes")

    def test_snake_to_camel_no_underscore(self):
        self.assertEqual(_snake_to_camel("hosts"), "hosts")
        self.assertEqual(_snake_to_camel("templates"), "templates")

    def test_normalize_converts_snake_case_rules(self):
        params = {
            "format": "yaml",
            "source": "<data>",
            "rules": {
                "templates": {"createMissing": True},
                "discovery_rules": {"createMissing": True, "updateExisting": True},
                "value_maps": {"createMissing": True},
            },
        }
        result = _normalize_import_rules(params)
        self.assertIn("discoveryRules", result["rules"])
        self.assertIn("valueMaps", result["rules"])
        self.assertIn("templates", result["rules"])
        self.assertNotIn("discovery_rules", result["rules"])
        self.assertNotIn("value_maps", result["rules"])

    def test_normalize_preserves_camel_case(self):
        params = {
            "format": "yaml",
            "source": "<data>",
            "rules": {
                "discoveryRules": {"createMissing": True},
                "templates": {"createMissing": True},
            },
        }
        result = _normalize_import_rules(params)
        self.assertIn("discoveryRules", result["rules"])
        self.assertIn("templates", result["rules"])

    def test_normalize_no_rules_key(self):
        params = {"format": "yaml", "source": "<data>"}
        result = _normalize_import_rules(params)
        self.assertEqual(result, params)

    def test_normalize_preserves_other_params(self):
        params = {
            "format": "json",
            "source": "{}",
            "rules": {"discovery_rules": {"createMissing": True}},
        }
        result = _normalize_import_rules(params)
        self.assertEqual(result["format"], "json")
        self.assertEqual(result["source"], "{}")

    # --- host_groups / template_groups must stay snake_case (Zabbix >=6.2 API) ---

    def test_host_groups_stays_snake_case(self):
        params = {"format": "yaml", "source": "", "rules": {
            "host_groups": {"createMissing": True},
            "template_groups": {"createMissing": True},
        }}
        result = _normalize_import_rules(params)
        self.assertIn("host_groups", result["rules"])
        self.assertIn("template_groups", result["rules"])
        self.assertNotIn("hostGroups", result["rules"])
        self.assertNotIn("templateGroups", result["rules"])

    def test_camel_hostGroups_converted_to_snake(self):
        """LLM generates camelCase hostGroups/templateGroups — must become snake_case."""
        params = {"format": "yaml", "source": "", "rules": {
            "hostGroups": {"createMissing": True},
            "templateGroups": {"updateExisting": True},
        }}
        result = _normalize_import_rules(params)
        self.assertIn("host_groups", result["rules"])
        self.assertIn("template_groups", result["rules"])
        self.assertNotIn("hostGroups", result["rules"])
        self.assertNotIn("templateGroups", result["rules"])

    # --- version-aware group fixup ---

    def test_version_62_groups_split(self):
        """Zabbix >=6.2: 'groups' should be split into host_groups + template_groups."""
        params = {"format": "yaml", "source": "", "rules": {
            "groups": {"createMissing": True},
        }}
        result = _normalize_import_rules(params, zabbix_version="7.0.0")
        self.assertIn("host_groups", result["rules"])
        self.assertIn("template_groups", result["rules"])
        self.assertNotIn("groups", result["rules"])

    def test_version_60_merges_to_groups(self):
        """Zabbix <6.2: host_groups/template_groups should merge into 'groups'."""
        params = {"format": "yaml", "source": "", "rules": {
            "host_groups": {"createMissing": True},
            "template_groups": {"updateExisting": True},
        }}
        result = _normalize_import_rules(params, zabbix_version="6.0.30")
        self.assertIn("groups", result["rules"])
        self.assertNotIn("host_groups", result["rules"])
        self.assertNotIn("template_groups", result["rules"])

    def test_version_60_camel_groups_merge(self):
        """Zabbix <6.2: camelCase hostGroups/templateGroups also merge into 'groups'."""
        params = {"format": "yaml", "source": "", "rules": {
            "hostGroups": {"createMissing": True},
            "templateGroups": {"updateExisting": True},
        }}
        result = _normalize_import_rules(params, zabbix_version="6.0.0")
        self.assertIn("groups", result["rules"])
        self.assertNotIn("hostGroups", result["rules"])
        self.assertNotIn("templateGroups", result["rules"])
        self.assertNotIn("host_groups", result["rules"])
        self.assertNotIn("template_groups", result["rules"])


class TestPreprocessingNormalization(unittest.TestCase):
    def test_symbolic_name_resolved(self):
        params = {"preprocessing": [{"type": "JSONPATH", "params": "$.value"}]}
        result = _normalize_preprocessing(params)
        self.assertEqual(result["preprocessing"][0]["type"], 12)

    def test_discard_unchanged_heartbeat(self):
        """The exact case from the user report — type 20, not 29."""
        params = {"preprocessing": [
            {"type": "DISCARD_UNCHANGED_HEARTBEAT", "params": "3600"},
        ]}
        result = _normalize_preprocessing(params)
        self.assertEqual(result["preprocessing"][0]["type"], 20)

    def test_snmp_get_value(self):
        """Type 30 — added in Zabbix 7.0."""
        params = {"preprocessing": [{"type": "SNMP_GET_VALUE", "params": "1"}]}
        result = _normalize_preprocessing(params)
        self.assertEqual(result["preprocessing"][0]["type"], 30)

    def test_case_insensitive(self):
        params = {"preprocessing": [{"type": "jsonpath", "params": "$.x"}]}
        result = _normalize_preprocessing(params)
        self.assertEqual(result["preprocessing"][0]["type"], 12)

    def test_numeric_int_passthrough(self):
        params = {"preprocessing": [{"type": 12, "params": "$.x"}]}
        result = _normalize_preprocessing(params)
        self.assertEqual(result["preprocessing"][0]["type"], 12)

    def test_numeric_string_passthrough(self):
        params = {"preprocessing": [{"type": "12", "params": "$.x"}]}
        result = _normalize_preprocessing(params)
        self.assertEqual(result["preprocessing"][0]["type"], "12")

    def test_unknown_name_passthrough(self):
        """Unknown names pass through so Zabbix API returns a clear error."""
        params = {"preprocessing": [{"type": "NONEXISTENT_TYPE", "params": ""}]}
        result = _normalize_preprocessing(params)
        self.assertEqual(result["preprocessing"][0]["type"], "NONEXISTENT_TYPE")

    def test_no_preprocessing_key(self):
        params = {"name": "test item", "key_": "test.key"}
        result = _normalize_preprocessing(params)
        self.assertEqual(result, params)

    def test_multiple_steps(self):
        params = {"preprocessing": [
            {"type": "JSONPATH", "params": "$.value"},
            {"type": "MULTIPLIER", "params": "1024"},
            {"type": "DISCARD_UNCHANGED_HEARTBEAT", "params": "600"},
        ]}
        result = _normalize_preprocessing(params)
        self.assertEqual(result["preprocessing"][0]["type"], 12)
        self.assertEqual(result["preprocessing"][1]["type"], 1)
        self.assertEqual(result["preprocessing"][2]["type"], 20)

    def test_mixed_numeric_and_symbolic(self):
        params = {"preprocessing": [
            {"type": 12, "params": "$.value"},
            {"type": "MULTIPLIER", "params": "1024"},
        ]}
        result = _normalize_preprocessing(params)
        self.assertEqual(result["preprocessing"][0]["type"], 12)
        self.assertEqual(result["preprocessing"][1]["type"], 1)

    def test_error_handler_symbolic(self):
        params = {"preprocessing": [
            {"type": "JSONPATH", "params": "$.x", "error_handler": "DISCARD_VALUE"},
        ]}
        result = _normalize_preprocessing(params)
        self.assertEqual(result["preprocessing"][0]["error_handler"], 1)

    def test_error_handler_set_error(self):
        params = {"preprocessing": [
            {"type": 12, "error_handler": "SET_ERROR", "error_handler_params": "Failed"},
        ]}
        result = _normalize_preprocessing(params)
        self.assertEqual(result["preprocessing"][0]["error_handler"], 3)

    def test_error_handler_int_passthrough(self):
        params = {"preprocessing": [{"type": 12, "error_handler": 0}]}
        result = _normalize_preprocessing(params)
        self.assertEqual(result["preprocessing"][0]["error_handler"], 0)

    def test_preserves_other_params(self):
        params = {
            "name": "CPU load",
            "key_": "system.cpu.load",
            "preprocessing": [{"type": "JSONPATH", "params": "$.value"}],
        }
        result = _normalize_preprocessing(params)
        self.assertEqual(result["name"], "CPU load")
        self.assertEqual(result["key_"], "system.cpu.load")

    def test_build_zabbix_params_applies_normalization(self):
        """Verify preprocessing normalization is applied in the full pipeline."""
        md = MethodDef("item.create", "item_create", "d", read_only=False,
                        params=[ParamDef("params", "dict", "d", required=True)])
        result = _build_zabbix_params(md, {"params": {
            "name": "test",
            "preprocessing": [{"type": "DISCARD_UNCHANGED_HEARTBEAT", "params": "3600"}],
        }})
        self.assertEqual(result["preprocessing"][0]["type"], 20)

    # --- error_handler aliases ---
    def test_error_handler_custom_value(self):
        params = {"preprocessing": [
            {"type": 12, "error_handler": "CUSTOM_VALUE", "error_handler_params": "0"},
        ]}
        result = _normalize_preprocessing(params)
        self.assertEqual(result["preprocessing"][0]["error_handler"], 2)

    def test_error_handler_custom_error(self):
        params = {"preprocessing": [
            {"type": 12, "error_handler": "CUSTOM_ERROR", "error_handler_params": "Err"},
        ]}
        result = _normalize_preprocessing(params)
        self.assertEqual(result["preprocessing"][0]["error_handler"], 3)

    # --- auto-fill error_handler ---
    def test_auto_fill_error_handler_on_jsonpath(self):
        """JSONPATH step missing error_handler → auto-fill with 0."""
        params = {"preprocessing": [{"type": 12, "params": "$.value"}]}
        result = _normalize_preprocessing(params)
        self.assertEqual(result["preprocessing"][0]["error_handler"], 0)
        self.assertEqual(result["preprocessing"][0]["error_handler_params"], "")

    def test_auto_fill_error_handler_on_regex(self):
        params = {"preprocessing": [{"type": 5, "params": "(.*)\\s+(.*)"}]}
        result = _normalize_preprocessing(params)
        self.assertEqual(result["preprocessing"][0]["error_handler"], 0)
        self.assertEqual(result["preprocessing"][0]["error_handler_params"], "")

    def test_auto_fill_error_handler_params_only(self):
        """error_handler set but error_handler_params missing → auto-fill params."""
        params = {"preprocessing": [{"type": 12, "params": "$.x", "error_handler": 1}]}
        result = _normalize_preprocessing(params)
        self.assertEqual(result["preprocessing"][0]["error_handler"], 1)
        self.assertEqual(result["preprocessing"][0]["error_handler_params"], "")

    def test_no_auto_fill_when_both_present(self):
        """Both already present → don't change."""
        params = {"preprocessing": [
            {"type": 12, "params": "$.x", "error_handler": 2, "error_handler_params": "0"},
        ]}
        result = _normalize_preprocessing(params)
        self.assertEqual(result["preprocessing"][0]["error_handler"], 2)
        self.assertEqual(result["preprocessing"][0]["error_handler_params"], "0")

    # --- auto-strip error_handler from DISCARD steps ---
    def test_strip_error_handler_from_discard_unchanged(self):
        params = {"preprocessing": [
            {"type": 19, "params": "", "error_handler": 0, "error_handler_params": ""},
        ]}
        result = _normalize_preprocessing(params)
        self.assertNotIn("error_handler", result["preprocessing"][0])
        self.assertNotIn("error_handler_params", result["preprocessing"][0])

    def test_strip_error_handler_from_discard_heartbeat(self):
        params = {"preprocessing": [
            {"type": "DISCARD_UNCHANGED_HEARTBEAT", "params": "3600",
             "error_handler": "0", "error_handler_params": ""},
        ]}
        result = _normalize_preprocessing(params)
        self.assertEqual(result["preprocessing"][0]["type"], 20)
        self.assertNotIn("error_handler", result["preprocessing"][0])
        self.assertNotIn("error_handler_params", result["preprocessing"][0])

    def test_no_strip_from_other_types(self):
        """Non-DISCARD type with error_handler → keep it."""
        params = {"preprocessing": [
            {"type": 12, "params": "$.x", "error_handler": 0, "error_handler_params": ""},
        ]}
        result = _normalize_preprocessing(params)
        self.assertIn("error_handler", result["preprocessing"][0])

    def test_discard_without_error_handler_ok(self):
        """DISCARD step without error_handler → nothing to strip, no auto-fill."""
        params = {"preprocessing": [{"type": 20, "params": "3600"}]}
        result = _normalize_preprocessing(params)
        self.assertNotIn("error_handler", result["preprocessing"][0])
        self.assertNotIn("error_handler_params", result["preprocessing"][0])

    def test_mixed_steps_auto_fill_and_strip(self):
        """Pipeline with JSONPATH + DISCARD: auto-fill on first, strip on second."""
        params = {"preprocessing": [
            {"type": "JSONPATH", "params": "$.value"},
            {"type": "DISCARD_UNCHANGED_HEARTBEAT", "params": "600",
             "error_handler": 0, "error_handler_params": ""},
        ]}
        result = _normalize_preprocessing(params)
        # JSONPATH: auto-filled
        self.assertEqual(result["preprocessing"][0]["error_handler"], 0)
        self.assertEqual(result["preprocessing"][0]["error_handler_params"], "")
        # DISCARD: stripped
        self.assertNotIn("error_handler", result["preprocessing"][1])
        self.assertNotIn("error_handler_params", result["preprocessing"][1])


class TestSourceFile(unittest.TestCase):
    def test_resolve_source_file(self):
        import tempfile, os
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, dir=tempfile.gettempdir()) as f:
            f.write("zabbix_export:\n  version: '7.0'\n")
            f.flush()
            params = {"source_file": f.name, "rules": {}}
            result = _resolve_source_file(params, allowed_import_dirs=[tempfile.gettempdir()])
        os.unlink(f.name)
        self.assertIn("source", result)
        self.assertNotIn("source_file", result)
        self.assertIn("zabbix_export", result["source"])
        self.assertEqual(result["format"], "yaml")

    def test_resolve_source_file_xml(self):
        import tempfile, os
        with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False, dir=tempfile.gettempdir()) as f:
            f.write("<zabbix_export><version>7.0</version></zabbix_export>")
            f.flush()
            params = {"source_file": f.name}
            result = _resolve_source_file(params, allowed_import_dirs=[tempfile.gettempdir()])
        os.unlink(f.name)
        self.assertEqual(result["format"], "xml")

    def test_source_takes_precedence(self):
        """If both source and source_file are present, source wins."""
        params = {"source": "existing", "source_file": "/some/path"}
        result = _resolve_source_file(params)
        self.assertEqual(result["source"], "existing")

    def test_disabled_without_allowed_dirs(self):
        """source_file is disabled when allowed_import_dirs is not configured."""
        params = {"source_file": "/some/file.yaml"}
        with self.assertRaises(ValueError) as ctx:
            _resolve_source_file(params)
        self.assertIn("disabled", str(ctx.exception))

    def test_path_traversal_blocked(self):
        """Paths outside allowed directories are rejected."""
        params = {"source_file": "/etc/passwd"}
        with self.assertRaises(ValueError) as ctx:
            _resolve_source_file(params, allowed_import_dirs=["/tmp/safe"])
        self.assertIn("allowed import directories", str(ctx.exception))

    def test_missing_file_raises(self):
        import tempfile
        params = {"source_file": tempfile.gettempdir() + "/nonexistent_file_12345.yaml"}
        with self.assertRaises(ValueError):
            _resolve_source_file(params, allowed_import_dirs=[tempfile.gettempdir()])

    def test_format_not_overridden(self):
        """Explicit format is preserved even with yaml extension."""
        import tempfile, os
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, dir=tempfile.gettempdir()) as f:
            f.write("data")
            f.flush()
            params = {"source_file": f.name, "format": "json"}
            result = _resolve_source_file(params, allowed_import_dirs=[tempfile.gettempdir()])
        os.unlink(f.name)
        self.assertEqual(result["format"], "json")


class TestUuidValidation(unittest.TestCase):
    def test_valid_uuids_pass(self):
        source = "uuid: 550e8400-e29b-41d4-a716-446655440000\nuuid: a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d\n"
        _validate_import_uuids({"source": source})  # should not raise

    def test_invalid_uuid_raises(self):
        source = "uuid: not-a-valid-uuid\n"
        with self.assertRaises(ValueError) as ctx:
            _validate_import_uuids({"source": source})
        self.assertIn("not-a-valid-uuid", str(ctx.exception))

    def test_no_source_passes(self):
        _validate_import_uuids({})  # should not raise

    def test_empty_source_passes(self):
        _validate_import_uuids({"source": ""})  # should not raise

    def test_valid_uuid_without_dashes(self):
        source = "uuid: 550e8400e29b41d4a716446655440000\n"
        _validate_import_uuids({"source": source})  # should not raise


class TestEnumFieldNormalization(unittest.TestCase):
    # --- Item type ---
    def test_item_type_symbolic(self):
        result = _normalize_enum_fields({"type": "HTTP_AGENT"}, "item.create")
        self.assertEqual(result["type"], 19)

    def test_item_type_snmp_agent(self):
        result = _normalize_enum_fields({"type": "SNMP_AGENT"}, "item.create")
        self.assertEqual(result["type"], 20)

    def test_item_type_zabbix_passive(self):
        result = _normalize_enum_fields({"type": "ZABBIX_PASSIVE"}, "item.update")
        self.assertEqual(result["type"], 0)

    def test_item_type_dependent(self):
        result = _normalize_enum_fields({"type": "DEPENDENT"}, "item.create")
        self.assertEqual(result["type"], 18)

    def test_item_type_browser(self):
        result = _normalize_enum_fields({"type": "BROWSER"}, "item.create")
        self.assertEqual(result["type"], 22)

    def test_item_type_case_insensitive(self):
        result = _normalize_enum_fields({"type": "http_agent"}, "item.create")
        self.assertEqual(result["type"], 19)

    def test_item_type_numeric_passthrough(self):
        result = _normalize_enum_fields({"type": 19}, "item.create")
        self.assertEqual(result["type"], 19)

    # --- Item value_type ---
    def test_value_type_float(self):
        result = _normalize_enum_fields({"value_type": "FLOAT"}, "item.create")
        self.assertEqual(result["value_type"], 0)

    def test_value_type_text(self):
        result = _normalize_enum_fields({"value_type": "TEXT"}, "item.create")
        self.assertEqual(result["value_type"], 4)

    def test_value_type_binary(self):
        """BINARY value_type — added in Zabbix 7.0."""
        result = _normalize_enum_fields({"value_type": "BINARY"}, "item.create")
        self.assertEqual(result["value_type"], 5)

    def test_value_type_unsigned(self):
        result = _normalize_enum_fields({"value_type": "UNSIGNED"}, "item.update")
        self.assertEqual(result["value_type"], 3)

    # --- Item type + value_type together ---
    def test_item_both_fields(self):
        result = _normalize_enum_fields(
            {"type": "HTTP_AGENT", "value_type": "TEXT", "name": "test"},
            "item.create",
        )
        self.assertEqual(result["type"], 19)
        self.assertEqual(result["value_type"], 4)
        self.assertEqual(result["name"], "test")

    # --- Item prototype ---
    def test_itemprototype_type(self):
        result = _normalize_enum_fields({"type": "DEPENDENT"}, "itemprototype.create")
        self.assertEqual(result["type"], 18)

    def test_itemprototype_value_type(self):
        result = _normalize_enum_fields({"value_type": "LOG"}, "itemprototype.update")
        self.assertEqual(result["value_type"], 2)

    # --- Discovery rule ---
    def test_discoveryrule_type(self):
        result = _normalize_enum_fields({"type": "ZABBIX_ACTIVE"}, "discoveryrule.create")
        self.assertEqual(result["type"], 7)

    # --- Trigger priority ---
    def test_trigger_priority_disaster(self):
        result = _normalize_enum_fields({"priority": "DISASTER"}, "trigger.create")
        self.assertEqual(result["priority"], 5)

    def test_trigger_priority_warning(self):
        result = _normalize_enum_fields({"priority": "WARNING"}, "trigger.update")
        self.assertEqual(result["priority"], 2)

    def test_trigger_priority_not_classified(self):
        result = _normalize_enum_fields({"priority": "NOT_CLASSIFIED"}, "trigger.create")
        self.assertEqual(result["priority"], 0)

    def test_triggerprototype_priority(self):
        result = _normalize_enum_fields({"priority": "HIGH"}, "triggerprototype.create")
        self.assertEqual(result["priority"], 4)

    # --- Host interface type ---
    def test_interface_type_agent(self):
        result = _normalize_enum_fields({"type": "AGENT"}, "hostinterface.create")
        self.assertEqual(result["type"], 1)

    def test_interface_type_snmp(self):
        result = _normalize_enum_fields({"type": "SNMP"}, "hostinterface.create")
        self.assertEqual(result["type"], 2)

    def test_interface_type_jmx(self):
        result = _normalize_enum_fields({"type": "JMX"}, "hostinterface.update")
        self.assertEqual(result["type"], 4)

    # --- Media type ---
    def test_mediatype_email(self):
        result = _normalize_enum_fields({"type": "EMAIL"}, "mediatype.create")
        self.assertEqual(result["type"], 0)

    def test_mediatype_webhook(self):
        result = _normalize_enum_fields({"type": "WEBHOOK"}, "mediatype.create")
        self.assertEqual(result["type"], 4)

    # --- Script ---
    def test_script_type_ssh(self):
        result = _normalize_enum_fields({"type": "SSH"}, "script.create")
        self.assertEqual(result["type"], 2)

    def test_script_type_webhook(self):
        result = _normalize_enum_fields({"type": "WEBHOOK"}, "script.create")
        self.assertEqual(result["type"], 5)

    def test_script_type_url(self):
        result = _normalize_enum_fields({"type": "URL"}, "script.create")
        self.assertEqual(result["type"], 6)

    def test_script_scope(self):
        result = _normalize_enum_fields({"scope": "MANUAL_HOST"}, "script.create")
        self.assertEqual(result["scope"], 2)

    def test_script_execute_on(self):
        result = _normalize_enum_fields({"execute_on": "SERVER"}, "script.create")
        self.assertEqual(result["execute_on"], 1)

    def test_script_multiple_fields(self):
        result = _normalize_enum_fields(
            {"type": "SSH", "scope": "ACTION_OPERATION", "execute_on": "AGENT"},
            "script.create",
        )
        self.assertEqual(result["type"], 2)
        self.assertEqual(result["scope"], 1)
        self.assertEqual(result["execute_on"], 0)

    # --- Action eventsource ---
    def test_action_eventsource_trigger(self):
        result = _normalize_enum_fields({"eventsource": "TRIGGER"}, "action.create")
        self.assertEqual(result["eventsource"], 0)

    def test_action_eventsource_discovery(self):
        result = _normalize_enum_fields({"eventsource": "DISCOVERY"}, "action.create")
        self.assertEqual(result["eventsource"], 1)

    def test_action_eventsource_service(self):
        result = _normalize_enum_fields({"eventsource": "SERVICE"}, "action.update")
        self.assertEqual(result["eventsource"], 4)

    # --- Unknown method prefix — no normalization ---
    def test_unknown_method_passthrough(self):
        params = {"type": "SOMETHING", "name": "test"}
        result = _normalize_enum_fields(params, "dashboard.create")
        self.assertEqual(result["type"], "SOMETHING")

    # --- Preserves unrelated fields ---
    def test_preserves_other_fields(self):
        result = _normalize_enum_fields(
            {"type": "TRAPPER", "name": "test", "key_": "trap.key"},
            "item.create",
        )
        self.assertEqual(result["type"], 2)
        self.assertEqual(result["name"], "test")
        self.assertEqual(result["key_"], "trap.key")

    # --- Full pipeline via _build_zabbix_params ---
    # --- HTTP agent authtype ---
    def test_item_authtype_none(self):
        result = _normalize_enum_fields({"authtype": "NONE"}, "item.create")
        self.assertEqual(result["authtype"], 0)

    def test_item_authtype_basic(self):
        result = _normalize_enum_fields({"authtype": "BASIC"}, "item.create")
        self.assertEqual(result["authtype"], 1)

    def test_item_authtype_ntlm(self):
        result = _normalize_enum_fields({"authtype": "NTLM"}, "item.update")
        self.assertEqual(result["authtype"], 2)

    def test_item_authtype_kerberos(self):
        result = _normalize_enum_fields({"authtype": "KERBEROS"}, "item.create")
        self.assertEqual(result["authtype"], 3)

    def test_item_authtype_digest(self):
        result = _normalize_enum_fields({"authtype": "DIGEST"}, "item.create")
        self.assertEqual(result["authtype"], 4)

    # --- HTTP agent post_type ---
    def test_item_post_type_raw(self):
        result = _normalize_enum_fields({"post_type": "RAW"}, "item.create")
        self.assertEqual(result["post_type"], 0)

    def test_item_post_type_json(self):
        result = _normalize_enum_fields({"post_type": "JSON"}, "item.create")
        self.assertEqual(result["post_type"], 2)

    def test_item_post_type_numeric_passthrough(self):
        result = _normalize_enum_fields({"post_type": 2}, "item.create")
        self.assertEqual(result["post_type"], 2)

    # --- itemprototype authtype / post_type ---
    def test_itemprototype_authtype(self):
        result = _normalize_enum_fields({"authtype": "DIGEST"}, "itemprototype.create")
        self.assertEqual(result["authtype"], 4)

    # --- Proxy operating_mode ---
    def test_proxy_operating_mode_active(self):
        result = _normalize_enum_fields({"operating_mode": "ACTIVE"}, "proxy.create")
        self.assertEqual(result["operating_mode"], 0)

    def test_proxy_operating_mode_passive(self):
        result = _normalize_enum_fields({"operating_mode": "PASSIVE"}, "proxy.create")
        self.assertEqual(result["operating_mode"], 1)

    def test_proxy_operating_mode_update(self):
        result = _normalize_enum_fields({"operating_mode": "PASSIVE"}, "proxy.update")
        self.assertEqual(result["operating_mode"], 1)

    def test_proxy_operating_mode_numeric_passthrough(self):
        result = _normalize_enum_fields({"operating_mode": 0}, "proxy.create")
        self.assertEqual(result["operating_mode"], 0)

    # --- Full pipeline via _build_zabbix_params ---
    def test_build_zabbix_params_applies_enum_normalization(self):
        md = MethodDef("item.create", "item_create", "d", read_only=False,
                        params=[ParamDef("params", "dict", "d", required=True)])
        result = _build_zabbix_params(md, {"params": {
            "name": "test",
            "type": "HTTP_AGENT",
            "value_type": "TEXT",
            "authtype": "BASIC",
            "post_type": "JSON",
            "preprocessing": [{"type": "JSONPATH", "params": "$.x"}],
        }})
        self.assertEqual(result["type"], 19)
        self.assertEqual(result["value_type"], 4)
        self.assertEqual(result["authtype"], 1)
        self.assertEqual(result["post_type"], 2)
        self.assertEqual(result["preprocessing"][0]["type"], 12)

    def test_build_zabbix_params_proxy(self):
        md = MethodDef("proxy.create", "proxy_create", "d", read_only=False,
                        params=[ParamDef("params", "dict", "d", required=True)])
        result = _build_zabbix_params(md, {"params": {
            "name": "my-proxy",
            "operating_mode": "ACTIVE",
        }})
        self.assertEqual(result["operating_mode"], 0)

    # --- User macro type ---
    def test_usermacro_type_text(self):
        result = _normalize_enum_fields({"type": "TEXT"}, "usermacro.create")
        self.assertEqual(result["type"], 0)

    def test_usermacro_type_secret(self):
        result = _normalize_enum_fields({"type": "SECRET"}, "usermacro.create")
        self.assertEqual(result["type"], 1)

    def test_usermacro_type_vault(self):
        result = _normalize_enum_fields({"type": "VAULT"}, "usermacro.update")
        self.assertEqual(result["type"], 2)

    # --- Connector data_type ---
    def test_connector_data_type_item_values(self):
        result = _normalize_enum_fields({"data_type": "ITEM_VALUES"}, "connector.create")
        self.assertEqual(result["data_type"], 0)

    def test_connector_data_type_events(self):
        result = _normalize_enum_fields({"data_type": "EVENTS"}, "connector.create")
        self.assertEqual(result["data_type"], 1)

    # --- Role type ---
    def test_role_type_user(self):
        result = _normalize_enum_fields({"type": "USER"}, "role.create")
        self.assertEqual(result["type"], 1)

    def test_role_type_admin(self):
        result = _normalize_enum_fields({"type": "ADMIN"}, "role.create")
        self.assertEqual(result["type"], 2)

    def test_role_type_super_admin(self):
        result = _normalize_enum_fields({"type": "SUPER_ADMIN"}, "role.create")
        self.assertEqual(result["type"], 3)

    def test_role_type_guest(self):
        result = _normalize_enum_fields({"type": "GUEST"}, "role.update")
        self.assertEqual(result["type"], 4)


class TestNestedInterfacesNormalization(unittest.TestCase):
    def test_symbolic_type_in_interfaces(self):
        params = {"interfaces": [
            {"type": "AGENT", "main": 1, "useip": 1, "ip": "10.0.0.1", "port": "10050"},
        ]}
        result = _normalize_nested_interfaces(params)
        self.assertEqual(result["interfaces"][0]["type"], 1)

    def test_multiple_interfaces(self):
        params = {"interfaces": [
            {"type": "AGENT", "main": 1, "useip": 1, "ip": "10.0.0.1", "port": "10050"},
            {"type": "SNMP", "main": 1, "useip": 1, "ip": "10.0.0.1", "port": "161"},
            {"type": "JMX", "main": 1, "useip": 1, "ip": "10.0.0.1", "port": "12345"},
        ]}
        result = _normalize_nested_interfaces(params)
        self.assertEqual(result["interfaces"][0]["type"], 1)
        self.assertEqual(result["interfaces"][1]["type"], 2)
        self.assertEqual(result["interfaces"][2]["type"], 4)

    def test_numeric_passthrough(self):
        params = {"interfaces": [{"type": 1, "main": 1}]}
        result = _normalize_nested_interfaces(params)
        self.assertEqual(result["interfaces"][0]["type"], 1)

    def test_no_interfaces_key(self):
        params = {"host": "myhost", "groups": [{"groupid": "1"}]}
        result = _normalize_nested_interfaces(params)
        self.assertEqual(result, params)

    def test_mixed_numeric_and_symbolic(self):
        params = {"interfaces": [
            {"type": 1, "main": 1},
            {"type": "IPMI", "main": 0},
        ]}
        result = _normalize_nested_interfaces(params)
        self.assertEqual(result["interfaces"][0]["type"], 1)
        self.assertEqual(result["interfaces"][1]["type"], 3)

    def test_preserves_other_params(self):
        params = {
            "host": "myhost",
            "groups": [{"groupid": "1"}],
            "interfaces": [{"type": "SNMP", "main": 1, "useip": 1, "ip": "10.0.0.1", "port": "161"}],
        }
        result = _normalize_nested_interfaces(params)
        self.assertEqual(result["host"], "myhost")
        self.assertEqual(result["groups"], [{"groupid": "1"}])
        self.assertEqual(result["interfaces"][0]["type"], 2)

    def test_build_zabbix_params_host_create(self):
        """Full pipeline: host.create with symbolic interface types."""
        md = MethodDef("host.create", "host_create", "d", read_only=False,
                        params=[ParamDef("params", "dict", "d", required=True)])
        result = _build_zabbix_params(md, {"params": {
            "host": "test-host",
            "groups": [{"groupid": "1"}],
            "interfaces": [
                {"type": "AGENT", "main": 1, "useip": 1, "ip": "10.0.0.1", "port": "10050"},
                {"type": "SNMP", "main": 1, "useip": 1, "ip": "10.0.0.1", "port": "161"},
            ],
        }})
        self.assertEqual(result["interfaces"][0]["type"], 1)
        self.assertEqual(result["interfaces"][1]["type"], 2)

    def test_case_insensitive(self):
        params = {"interfaces": [{"type": "agent", "main": 1}]}
        result = _normalize_nested_interfaces(params)
        self.assertEqual(result["interfaces"][0]["type"], 1)


class TestNestedDchecksNormalization(unittest.TestCase):
    def test_symbolic_type(self):
        params = {"dchecks": [{"type": "HTTP", "ports": "80"}]}
        result = _normalize_nested_dchecks(params)
        self.assertEqual(result["dchecks"][0]["type"], 4)

    def test_icmp(self):
        params = {"dchecks": [{"type": "ICMP"}]}
        result = _normalize_nested_dchecks(params)
        self.assertEqual(result["dchecks"][0]["type"], 12)

    def test_snmpv3(self):
        params = {"dchecks": [{"type": "SNMPV3"}]}
        result = _normalize_nested_dchecks(params)
        self.assertEqual(result["dchecks"][0]["type"], 13)

    def test_multiple_checks(self):
        params = {"dchecks": [
            {"type": "ICMP"},
            {"type": "TCP", "ports": "22"},
            {"type": "ZABBIX_AGENT", "key_": "system.uname"},
        ]}
        result = _normalize_nested_dchecks(params)
        self.assertEqual(result["dchecks"][0]["type"], 12)
        self.assertEqual(result["dchecks"][1]["type"], 8)
        self.assertEqual(result["dchecks"][2]["type"], 9)

    def test_numeric_passthrough(self):
        params = {"dchecks": [{"type": 4}]}
        result = _normalize_nested_dchecks(params)
        self.assertEqual(result["dchecks"][0]["type"], 4)

    def test_no_dchecks(self):
        params = {"name": "test"}
        result = _normalize_nested_dchecks(params)
        self.assertEqual(result, params)

    def test_build_zabbix_params_drule_create(self):
        md = MethodDef("drule.create", "drule_create", "d", read_only=False,
                        params=[ParamDef("params", "dict", "d", required=True)])
        result = _build_zabbix_params(md, {"params": {
            "name": "test",
            "iprange": "192.168.1.1-255",
            "dchecks": [{"type": "ICMP"}, {"type": "HTTP", "ports": "80"}],
        }})
        self.assertEqual(result["dchecks"][0]["type"], 12)
        self.assertEqual(result["dchecks"][1]["type"], 4)


class TestAutoWrapArrays(unittest.TestCase):
    def test_wrap_groups(self):
        params = {"groups": {"groupid": "1"}}
        result = _auto_wrap_arrays(params)
        self.assertEqual(result["groups"], [{"groupid": "1"}])

    def test_wrap_tags(self):
        params = {"tags": {"tag": "env", "value": "prod"}}
        result = _auto_wrap_arrays(params)
        self.assertEqual(result["tags"], [{"tag": "env", "value": "prod"}])

    def test_wrap_templates(self):
        params = {"templates": {"templateid": "10001"}}
        result = _auto_wrap_arrays(params)
        self.assertEqual(result["templates"], [{"templateid": "10001"}])

    def test_wrap_interfaces(self):
        params = {"interfaces": {"type": 1, "main": 1, "ip": "10.0.0.1"}}
        result = _auto_wrap_arrays(params)
        self.assertEqual(result["interfaces"], [{"type": 1, "main": 1, "ip": "10.0.0.1"}])

    def test_wrap_macros(self):
        params = {"macros": {"macro": "{$TEST}", "value": "123"}}
        result = _auto_wrap_arrays(params)
        self.assertEqual(result["macros"], [{"macro": "{$TEST}", "value": "123"}])

    def test_wrap_preprocessing(self):
        params = {"preprocessing": {"type": 12, "params": "$.x"}}
        result = _auto_wrap_arrays(params)
        self.assertEqual(result["preprocessing"], [{"type": 12, "params": "$.x"}])

    def test_wrap_dchecks(self):
        params = {"dchecks": {"type": 12}}
        result = _auto_wrap_arrays(params)
        self.assertEqual(result["dchecks"], [{"type": 12}])

    def test_list_passthrough(self):
        """Already a list — don't double-wrap."""
        params = {"groups": [{"groupid": "1"}]}
        result = _auto_wrap_arrays(params)
        self.assertEqual(result["groups"], [{"groupid": "1"}])

    def test_multiple_fields(self):
        params = {
            "groups": {"groupid": "1"},
            "tags": {"tag": "env", "value": "prod"},
            "name": "test",
        }
        result = _auto_wrap_arrays(params)
        self.assertEqual(result["groups"], [{"groupid": "1"}])
        self.assertEqual(result["tags"], [{"tag": "env", "value": "prod"}])
        self.assertEqual(result["name"], "test")

    def test_no_array_fields(self):
        params = {"name": "test", "key_": "test.key"}
        result = _auto_wrap_arrays(params)
        self.assertEqual(result, params)

    def test_build_zabbix_params_auto_wraps(self):
        """Full pipeline: auto-wrap applied in host.create."""
        md = MethodDef("host.create", "host_create", "d", read_only=False,
                        params=[ParamDef("params", "dict", "d", required=True)])
        result = _build_zabbix_params(md, {"params": {
            "host": "test",
            "groups": {"groupid": "1"},
            "interfaces": {"type": "AGENT", "main": 1, "useip": 1, "ip": "10.0.0.1", "port": "10050"},
        }})
        self.assertIsInstance(result["groups"], list)
        self.assertIsInstance(result["interfaces"], list)
        # Also verify interface type was normalized after wrapping
        self.assertEqual(result["interfaces"][0]["type"], 1)


class TestEdgeCaseEnums(unittest.TestCase):
    def test_httptest_authentication(self):
        result = _normalize_enum_fields({"authentication": "BASIC"}, "httptest.create")
        self.assertEqual(result["authentication"], 1)

    def test_httptest_authentication_kerberos(self):
        result = _normalize_enum_fields({"authentication": "KERBEROS"}, "httptest.update")
        self.assertEqual(result["authentication"], 3)

    def test_maintenance_type_data_collection(self):
        result = _normalize_enum_fields({"maintenance_type": "DATA_COLLECTION"}, "maintenance.create")
        self.assertEqual(result["maintenance_type"], 0)

    def test_maintenance_type_no_data(self):
        result = _normalize_enum_fields({"maintenance_type": "NO_DATA"}, "maintenance.create")
        self.assertEqual(result["maintenance_type"], 1)


class TestDefaultOutput(unittest.TestCase):
    def test_default_output_extend(self):
        """Get methods should default output to 'extend'."""
        md = MethodDef("host.get", "host_get", "d", read_only=True,
                        params=[ParamDef("output", "str", "d")])
        result = _build_zabbix_params(md, {})
        self.assertEqual(result["output"], "extend")

    def test_explicit_output_preserved(self):
        md = MethodDef("host.get", "host_get", "d", read_only=True,
                        params=[ParamDef("output", "str", "d")])
        result = _build_zabbix_params(md, {"output": "hostid,name"})
        self.assertEqual(result["output"], ["hostid", "name"])

    def test_explicit_extend_preserved(self):
        md = MethodDef("host.get", "host_get", "d", read_only=True,
                        params=[ParamDef("output", "str", "d")])
        result = _build_zabbix_params(md, {"output": "extend"})
        self.assertEqual(result["output"], "extend")

    def test_count_output_no_default(self):
        """When countOutput is set, don't add output=extend."""
        md = MethodDef("host.get", "host_get", "d", read_only=True,
                        params=[
                            ParamDef("output", "str", "d"),
                            ParamDef("countOutput", "bool", "d"),
                        ])
        result = _build_zabbix_params(md, {"countOutput": True})
        self.assertNotIn("output", result)

    def test_no_default_for_write_methods(self):
        """Create/update methods should not get default output."""
        md = MethodDef("host.create", "host_create", "d", read_only=False,
                        params=[ParamDef("params", "dict", "d", required=True)])
        result = _build_zabbix_params(md, {"params": {"host": "test"}})
        self.assertNotIn("output", result)

    def test_compact_output_uses_compact_fields(self):
        """When compact_output=True and compact_fields defined, use them."""
        md = MethodDef("host.get", "host_get", "d", read_only=True,
                        params=[ParamDef("output", "str", "d")],
                        compact_fields=("hostid", "host", "name", "status"))
        result = _build_zabbix_params(md, {}, compact_output=True)
        self.assertEqual(result["output"], ["hostid", "host", "name", "status"])

    def test_compact_output_disabled_uses_extend(self):
        """When compact_output=False, always use 'extend'."""
        md = MethodDef("host.get", "host_get", "d", read_only=True,
                        params=[ParamDef("output", "str", "d")],
                        compact_fields=("hostid", "host", "name", "status"))
        result = _build_zabbix_params(md, {}, compact_output=False)
        self.assertEqual(result["output"], "extend")

    def test_compact_output_explicit_extend_override(self):
        """LLM explicitly passing 'extend' overrides compact mode."""
        md = MethodDef("host.get", "host_get", "d", read_only=True,
                        params=[ParamDef("output", "str", "d")],
                        compact_fields=("hostid", "host", "name", "status"))
        result = _build_zabbix_params(md, {"output": "extend"}, compact_output=True)
        self.assertEqual(result["output"], "extend")

    def test_compact_output_explicit_fields_override(self):
        """LLM explicitly passing field names overrides compact mode."""
        md = MethodDef("host.get", "host_get", "d", read_only=True,
                        params=[ParamDef("output", "str", "d")],
                        compact_fields=("hostid", "host", "name", "status"))
        result = _build_zabbix_params(md, {"output": "hostid,name,interfaces"}, compact_output=True)
        self.assertEqual(result["output"], ["hostid", "name", "interfaces"])

    def test_compact_output_no_compact_fields_fallback(self):
        """Methods without compact_fields fall back to 'extend'."""
        md = MethodDef("history.get", "history_get", "d", read_only=True,
                        params=[ParamDef("output", "str", "d")])
        result = _build_zabbix_params(md, {}, compact_output=True)
        self.assertEqual(result["output"], "extend")

    def test_compact_output_count_output_skips(self):
        """countOutput should skip output entirely even with compact mode."""
        md = MethodDef("host.get", "host_get", "d", read_only=True,
                        params=[
                            ParamDef("output", "str", "d"),
                            ParamDef("countOutput", "bool", "d"),
                        ],
                        compact_fields=("hostid", "host", "name", "status"))
        result = _build_zabbix_params(md, {"countOutput": True}, compact_output=True)
        self.assertNotIn("output", result)


class TestTimestampNormalization(unittest.TestCase):
    def test_iso_datetime(self):
        params = {"active_since": "2026-04-01 08:00:00"}
        result = _normalize_timestamps(params)
        self.assertIsInstance(result["active_since"], int)
        self.assertEqual(result["active_since"], 1775030400)

    def test_iso_datetime_t_separator(self):
        params = {"active_since": "2026-04-01T08:00:00"}
        result = _normalize_timestamps(params)
        self.assertIsInstance(result["active_since"], int)
        self.assertEqual(result["active_since"], 1775030400)

    def test_iso_datetime_with_timezone(self):
        params = {"active_till": "2026-04-01T08:00:00+00:00"}
        result = _normalize_timestamps(params)
        self.assertIsInstance(result["active_till"], int)
        self.assertEqual(result["active_till"], 1775030400)

    def test_iso_date_only(self):
        params = {"active_since": "2026-04-01"}
        result = _normalize_timestamps(params)
        self.assertIsInstance(result["active_since"], int)
        self.assertEqual(result["active_since"], 1775001600)

    def test_iso_datetime_minutes_only(self):
        params = {"time_from": "2026-04-01 08:00"}
        result = _normalize_timestamps(params)
        self.assertIsInstance(result["time_from"], int)

    def test_int_passthrough(self):
        params = {"active_since": 1774944000}
        result = _normalize_timestamps(params)
        self.assertEqual(result["active_since"], 1774944000)

    def test_numeric_string_passthrough(self):
        params = {"active_since": "1774944000"}
        result = _normalize_timestamps(params)
        self.assertEqual(result["active_since"], "1774944000")

    def test_unknown_field_ignored(self):
        params = {"name": "2026-04-01 08:00:00"}
        result = _normalize_timestamps(params)
        self.assertEqual(result["name"], "2026-04-01 08:00:00")

    def test_no_timestamp_fields(self):
        params = {"name": "test", "key_": "test.key"}
        result = _normalize_timestamps(params)
        self.assertEqual(result, params)

    def test_multiple_fields(self):
        params = {
            "active_since": "2026-04-01 08:00:00",
            "active_till": "2026-04-02 08:00:00",
        }
        result = _normalize_timestamps(params)
        self.assertIsInstance(result["active_since"], int)
        self.assertIsInstance(result["active_till"], int)
        self.assertEqual(result["active_till"] - result["active_since"], 86400)

    def test_preserves_other_fields(self):
        params = {"active_since": "2026-04-01 08:00:00", "name": "test"}
        result = _normalize_timestamps(params)
        self.assertEqual(result["name"], "test")

    def test_build_params_create_applies(self):
        """Timestamp normalization in create/update pipeline."""
        md = MethodDef("maintenance.create", "maintenance_create", "d", read_only=False,
                        params=[ParamDef("params", "dict", "d", required=True)])
        result = _build_zabbix_params(md, {"params": {
            "name": "test",
            "active_since": "2026-04-01T08:00:00",
            "active_till": "2026-04-02T08:00:00",
        }})
        self.assertIsInstance(result["active_since"], int)
        self.assertIsInstance(result["active_till"], int)

    def test_build_params_get_applies(self):
        """Timestamp normalization in get method pipeline."""
        md = MethodDef("event.get", "event_get", "d", read_only=True,
                        params=[
                            ParamDef("output", "str", "d"),
                            ParamDef("time_from", "int", "d"),
                            ParamDef("time_till", "int", "d"),
                        ])
        result = _build_zabbix_params(md, {
            "time_from": "2026-04-01 00:00:00",
            "time_till": "2026-04-02 00:00:00",
        })
        self.assertIsInstance(result["time_from"], int)
        self.assertIsInstance(result["time_till"], int)

    def test_invalid_string_passthrough(self):
        """Non-date strings pass through unchanged."""
        params = {"active_since": "not-a-date"}
        result = _normalize_timestamps(params)
        self.assertEqual(result["active_since"], "not-a-date")


class TestResolveValuemapByName(unittest.TestCase):
    """Test _resolve_valuemap_by_name edge cases (no live API)."""

    def test_skip_non_item_methods(self):
        from zabbix_mcp.server import _resolve_valuemap_by_name
        params = {"valuemap": {"name": "test"}}
        # Should return unchanged for non-item methods
        result = _resolve_valuemap_by_name(params, "trigger.create", None, "s")
        self.assertEqual(result, params)

    def test_skip_when_no_valuemap(self):
        from zabbix_mcp.server import _resolve_valuemap_by_name
        params = {"name": "test", "valuemapid": "5"}
        result = _resolve_valuemap_by_name(params, "item.create", None, "s")
        self.assertEqual(result, params)

    def test_skip_when_valuemapid_already_set(self):
        from zabbix_mcp.server import _resolve_valuemap_by_name
        params = {"valuemap": {"name": "test"}, "valuemapid": "5"}
        result = _resolve_valuemap_by_name(params, "item.create", None, "s")
        self.assertEqual(result, params)

    def test_skip_non_dict_params(self):
        from zabbix_mcp.server import _resolve_valuemap_by_name
        result = _resolve_valuemap_by_name(["id1"], "item.create", None, "s")
        self.assertEqual(result, ["id1"])

    def test_skip_valuemap_without_name(self):
        from zabbix_mcp.server import _resolve_valuemap_by_name
        params = {"valuemap": {"valuemapid": "5"}}
        result = _resolve_valuemap_by_name(params, "item.create", None, "s")
        self.assertEqual(result, params)

    def test_applies_to_item_methods(self):
        """Verify all expected methods are in _VALUEMAP_METHODS."""
        from zabbix_mcp.server import _VALUEMAP_METHODS
        for method in ["item.create", "item.update",
                       "itemprototype.create", "itemprototype.update"]:
            self.assertIn(method, _VALUEMAP_METHODS)


class TestBuildZabbixParams(unittest.TestCase):
    def test_delete_method_returns_list(self):
        md = MethodDef("host.delete", "host_delete", "d", read_only=False,
                        params=[ParamDef("ids", "list[str]", "d", required=True)])
        result = _build_zabbix_params(md, {"ids": ["10084", "10085"]})
        self.assertEqual(result, ["10084", "10085"])

    def test_array_param_returns_list(self):
        md = MethodDef("history.clear", "history_clear", "d", read_only=False,
                        params=[ParamDef("itemids", "list[str]", "d", required=True)],
                        array_param="itemids")
        result = _build_zabbix_params(md, {"itemids": ["101", "102"]})
        self.assertEqual(result, ["101", "102"])

    def test_array_param_list_type(self):
        md = MethodDef("history.push", "history_push", "d", read_only=False,
                        params=[ParamDef("items", "list", "d", required=True)],
                        array_param="items")
        data = [{"itemid": "1", "clock": 123, "ns": 0, "value": "42"}]
        result = _build_zabbix_params(md, {"items": data})
        self.assertEqual(result, data)

    def test_array_param_takes_priority(self):
        """array_param should be checked before 'params' dict path."""
        md = MethodDef("user.unblock", "user_unblock", "d", read_only=False,
                        params=[ParamDef("userids", "list[str]", "d", required=True)],
                        array_param="userids")
        result = _build_zabbix_params(md, {"userids": ["5", "6"]})
        self.assertIsInstance(result, list)
        self.assertEqual(result, ["5", "6"])

    def test_get_method_returns_dict(self):
        md = MethodDef("host.get", "host_get", "d", read_only=True,
                        params=[ParamDef("output", "str", "d")])
        result = _build_zabbix_params(md, {"output": "extend"})
        self.assertEqual(result, {"output": "extend"})

    # --- extra_params for get methods ---

    def test_extra_params_merged(self):
        """extra_params should be merged into get method params."""
        md = MethodDef("item.get", "item_get", "d", read_only=True,
                        params=[
                            ParamDef("output", "str", "d"),
                            ParamDef("extra_params", "dict", "d"),
                        ])
        result = _build_zabbix_params(md, {
            "output": "extend",
            "extra_params": {"selectPreprocessing": "extend", "selectTags": "extend"},
        })
        self.assertEqual(result["output"], "extend")
        self.assertEqual(result["selectPreprocessing"], "extend")
        self.assertEqual(result["selectTags"], "extend")

    def test_extra_params_does_not_override_typed(self):
        """Typed params take precedence over extra_params."""
        md = MethodDef("item.get", "item_get", "d", read_only=True,
                        params=[
                            ParamDef("output", "str", "d"),
                            ParamDef("extra_params", "dict", "d"),
                        ])
        result = _build_zabbix_params(md, {
            "output": "extend",
            "extra_params": {"output": "count", "selectHosts": "extend"},
        })
        self.assertEqual(result["output"], "extend")
        self.assertEqual(result["selectHosts"], "extend")

    def test_extra_params_none_ignored(self):
        """extra_params=None should be ignored."""
        md = MethodDef("item.get", "item_get", "d", read_only=True,
                        params=[
                            ParamDef("output", "str", "d"),
                            ParamDef("extra_params", "dict", "d"),
                        ])
        result = _build_zabbix_params(md, {"output": "extend"})
        self.assertEqual(result, {"output": "extend"})

    def test_extra_params_not_in_result(self):
        """extra_params itself should not appear in the result dict."""
        md = MethodDef("host.get", "host_get", "d", read_only=True,
                        params=[
                            ParamDef("output", "str", "d"),
                            ParamDef("extra_params", "dict", "d"),
                        ])
        result = _build_zabbix_params(md, {
            "output": "extend",
            "extra_params": {"selectInterfaces": "extend"},
        })
        self.assertNotIn("extra_params", result)
        self.assertEqual(result["selectInterfaces"], "extend")

    def test_extra_params_in_all_get_methods(self):
        """All get methods should have extra_params parameter."""
        get_methods = [m for m in ALL_METHODS if m.api_method.endswith(".get")]
        for m in get_methods:
            param_names = [p.name for p in m.params]
            self.assertIn("extra_params", param_names,
                          f"{m.api_method}: missing extra_params parameter")

    def test_array_param_methods_in_registry(self):
        """All methods with array_param set should exist and be consistent."""
        array_methods = [m for m in ALL_METHODS if m.array_param is not None]
        self.assertGreater(len(array_methods), 0)
        for m in array_methods:
            param_names = [p.name for p in m.params]
            self.assertIn(m.array_param, param_names,
                          f"{m.api_method}: array_param '{m.array_param}' not in params")


class TestSecurityPathTraversal(unittest.TestCase):
    """Security tests for path traversal attacks in source_file resolution."""

    def test_dotdot_traversal_blocked(self):
        """Path with ../../ to escape allowed directory is rejected."""
        import tempfile
        allowed = tempfile.gettempdir()
        params = {"source_file": os.path.join(allowed, "..", "..", "etc", "passwd")}
        with self.assertRaises(ValueError) as ctx:
            _resolve_source_file(params, allowed_import_dirs=[allowed])
        self.assertIn("allowed import directories", str(ctx.exception))

    def test_absolute_path_outside_allowed(self):
        """Absolute path outside allowed dirs is rejected."""
        params = {"source_file": "/etc/shadow"}
        with self.assertRaises(ValueError) as ctx:
            _resolve_source_file(params, allowed_import_dirs=["/opt/zabbix-mcp/imports"])
        self.assertIn("allowed import directories", str(ctx.exception))

    def test_symlink_rejected(self):
        """Symlink pointing to a valid file inside allowed dir is still rejected."""
        import tempfile
        tmpdir = tempfile.mkdtemp()
        target = os.path.join(tmpdir, "template.yaml")
        link = os.path.join(tmpdir, "link.yaml")
        try:
            with open(target, "w") as f:
                f.write("zabbix_export:\n  version: '7.0'\n")
            os.symlink(target, link)
            params = {"source_file": link}
            with self.assertRaises(ValueError) as ctx:
                _resolve_source_file(params, allowed_import_dirs=[tmpdir])
            self.assertIn("symbolic link", str(ctx.exception))
        finally:
            os.unlink(link)
            os.unlink(target)
            os.rmdir(tmpdir)

    def test_symlink_escaping_allowed_dir(self):
        """Symlink pointing outside allowed dir is rejected."""
        import tempfile
        tmpdir = tempfile.mkdtemp()
        link = os.path.join(tmpdir, "escape.yaml")
        try:
            os.symlink("/etc/passwd", link)
            params = {"source_file": link}
            with self.assertRaises(ValueError) as ctx:
                _resolve_source_file(params, allowed_import_dirs=[tmpdir])
            self.assertIn("symbolic link", str(ctx.exception))
        finally:
            os.unlink(link)
            os.rmdir(tmpdir)

    def test_no_allowed_dirs_disables_feature(self):
        """source_file is rejected when allowed_import_dirs is not configured."""
        params = {"source_file": "/tmp/template.yaml"}
        with self.assertRaises(ValueError) as ctx:
            _resolve_source_file(params)
        self.assertIn("disabled", str(ctx.exception))

    def test_empty_allowed_dirs_disables_feature(self):
        """Empty allowed_import_dirs list disables the feature."""
        params = {"source_file": "/tmp/template.yaml"}
        with self.assertRaises(ValueError) as ctx:
            _resolve_source_file(params, allowed_import_dirs=[])
        self.assertIn("disabled", str(ctx.exception))

    def test_valid_file_in_allowed_dir(self):
        """Legitimate file inside allowed dir works normally."""
        import tempfile
        tmpdir = tempfile.mkdtemp()
        target = os.path.join(tmpdir, "valid.yaml")
        try:
            with open(target, "w") as f:
                f.write("zabbix_export:\n  version: '7.0'\n")
            params = {"source_file": target}
            result = _resolve_source_file(params, allowed_import_dirs=[tmpdir])
            self.assertIn("source", result)
            self.assertNotIn("source_file", result)
        finally:
            os.unlink(target)
            os.rmdir(tmpdir)


class TestSecurityAuthBypass(unittest.TestCase):
    """Security tests for authentication bypass attempts."""

    def test_empty_token_rejected(self):
        v = _BearerTokenVerifier("secret-token")
        result = asyncio.run(v.verify_token(""))
        self.assertIsNone(result)

    def test_none_string_rejected(self):
        v = _BearerTokenVerifier("secret-token")
        result = asyncio.run(v.verify_token("None"))
        self.assertIsNone(result)

    def test_partial_token_rejected(self):
        v = _BearerTokenVerifier("secret-token-12345")
        result = asyncio.run(v.verify_token("secret-token"))
        self.assertIsNone(result)

    def test_token_with_extra_chars_rejected(self):
        v = _BearerTokenVerifier("secret")
        result = asyncio.run(v.verify_token("secret\x00"))
        self.assertIsNone(result)

    def test_token_case_sensitive(self):
        v = _BearerTokenVerifier("Secret-Token")
        result = asyncio.run(v.verify_token("secret-token"))
        self.assertIsNone(result)

    def test_valid_token_accepted(self):
        v = _BearerTokenVerifier("correct-token")
        result = asyncio.run(v.verify_token("correct-token"))
        self.assertIsNotNone(result)
        self.assertEqual(result.client_id, "mcp-client")


class TestSecurityAPIMethodValidation(unittest.TestCase):
    """Security tests for API method injection prevention."""

    def test_reject_double_dot_method(self):
        mgr = ClientManager(_make_config())
        with self.assertRaises(ValueError):
            mgr._do_call(None, "host..get", {})

    def test_reject_method_with_underscore(self):
        mgr = ClientManager(_make_config())
        with self.assertRaises(ValueError):
            mgr._do_call(None, "host.__class__", {})

    def test_reject_method_with_slash(self):
        mgr = ClientManager(_make_config())
        with self.assertRaises(ValueError):
            mgr._do_call(None, "../../etc/passwd", {})

    def test_reject_method_without_dot(self):
        mgr = ClientManager(_make_config())
        with self.assertRaises(ValueError):
            mgr._do_call(None, "hostget", {})

    def test_reject_triple_part_method(self):
        mgr = ClientManager(_make_config())
        with self.assertRaises(ValueError):
            mgr._do_call(None, "host.get.all", {})

    def test_reject_method_with_numbers(self):
        mgr = ClientManager(_make_config())
        with self.assertRaises(ValueError):
            mgr._do_call(None, "host.get123", {})

    def test_reject_empty_method(self):
        mgr = ClientManager(_make_config())
        with self.assertRaises(ValueError):
            mgr._do_call(None, "", {})


class TestSecurityExtraParamsInjection(unittest.TestCase):
    """Security tests for extra_params key injection prevention."""

    def test_reject_dunder_key(self):
        """__proto__ style keys should be silently dropped."""
        md = MethodDef("host.get", "host_get", "d", read_only=True,
                        params=[
                            ParamDef("output", "str", "d"),
                            ParamDef("extra_params", "dict", "d"),
                        ])
        result = _build_zabbix_params(md, {
            "output": "extend",
            "extra_params": {"__proto__": {"polluted": True}},
        })
        self.assertNotIn("__proto__", result)

    def test_reject_numeric_start_key(self):
        md = MethodDef("host.get", "host_get", "d", read_only=True,
                        params=[
                            ParamDef("output", "str", "d"),
                            ParamDef("extra_params", "dict", "d"),
                        ])
        result = _build_zabbix_params(md, {
            "extra_params": {"1invalid": "value"},
        })
        self.assertNotIn("1invalid", result)

    def test_reject_special_char_key(self):
        md = MethodDef("host.get", "host_get", "d", read_only=True,
                        params=[
                            ParamDef("output", "str", "d"),
                            ParamDef("extra_params", "dict", "d"),
                        ])
        result = _build_zabbix_params(md, {
            "extra_params": {"select;drop": "value", "key=val": "x"},
        })
        self.assertNotIn("select;drop", result)
        self.assertNotIn("key=val", result)

    def test_valid_extra_params_accepted(self):
        md = MethodDef("host.get", "host_get", "d", read_only=True,
                        params=[
                            ParamDef("output", "str", "d"),
                            ParamDef("extra_params", "dict", "d"),
                        ])
        result = _build_zabbix_params(md, {
            "extra_params": {"selectInterfaces": "extend", "selectTags": "extend"},
        })
        self.assertEqual(result["selectInterfaces"], "extend")
        self.assertEqual(result["selectTags"], "extend")


class TestSecurityReadOnlyEnforcement(unittest.TestCase):
    """Security tests for read-only mode enforcement."""

    def test_readonly_blocks_create(self):
        mgr = ClientManager(_make_config())
        with self.assertRaises(ReadOnlyError):
            mgr.check_write("test")

    def test_readonly_default_true(self):
        """Default server config should be read-only."""
        cfg = _make_config()
        self.assertTrue(cfg.zabbix_servers["test"].read_only)

    def test_ip_allowlist_middleware_rejects_unlisted(self):
        """IP not in allowlist should be rejected with 403."""
        from zabbix_mcp.server import _IPAllowlistMiddleware

        responses = []

        async def mock_send(message):
            responses.append(message)

        async def mock_app(scope, receive, send):
            pass

        middleware = _IPAllowlistMiddleware(mock_app, ["10.0.0.0/24"])
        scope = {"type": "http", "client": ("192.168.1.1", 12345)}
        asyncio.run(middleware(scope, None, mock_send))
        self.assertEqual(responses[0]["status"], 403)

    def test_ip_allowlist_middleware_allows_listed(self):
        """IP in allowlist should be passed through to app."""
        from zabbix_mcp.server import _IPAllowlistMiddleware

        app_called = []

        async def mock_app(scope, receive, send):
            app_called.append(True)

        middleware = _IPAllowlistMiddleware(mock_app, ["10.0.0.0/24"])
        scope = {"type": "http", "client": ("10.0.0.5", 12345)}
        asyncio.run(middleware(scope, None, None))
        self.assertTrue(app_called)

    def test_ip_allowlist_invalid_cidr_raises(self):
        """Invalid CIDR notation should raise ValueError at init."""
        from zabbix_mcp.server import _IPAllowlistMiddleware

        with self.assertRaises(ValueError):
            _IPAllowlistMiddleware(None, ["not-an-ip"])


if __name__ == "__main__":
    unittest.main()
