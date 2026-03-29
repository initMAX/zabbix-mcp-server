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
from zabbix_mcp.server import _BearerTokenVerifier, _register_tools
from zabbix_mcp.api import ALL_METHODS


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
        self.assertEqual(cfg.server.rate_limit, 60)
        self.assertIsNone(cfg.server.auth_token)
        self.assertIsNone(cfg.server.log_file)

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
        # 218 API methods + raw_api_call + health_check
        self.assertEqual(count, len(ALL_METHODS) + 2)

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


if __name__ == "__main__":
    unittest.main()
