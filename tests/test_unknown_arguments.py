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

"""A call with an argument the tool does not have is refused, not run without it.

The MCP SDK validates a call against a model that ignores unknown keys:
``host_get(hostid="10084")`` (for ``hostids``) ran without the filter and
returned every host, ``host_get(selectInterfaces="extend")`` hosts without
interfaces, and a parameter removed from a tool kept "working" by doing
nothing. The refusal says where the value belongs.
"""

import asyncio
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import jsonschema  # noqa: E402  (a dependency of the MCP SDK)
from mcp.server.mcpserver.exceptions import ToolError  # noqa: E402

from zabbix_mcp.client import ClientManager  # noqa: E402
from zabbix_mcp.config import AppConfig, ServerConfig, ZabbixServerConfig  # noqa: E402
from zabbix_mcp.server import ZabbixMCPServer, _register_tools, _unknown_arguments_message  # noqa: E402


def _server(reject: bool = True, **kwargs):
    cfg = AppConfig(server=ServerConfig(timezone="UTC"),
                    zabbix_servers={"t": ZabbixServerConfig(name="t", url="http://localhost", api_token="x", read_only=False)})
    mgr = ClientManager(cfg)
    mcp = ZabbixMCPServer(name="test")
    mcp.reject_unknown_arguments = reject
    _register_tools(mcp, mgr, reject_unknown_arguments=reject, **kwargs)
    return mcp, mgr, {t.name: t for t in mcp._tool_manager.list_tools()}


MCP, MGR, TOOLS = _server()


def message(tool: str, args: dict) -> str | None:
    return _unknown_arguments_message(tool, TOOLS[tool].parameters, args)


class TestTheMessage(unittest.TestCase):
    def test_every_tool_takes_each_of_its_own_parameters(self):
        for name, tool in TOOLS.items():
            own = {key: None for key in tool.parameters.get("properties", {})}
            self.assertIsNone(_unknown_arguments_message(name, tool.parameters, own), name)
        self.assertIsNone(message("host_get", {}))
        self.assertIsNone(_unknown_arguments_message("host_get", TOOLS["host_get"].parameters, None))

    def test_a_near_miss_names_the_parameter_that_was_meant(self):
        self.assertIn("host_get has no parameter 'hostid'; did you mean 'hostids'?", message("host_get", {"hostid": "1"}))
        self.assertIn("did you mean 'hostids'?", message("host_get", {"hostIds": ["1"]}))
        self.assertIn("did you mean 'method'?", message("zabbix_raw_api_call", {"api_method": "host.get"}))
        self.assertIn("did you mean 'severities'?", message("problem_active_get", {"severity": 4}))

    def test_a_native_parameter_belongs_in_extra_params(self):
        text = message("host_get", {"selectInterfaces": "extend"})
        self.assertIn("'selectInterfaces' is a parameter of host.get that host_get takes inside 'extra_params'", text)
        self.assertIn('extra_params = {"selectInterfaces": ...}', text)
        self.assertIn("did you mean 'selectInterfaces' inside 'extra_params'?",
                      message("host_get", {"selectInterface": "extend"}))
        # a generic get parameter the tool does not type goes the same way
        self.assertIn("inside 'extra_params'", message("host_get", {"preservekeys": True}))

    def test_a_property_of_the_object_belongs_in_filter_or_search(self):
        text = message("host_get", {"host": "web01"})
        self.assertIn("'host' is a property of the host object, not a parameter of host_get", text)
        self.assertIn('filter = {"host": ...} for an exact match or search = {"host": ...} for a substring', text)
        # a text property can only be searched, a number only filtered
        self.assertNotIn("filter =", message("host_get", {"description": "x"}))
        self.assertNotIn("search =", message("trigger_get", {"priority": 4}))
        # the name most models reach for
        self.assertIn("'key' (the property is 'key_')", message("item_get", {"key": "system.cpu.load"}))

    def test_the_object_of_a_write_tool_belongs_in_params(self):
        text = message("host_create", {"host": "web01", "groups": [{"groupid": "2"}]})
        self.assertIn("host_create has no parameters 'host', 'groups': the properties of the object go inside "
                      "'params'", text)
        self.assertIn("Parameters of host_create: server, params, raw_json.", text)

    def test_anything_else_is_named_with_what_the_tool_takes(self):
        text = message("trend_get", {"sortfield": "clock"})
        self.assertIn("trend_get has no parameter 'sortfield'.", text)
        self.assertIn("Nothing was sent to Zabbix.", text)
        self.assertIn("Parameters of trend_get: server, output, limit", text)
        self.assertIn("Parameters of health_check: none.", message("health_check", {"x": 1}))

    def test_several_at_once(self):
        text = message("host_get", {"hostid": "1", "name": "web", "bogus": 1})
        for part in ("did you mean 'hostids'?", "'name' is a property of the host object", "no parameter 'bogus'"):
            self.assertIn(part, text)

    def test_a_value_is_never_repeated(self):
        # the names only: a value can be a credential
        self.assertNotIn("s3cret", message("host_get", {"hostid": "s3cret", "passwd": "s3cret"}))


class TestTheCall(unittest.TestCase):
    def _call(self, mcp, mgr, tool, args):
        sent = []
        with patch.object(mgr, "call", side_effect=lambda s, m, p, *a, **k: sent.append((m, p)) or []), \
                patch.object(mgr, "get_version", return_value="8.0.0"):
            try:
                asyncio.run(mcp.call_tool(tool, args))
            except ToolError as error:
                return sent, str(error)
        return sent, None

    def test_a_misspelt_filter_no_longer_returns_everything(self):
        sent, error = self._call(MCP, MGR, "host_get", {"hostid": "10084"})
        self.assertEqual(sent, [])   # nothing reached Zabbix
        self.assertIn("did you mean 'hostids'?", error)

    def test_a_parameter_removed_from_a_tool_is_refused(self):
        # proxy_get never had with_hosts in Zabbix; it was typed until 1.41
        for tool, name in (("proxy_get", "with_hosts"), ("usergroup_get", "with_users")):
            sent, error = self._call(MCP, MGR, tool, {name: True})
            self.assertEqual(sent, [], tool)
            self.assertIn(f"no parameter '{name}'", error, tool)

    def test_a_write_with_the_object_at_the_top_level(self):
        sent, error = self._call(MCP, MGR, "host_create", {"host": "web01"})
        self.assertEqual(sent, [])
        self.assertIn("go inside 'params'", error)

    def test_a_correct_call_goes_through(self):
        sent, error = self._call(MCP, MGR, "host_get", {"hostids": ["10084"], "extra_params": {"selectInterfaces": "extend"}})
        self.assertIsNone(error)
        self.assertEqual(sent[0][0], "host.get")
        self.assertEqual(sent[0][1]["hostids"], ["10084"])
        self.assertEqual(sent[0][1]["selectInterfaces"], "extend")

    def test_an_unknown_tool_is_still_the_sdk_s_error(self):
        _, error = self._call(MCP, MGR, "no_such_tool", {"x": 1})
        self.assertIn("Unknown tool", error)

    def test_switched_off_the_argument_is_dropped_as_before(self):
        mcp, mgr, _ = _server(reject=False)
        sent, error = self._call(mcp, mgr, "host_get", {"hostid": "10084"})
        self.assertIsNone(error)
        self.assertEqual(sent[0][0], "host.get")
        self.assertNotIn("hostid", sent[0][1])


class TestTheSchemaSaysSo(unittest.TestCase):
    def test_every_tool_schema_closes_its_argument_list(self):
        for name, tool in TOOLS.items():
            self.assertIs(tool.parameters.get("additionalProperties"), False, name)
        validator = jsonschema.Draft202012Validator(TOOLS["host_get"].parameters)
        self.assertTrue(validator.is_valid({"hostids": ["1"]}))
        self.assertFalse(validator.is_valid({"hostid": "1"}))

    def test_not_when_the_check_is_off(self):
        _, _, tools = _server(reject=False)
        for name, tool in tools.items():
            self.assertNotIn("additionalProperties", tool.parameters, name)

    def test_not_when_the_schema_is_kept_plain(self):
        # [server].schema_constraints = false is "the catalog as it was"; the
        # call is refused all the same
        mcp, mgr, tools = _server(schema_constraints=False)
        self.assertNotIn('"additionalProperties": false', json.dumps([t.parameters for t in tools.values()]))
        with self.assertRaises(ToolError):
            asyncio.run(mcp.call_tool("host_get", {"hostid": "1"}))


class TestConfig(unittest.TestCase):
    def test_default_on_and_a_boolean(self):
        import tempfile
        import textwrap
        from zabbix_mcp.config import ConfigError, load_config

        def load(line: str):
            with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as f:
                f.write(textwrap.dedent(f"""
                    [server]
                    {line}
                    [zabbix.t]
                    url = "http://localhost"
                    api_token = "x"
                """))
            return load_config(f.name)

        self.assertTrue(load("").server.reject_unknown_arguments)
        self.assertFalse(load("reject_unknown_arguments = false").server.reject_unknown_arguments)
        with self.assertRaises(ConfigError):
            load('reject_unknown_arguments = "no"')


if __name__ == "__main__":
    unittest.main()
