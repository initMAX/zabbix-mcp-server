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

"""An answer goes out once, as text.

The MCP SDK takes a handler's ``-> str`` for structured output: the tool is
announced with the output schema ``{"result": string}`` and the answer is
sent a second time as ``structuredContent``. Until 1.41 every tool did that;
a client that prefers the structured copy handed the model the JSON-escaped
text. The wire side of this is in ``test_protocol_e2e.py``.
"""

import asyncio
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mcp.server.mcpserver import MCPServer  # noqa: E402
from mcp.types import CallToolResult, ResourceLink, TextContent  # noqa: E402

from zabbix_mcp.client import ClientManager  # noqa: E402
from zabbix_mcp.config import AppConfig, ServerConfig, ZabbixServerConfig  # noqa: E402
from zabbix_mcp.server import ZabbixMCPServer, _add_text_tool, _register_tools  # noqa: E402


def _registered(server_class=ZabbixMCPServer):
    cfg = AppConfig(server=ServerConfig(timezone="UTC"),
                    zabbix_servers={"t": ZabbixServerConfig(name="t", url="http://localhost", api_token="x", read_only=False)})
    mgr = ClientManager(cfg)
    mcp = server_class(name="test")
    _register_tools(mcp, mgr)
    return mcp, mgr


class TestTextOnly(unittest.TestCase):
    def test_no_tool_announces_an_output_schema(self):
        # whichever server class the tools are registered on
        for server_class in (ZabbixMCPServer, MCPServer):
            mcp, _ = _registered(server_class)
            tools = mcp._tool_manager.list_tools()
            self.assertGreater(len(tools), 200)
            for tool in tools:
                self.assertIsNone(tool.output_schema, tool.name)

    def test_an_answer_has_no_structured_copy(self):
        mcp, mgr = _registered()
        rows = [{"hostid": "10084", "host": 'a "quoted" name'}]
        with patch.object(mgr, "call", side_effect=lambda s, m, p, *a, **k: rows), \
                patch.object(mgr, "get_version", return_value="8.0.0"):
            for tool, args in (("host_get", {}), ("host_get", {"output": "count"}), ("health_check", {})):
                result = asyncio.run(mcp.call_tool(tool, args))
                self.assertIsNone(result.structured_content, tool)
                self.assertEqual([c.type for c in result.content], ["text"], tool)
        # the text is the answer itself, not a JSON string of it
        with patch.object(mgr, "call", side_effect=lambda s, m, p, *a, **k: rows), \
                patch.object(mgr, "get_version", return_value="8.0.0"):
            text = asyncio.run(mcp.call_tool("host_get", {})).content[0].text
        self.assertFalse(text.startswith("{"))
        self.assertEqual(json.loads(text.split("\n", 1)[1]), rows)

    def test_it_is_the_registration_that_decides(self):
        # the same handler, registered the SDK's way and ours
        async def answer() -> str:
            return "text"

        plain = MCPServer(name="plain")
        plain.add_tool(answer, name="answer")
        self.assertEqual(plain._tool_manager.get_tool("answer").output_schema["properties"]["result"]["type"], "string")
        self.assertEqual(asyncio.run(plain.call_tool("answer", {})).structured_content, {"result": "text"})

        ours = MCPServer(name="ours")
        _add_text_tool(ours, answer, name="answer")
        self.assertIsNone(ours._tool_manager.get_tool("answer").output_schema)
        result = asyncio.run(ours.call_tool("answer", {}))
        self.assertIsNone(result.structured_content)
        self.assertEqual(result.content[0].text, "text")

    def test_a_result_a_tool_builds_itself_passes_through(self):
        # the shape report_generate returns: text and a link to the PDF
        mcp = ZabbixMCPServer(name="test")

        async def with_a_link():
            return CallToolResult(content=[
                TextContent(type="text", text="the report"),
                ResourceLink(type="resource_link", uri="zabbix://report/abc", name="report.pdf", mimeType="application/pdf"),
            ])

        _add_text_tool(mcp, with_a_link, name="with_a_link")
        result = asyncio.run(mcp.call_tool("with_a_link", {}))
        self.assertEqual([c.type for c in result.content], ["text", "resource_link"])
        self.assertIsNone(result.structured_content)
        self.assertIsNone(mcp._tool_manager.get_tool("with_a_link").output_schema)


if __name__ == "__main__":
    unittest.main()
