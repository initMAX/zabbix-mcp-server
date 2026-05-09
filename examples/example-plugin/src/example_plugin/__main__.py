"""Minimal stdio MCP server demonstrating the plugin contract.

Reads JSON-RPC 2.0 requests line-by-line from stdin and writes one
response line per request to stdout. No external dependencies - the
whole protocol surface fits in this file so plugin authors can read
the reference end-to-end without chasing imports.

Supported methods (subset of MCP 2025-11-25 sufficient for a plugin):

  initialize   - handshake, returns serverInfo + capabilities
  tools/list   - returns the single ``example__echo`` tool descriptor
  tools/call   - dispatches the tool by name and returns its result
  ping         - liveness probe (used by the host's plugin watchdog)
  shutdown     - graceful stop signal from the host

For development you can run this plugin standalone and feed it a
hand-crafted JSON-RPC request to validate the contract, e.g.::

    echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \\
        | python -m example_plugin

The plugin is not loaded by the host in v1.31 - the loader is
forthcoming, tracked under issue #47. This file ships as documentary
reference for plugin authors.
"""

from __future__ import annotations

import json
import sys
from typing import Any

from . import __version__

PROTOCOL_VERSION = "2025-11-25"
PLUGIN_ID = "example"
TOOL_PREFIX = "example"

TOOLS = [
    {
        "name": f"{TOOL_PREFIX}__echo",
        "description": "Returns the input string verbatim. Use to verify the plugin is reachable and the tool prefix is wired up correctly.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {
                    "type": "string",
                    "description": "Text to echo back to the caller.",
                },
            },
            "required": ["text"],
        },
    },
]


def _respond(req_id: Any, result: dict) -> None:
    sys.stdout.write(
        json.dumps({"jsonrpc": "2.0", "id": req_id, "result": result}) + "\n"
    )
    sys.stdout.flush()


def _error(req_id: Any, code: int, message: str) -> None:
    sys.stdout.write(
        json.dumps(
            {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}
        )
        + "\n"
    )
    sys.stdout.flush()


def _handle(msg: dict) -> bool:
    """Return False when the host signalled shutdown."""
    method = msg.get("method")
    req_id = msg.get("id")

    if method == "initialize":
        _respond(
            req_id,
            {
                "protocolVersion": PROTOCOL_VERSION,
                "serverInfo": {"name": PLUGIN_ID, "version": __version__},
                "capabilities": {"tools": {}},
            },
        )
        return True

    if method == "ping":
        _respond(req_id, {})
        return True

    if method == "tools/list":
        _respond(req_id, {"tools": TOOLS})
        return True

    if method == "tools/call":
        params = msg.get("params") or {}
        name = params.get("name")
        args = params.get("arguments") or {}
        if name == f"{TOOL_PREFIX}__echo":
            text = args.get("text", "")
            _respond(req_id, {"content": [{"type": "text", "text": text}]})
        else:
            _error(req_id, -32601, f"Unknown tool: {name!r}")
        return True

    if method == "shutdown":
        _respond(req_id, {})
        return False

    _error(req_id, -32601, f"Method not supported: {method!r}")
    return True


def main() -> int:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError as exc:
            _error(None, -32700, f"Parse error: {exc}")
            continue
        if not _handle(msg):
            break
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
