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

"""MCP server setup, lifespan management, and dynamic tool registration."""

import inspect
import json
import logging
import time
from typing import Annotated, Any, Optional

from pydantic import Field
from mcp.server.fastmcp import FastMCP
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings

from zabbix_mcp.api import ALL_METHODS
from zabbix_mcp.api.types import MethodDef, ParamDef
from zabbix_mcp.client import ClientManager, RateLimitError, ReadOnlyError
from zabbix_mcp.config import AppConfig

logger = logging.getLogger("zabbix_mcp.server")

# Map param_type strings to Python types for dynamic signature building
_PYTHON_TYPES: dict[str, type] = {
    "str": str,
    "int": int,
    "bool": bool,
    "list[str]": list[str],
    "dict": dict,
}


def _build_zabbix_params(method_def: MethodDef, kwargs: dict[str, Any]) -> Any:
    """Convert tool keyword arguments into Zabbix API parameters."""
    args = {k: v for k, v in kwargs.items() if k != "server" and v is not None}

    # Delete methods expect a plain list of IDs
    if "ids" in args and method_def.api_method.endswith(".delete"):
        return args["ids"]

    # create/update/mass/special methods: the 'params' dict IS the API payload
    if "params" in args:
        return args["params"]

    # For get methods: build params dict from individual arguments
    params: dict[str, Any] = {}
    for param_def in method_def.params:
        if param_def.name in args:
            value = args[param_def.name]
            # Split comma-separated output fields
            if param_def.name == "output" and isinstance(value, str) and value != "extend":
                if "," in value:
                    value = [f.strip() for f in value.split(",")]
            # Split comma-separated sort fields
            if param_def.name == "sortfield" and isinstance(value, str) and "," in value:
                value = [f.strip() for f in value.split(",")]
            params[param_def.name] = value
    return params


def _make_tool_handler(
    method_def: MethodDef,
    client_manager: ClientManager,
    server_names: list[str],
):
    """Create a tool handler with a proper typed signature for FastMCP schema generation."""

    # Build the actual handler that does the work
    async def handler(**kwargs: Any) -> str:
        server_name = kwargs.get("server") or client_manager.default_server
        if not server_name:
            return "Error: No Zabbix server configured."

        try:
            server_name = client_manager.resolve_server(server_name)

            if not method_def.read_only:
                client_manager.check_write(server_name)

            params = _build_zabbix_params(method_def, kwargs)
            result = client_manager.call(server_name, method_def.api_method, params)

            text = json.dumps(result, indent=2, default=str, ensure_ascii=False)
            if len(text) > 50000:
                text = text[:50000] + "\n\n... [truncated, use 'limit' parameter to reduce results]"
            return text

        except (ReadOnlyError, RateLimitError) as e:
            return f"Error: {e}"
        except ValueError as e:
            return f"Error: {e}"
        except Exception as e:
            logger.exception("Error calling %s on server '%s'", method_def.api_method, server_name)
            return f"Error calling {method_def.api_method}: {e}"

    # Build a dynamic function signature so FastMCP generates proper JSON Schema
    sig_params: list[inspect.Parameter] = []

    # Server parameter
    server_desc = (
        f"Target Zabbix server. Available: {', '.join(server_names)}. "
        f"Defaults to '{server_names[0]}' if omitted."
    )
    sig_params.append(inspect.Parameter(
        "server",
        inspect.Parameter.KEYWORD_ONLY,
        default=None,
        annotation=Annotated[Optional[str], Field(description=server_desc)],
    ))

    # Method-specific parameters
    for p in method_def.params:
        python_type = _PYTHON_TYPES.get(p.param_type, str)
        if p.required:
            annotation = Annotated[python_type, Field(description=p.description)]
            default = inspect.Parameter.empty
        else:
            annotation = Annotated[Optional[python_type], Field(description=p.description)]
            default = p.default
        sig_params.append(inspect.Parameter(
            p.name,
            inspect.Parameter.KEYWORD_ONLY,
            default=default,
            annotation=annotation,
        ))

    handler.__signature__ = inspect.Signature(sig_params, return_annotation=str)
    handler.__name__ = method_def.tool_name
    handler.__doc__ = method_def.description
    handler.__qualname__ = method_def.tool_name

    return handler


def _register_tools(mcp: FastMCP, client_manager: ClientManager) -> int:
    """Register all Zabbix API methods as MCP tools. Returns tool count."""
    server_names = client_manager.server_names
    count = 0

    for method_def in ALL_METHODS:
        handler = _make_tool_handler(method_def, client_manager, server_names)
        mcp.add_tool(handler, name=method_def.tool_name, description=method_def.description)
        count += 1

    # Generic raw API call tool
    server_desc = (
        f"Target Zabbix server. Available: {', '.join(server_names)}. "
        f"Defaults to '{server_names[0]}' if omitted."
    )

    async def zabbix_raw_api_call(
        *,
        method: Annotated[str, Field(description="Full Zabbix API method name, e.g. 'host.get', 'trigger.create'")],
        params: Annotated[Optional[dict], Field(description="API method parameters as a JSON object")] = None,
        server: Annotated[Optional[str], Field(description=server_desc)] = None,
    ) -> str:
        """Execute any Zabbix API method directly. Use this for methods not covered
        by dedicated tools, or for advanced/undocumented API calls."""
        server_name = server or client_manager.default_server
        if not server_name:
            return "Error: No Zabbix server configured."
        try:
            server_name = client_manager.resolve_server(server_name)
            result = client_manager.call(server_name, method, params or {})
            text = json.dumps(result, indent=2, default=str, ensure_ascii=False)
            if len(text) > 50000:
                text = text[:50000] + "\n\n... [truncated]"
            return text
        except Exception as e:
            return f"Error: {e}"

    mcp.add_tool(zabbix_raw_api_call)
    count += 1

    # Health check tool
    async def health_check() -> str:
        """Check the health of the MCP server and its connections to Zabbix servers.
        Returns the status of each configured Zabbix server (version, connectivity)."""
        from zabbix_mcp import __version__
        results: dict[str, Any] = {
            "mcp_server": "ok",
            "version": __version__,
            "tools": count,
            "zabbix_servers": {},
        }
        for name in client_manager.server_names:
            try:
                client = client_manager._get_client(name)
                version = client.api_version()
                results["zabbix_servers"][name] = {"status": "ok", "zabbix_version": version}
            except Exception as e:
                results["zabbix_servers"][name] = {"status": "error", "error": str(e)}
        return json.dumps(results, indent=2)

    mcp.add_tool(health_check)
    count += 1

    return count


class _BearerTokenVerifier:
    """Simple bearer token verifier for HTTP transport authentication."""

    def __init__(self, expected_token: str) -> None:
        self._expected_token = expected_token

    async def verify_token(self, token: str) -> AccessToken | None:
        if token == self._expected_token:
            return AccessToken(
                token=token,
                client_id="mcp-client",
                scopes=["all"],
                expires_at=int(time.time()) + 86400,
            )
        return None


def run_server(
    config: AppConfig,
    *,
    transport: str = "stdio",
    host: str = "127.0.0.1",
    port: int = 8080,
) -> None:
    """Create and run the MCP server."""
    client_manager = ClientManager(config)

    # Set up bearer token auth for HTTP transport
    auth_kwargs: dict[str, Any] = {}
    if config.server.auth_token and transport == "http":
        server_url = f"http://{host}:{port}"
        auth_kwargs["token_verifier"] = _BearerTokenVerifier(config.server.auth_token)
        auth_kwargs["auth"] = AuthSettings(
            issuer_url=server_url,
            resource_server_url=server_url,
        )
        logger.info("Bearer token authentication enabled")
    elif transport == "http" and not config.server.auth_token:
        logger.warning("No auth_token configured - HTTP server is unauthenticated!")

    mcp = FastMCP(
        name="zabbix-mcp-server",
        host=host,
        port=port,
        instructions=(
            "Zabbix MCP Server provides full access to the Zabbix monitoring API. "
            "Use the tools to query hosts, problems, triggers, items, and all other "
            "Zabbix objects. Most 'get' tools support filtering via 'filter', 'search', "
            "and 'limit' parameters. Write operations (create/update/delete) are only "
            "allowed on servers not configured as read_only."
        ),
        **auth_kwargs,
    )

    tool_count = _register_tools(mcp, client_manager)
    logger.info("Registered %d tools", tool_count)

    try:
        if transport == "http":
            mcp.run(transport="streamable-http")
        else:
            mcp.run(transport="stdio")
    finally:
        client_manager.close()
