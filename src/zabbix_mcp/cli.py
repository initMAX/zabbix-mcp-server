"""CLI entry point for zabbix-mcp-server."""

from __future__ import annotations

import argparse
import logging
import sys

from zabbix_mcp import __version__
from zabbix_mcp.config import ConfigError, load_config
from zabbix_mcp.server import run_server

logger = logging.getLogger("zabbix_mcp")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="zabbix-mcp-server",
        description="MCP server for the complete Zabbix API",
    )
    parser.add_argument(
        "--config",
        required=True,
        help="Path to config.toml",
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "http"],
        help="Override transport from config",
    )
    parser.add_argument(
        "--host",
        help="Override HTTP host from config",
    )
    parser.add_argument(
        "--port",
        type=int,
        help="Override HTTP port from config",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    args = parser.parse_args()

    try:
        config = load_config(args.config)
    except ConfigError as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        sys.exit(1)

    log_level = getattr(logging, config.server.log_level.upper(), logging.INFO)
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stderr,
    )

    transport = args.transport or config.server.transport
    host = args.host or config.server.host
    port = args.port or config.server.port

    server_names = ", ".join(config.zabbix_servers.keys())
    logger.info("Starting Zabbix MCP Server v%s", __version__)
    logger.info("Transport: %s", transport)
    logger.info("Zabbix servers: %s", server_names)

    run_server(config, transport=transport, host=host, port=port)
