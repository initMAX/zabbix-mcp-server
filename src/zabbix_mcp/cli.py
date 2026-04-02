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
        choices=["stdio", "http", "sse"],
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
    log_format = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    formatter = logging.Formatter(log_format)

    # Build handler list: when log_file is set, write ONLY to file (not stderr)
    # to avoid duplicates when systemd also redirects stderr to the same file.
    # When log_file is not set, write to stderr only.
    handlers: list[logging.Handler] = []
    if config.server.log_file:
        from pathlib import Path
        log_path = Path(config.server.log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_path))
    else:
        handlers.append(logging.StreamHandler(sys.stderr))

    for h in handlers:
        h.setFormatter(formatter)

    # Configure app logger — no propagation to root to prevent duplicates
    for logger_name in ("zabbix_mcp", "mcp"):
        named_logger = logging.getLogger(logger_name)
        named_logger.setLevel(log_level)
        named_logger.handlers.clear()
        named_logger.propagate = False
        for h in handlers:
            named_logger.addHandler(h)

    # Silence root logger to prevent any stray duplicates
    logging.root.handlers.clear()

    transport = args.transport or config.server.transport
    host = args.host or config.server.host
    port = args.port or config.server.port

    server_names = ", ".join(config.zabbix_servers.keys())
    logger.info("Starting Zabbix MCP Server v%s", __version__)
    logger.info("Transport: %s | Listening on: %s:%d", transport, host, port)
    logger.info("Zabbix servers: %s", server_names)

    run_server(config, transport=transport, host=host, port=port)
