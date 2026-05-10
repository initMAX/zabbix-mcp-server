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
from pathlib import Path

from zabbix_mcp import __version__
from zabbix_mcp.config import ConfigError, load_config
from zabbix_mcp.server import run_server

logger = logging.getLogger("zabbix_mcp")


def main() -> None:
    # Subcommand routing for audit utilities (issue #49 acceptance
    # criterion). Detected before argparse so existing 'serve'-style
    # invocations (--config X) still work without a leading subcommand.
    if len(sys.argv) > 1 and sys.argv[1] == "audit":
        from zabbix_mcp.cli_audit import main as audit_main
        sys.exit(audit_main(sys.argv[2:]))

    parser = argparse.ArgumentParser(
        prog="zabbix-mcp-server",
        description=(
            "MCP server for the complete Zabbix API. "
            "Run with --config to start the server. "
            "Use 'zabbix-mcp-server audit --help' for the audit log utilities."
        ),
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
        "--check-config",
        action="store_true",
        help="Validate config.toml and exit without starting the server",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    args = parser.parse_args()

    try:
        config = load_config(args.config)
        # Store config path for admin portal and config writer
        object.__setattr__(config, "_config_path", str(Path(args.config).resolve()))
    except FileNotFoundError:
        print(f"ERROR: Config file not found: {args.config}", file=sys.stderr)
        sys.exit(1)
    except PermissionError:
        print(
            f"ERROR: Cannot read {args.config} (permission denied). "
            f"Fix: sudo chown zabbix-mcp:zabbix-mcp {args.config}",
            file=sys.stderr,
        )
        sys.exit(1)
    except ConfigError as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        sys.exit(1)

    # --check-config: validate only, do not start the server.
    if args.check_config:
        print(f"OK: {args.config} is valid")
        sys.exit(0)

    log_level = getattr(logging, config.server.log_level.upper(), logging.INFO)
    log_format = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    formatter = logging.Formatter(log_format)

    # Build handler list: when log_file is set, write ONLY to file (not stderr).
    # When log_file is not set, write to stderr (goes to journal under systemd).
    handlers: list[logging.Handler] = []
    if config.server.log_file:
        log_path = Path(config.server.log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            handlers.append(logging.FileHandler(log_path))
        except PermissionError:
            handlers.append(logging.StreamHandler(sys.stderr))
            print(
                f"WARNING: Cannot write to {log_path} (permission denied), "
                f"falling back to stderr. "
                f"Fix: sudo chown zabbix-mcp:zabbix-mcp {log_path}",
                file=sys.stderr,
            )
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

    transport = args.transport if args.transport is not None else config.server.transport
    host = args.host if args.host is not None else config.server.host
    port = args.port if args.port is not None else config.server.port

    server_names = ", ".join(config.zabbix_servers.keys())
    logger.info("initMAX MCP Server v%s - developed by initMAX s.r.o.", __version__)
    logger.info("Transport: %s | Listening on: %s:%d", transport, host, port)
    logger.info("Zabbix servers: %s", server_names)

    # Operational log: record service start with the resolved binding.
    # Best-effort - the import lives here (not at module top) so a
    # build that strips the module still boots.
    try:
        import os
        from zabbix_mcp.admin import operational_log
        ops_cfg = config.operational_log
        operational_log.configure(enabled=ops_cfg.enabled, path=ops_cfg.path)
        operational_log.service_start(
            version=__version__, transport=transport,
            host=host, port=port, pid=os.getpid(),
        )
    except Exception:
        logger.debug("operational_log not available", exc_info=True)

    run_server(config, transport=transport, host=host, port=port)
