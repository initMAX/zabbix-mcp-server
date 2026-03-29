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

"""Configuration loading and validation."""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomllib
    except ModuleNotFoundError:
        import tomli as tomllib  # type: ignore[no-redef]


@dataclass(frozen=True)
class ZabbixServerConfig:
    """Configuration for a single Zabbix server."""

    name: str
    url: str
    api_token: str
    read_only: bool = True
    verify_ssl: bool = True


@dataclass(frozen=True)
class ServerConfig:
    """MCP server configuration."""

    transport: str = "stdio"
    host: str = "127.0.0.1"
    port: int = 8080
    log_level: str = "info"
    log_file: str | None = None
    auth_token: str | None = None


@dataclass(frozen=True)
class AppConfig:
    """Top-level application configuration."""

    server: ServerConfig = field(default_factory=ServerConfig)
    zabbix_servers: dict[str, ZabbixServerConfig] = field(default_factory=dict)

    @property
    def default_server(self) -> str | None:
        """Return the name of the first configured Zabbix server."""
        servers = list(self.zabbix_servers)
        return servers[0] if servers else None


_ENV_VAR_RE = re.compile(r"\$\{([^}]+)}")


def _resolve_env_vars(value: str) -> str:
    """Replace ${VAR_NAME} references with environment variable values."""

    def _replace(match: re.Match[str]) -> str:
        var_name = match.group(1)
        env_value = os.environ.get(var_name)
        if env_value is None:
            raise ConfigError(
                f"Environment variable '{var_name}' referenced in config is not set"
            )
        return env_value

    return _ENV_VAR_RE.sub(_replace, value)


class ConfigError(Exception):
    """Raised when configuration is invalid."""


def load_config(path: str | Path) -> AppConfig:
    """Load and validate configuration from a TOML file."""
    path = Path(path)
    if not path.exists():
        raise ConfigError(f"Config file not found: {path}")

    with open(path, "rb") as f:
        raw = tomllib.load(f)

    server_raw = raw.get("server", {})
    transport = server_raw.get("transport", "stdio")
    if transport not in ("stdio", "http"):
        raise ConfigError(f"Invalid transport '{transport}', must be 'stdio' or 'http'")

    server_config = ServerConfig(
        transport=transport,
        host=server_raw.get("host", "127.0.0.1"),
        port=server_raw.get("port", 8080),
        log_level=server_raw.get("log_level", "info"),
        log_file=server_raw.get("log_file"),
        auth_token=_resolve_env_vars(server_raw["auth_token"]) if server_raw.get("auth_token") else None,
    )

    zabbix_raw = raw.get("zabbix", {})
    if not zabbix_raw:
        raise ConfigError(
            "No Zabbix servers configured. Add at least one [zabbix.<name>] section."
        )

    zabbix_servers: dict[str, ZabbixServerConfig] = {}
    for name, srv in zabbix_raw.items():
        if not isinstance(srv, dict):
            raise ConfigError(f"Invalid Zabbix server config for '{name}'")

        url = srv.get("url")
        if not url:
            raise ConfigError(f"Zabbix server '{name}' is missing 'url'")

        api_token = srv.get("api_token")
        if not api_token:
            raise ConfigError(f"Zabbix server '{name}' is missing 'api_token'")

        api_token = _resolve_env_vars(api_token)

        zabbix_servers[name] = ZabbixServerConfig(
            name=name,
            url=url.rstrip("/"),
            api_token=api_token,
            read_only=srv.get("read_only", True),
            verify_ssl=srv.get("verify_ssl", True),
        )

    return AppConfig(server=server_config, zabbix_servers=zabbix_servers)
