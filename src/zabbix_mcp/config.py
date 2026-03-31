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
    skip_version_check: bool = False


@dataclass(frozen=True)
class ServerConfig:
    """MCP server configuration."""

    transport: str = "stdio"
    host: str = "127.0.0.1"
    port: int = 8080
    log_level: str = "info"
    log_file: str | None = None
    auth_token: str | None = None
    rate_limit: int = 300
    tools: list[str] | None = None
    disabled_tools: list[str] | None = None


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


TOOL_GROUPS: dict[str, list[str]] = {
    "monitoring": [
        "host", "hostgroup", "hostinterface", "hostprototype",
        "item", "itemprototype", "trigger", "triggerprototype",
        "problem", "event", "history", "trend",
        "graph", "graphitem", "graphprototype",
        "discoveryrule", "discoveryruleprototype",
        "dcheck", "dhost", "drule", "dservice", "httptest",
    ],
    "data_collection": [
        "template", "templategroup", "templatedashboard",
        "valuemap", "dashboard",
    ],
    "alerts": [
        "action", "alert", "mediatype", "script",
    ],
    "users": [
        "user", "usergroup", "userdirectory", "usermacro",
        "token", "role", "mfa",
    ],
    "administration": [
        "settings", "housekeeping", "authentication", "autoregistration",
        "configuration", "connector", "correlation", "hanode",
        "iconmap", "image", "maintenance", "map", "module",
        "proxy", "proxygroup", "regexp", "report", "task",
        "auditlog",
    ],
}


def _expand_tool_groups(tools: list[str]) -> list[str]:
    """Expand group names (e.g. 'monitoring') into individual tool prefixes."""
    expanded: list[str] = []
    for entry in tools:
        entry = entry.lower()
        if entry in TOOL_GROUPS:
            expanded.extend(TOOL_GROUPS[entry])
        else:
            expanded.append(entry)
    return list(dict.fromkeys(expanded))  # deduplicate, preserve order


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
    if transport not in ("stdio", "http", "sse"):
        raise ConfigError(f"Invalid transport '{transport}', must be 'stdio', 'http', or 'sse'")

    tools_raw = server_raw.get("tools")
    tools_filter: list[str] | None = None
    if tools_raw is not None:
        if not isinstance(tools_raw, list):
            raise ConfigError("'tools' must be a list of tool group names")
        tools_filter = _expand_tool_groups([str(t) for t in tools_raw])

    disabled_tools_raw = server_raw.get("disabled_tools")
    disabled_tools_filter: list[str] | None = None
    if disabled_tools_raw is not None:
        if not isinstance(disabled_tools_raw, list):
            raise ConfigError("'disabled_tools' must be a list of tool group names")
        disabled_tools_filter = _expand_tool_groups([str(t) for t in disabled_tools_raw])

    server_config = ServerConfig(
        transport=transport,
        host=server_raw.get("host", "127.0.0.1"),
        port=server_raw.get("port", 8080),
        log_level=server_raw.get("log_level", "info"),
        log_file=server_raw.get("log_file"),
        auth_token=_resolve_env_vars(server_raw["auth_token"]) if server_raw.get("auth_token") else None,
        rate_limit=server_raw.get("rate_limit", 60),
        tools=tools_filter,
        disabled_tools=disabled_tools_filter,
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
            skip_version_check=srv.get("skip_version_check", False),
        )

    return AppConfig(server=server_config, zabbix_servers=zabbix_servers)
