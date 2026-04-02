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

"""Multi-server Zabbix API client manager."""

from __future__ import annotations

import logging
import re
import threading
import time
from typing import Any

from zabbix_utils import ZabbixAPI
from zabbix_utils.exceptions import ProcessingError

from zabbix_mcp.config import AppConfig, ZabbixServerConfig

logger = logging.getLogger("zabbix_mcp.client")


class ReadOnlyError(Exception):
    """Raised when a write operation is attempted on a read-only server."""


class RateLimitError(Exception):
    """Raised when the rate limit is exceeded."""


class _RateLimiter:
    """Per-client sliding window rate limiter (calls per minute).

    Each unique *client_id* gets its own independent counter.
    When *client_id* is ``None``, a shared "global" bucket is used.
    """

    _MAX_BUCKETS = 1000

    def __init__(self, max_calls: int) -> None:
        self._max_calls = max_calls
        self._buckets: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def check(self, client_id: str | None = None) -> None:
        if self._max_calls <= 0:
            return
        key = client_id or "__global__"
        now = time.monotonic()
        with self._lock:
            # Periodic cleanup of stale buckets
            if len(self._buckets) > 50:
                stale = [k for k, v in self._buckets.items() if not v or now - v[-1] > 120.0]
                for k in stale:
                    del self._buckets[k]

            # Hard limit on bucket count to prevent memory exhaustion
            if key not in self._buckets and len(self._buckets) >= self._MAX_BUCKETS:
                # Evict the oldest bucket
                oldest_key = min(self._buckets, key=lambda k: self._buckets[k][-1] if self._buckets[k] else 0.0)
                del self._buckets[oldest_key]

            calls = self._buckets.get(key, [])
            calls = [t for t in calls if now - t < 60.0]
            if len(calls) >= self._max_calls:
                raise RateLimitError(
                    f"Rate limit exceeded ({self._max_calls} calls/minute). "
                    f"Try again shortly or increase rate_limit in config."
                )
            calls.append(now)
            self._buckets[key] = calls


class ClientManager:
    """Manages connections to multiple Zabbix servers with lazy connect and auto-reconnect."""

    def __init__(self, config: AppConfig) -> None:
        self._config = config
        self._clients: dict[str, ZabbixAPI] = {}
        self._rate_limiter = _RateLimiter(config.server.rate_limit)

    @property
    def server_names(self) -> list[str]:
        return list(self._config.zabbix_servers.keys())

    @property
    def default_server(self) -> str | None:
        return self._config.default_server

    def get_server_config(self, name: str) -> ZabbixServerConfig:
        if name not in self._config.zabbix_servers:
            available = ", ".join(self.server_names)
            raise ValueError(
                f"Unknown Zabbix server '{name}'. Available: {available}"
            )
        return self._config.zabbix_servers[name]

    def _connect(self, name: str) -> ZabbixAPI:
        """Create and authenticate a Zabbix API client."""
        srv = self.get_server_config(name)
        logger.info("Connecting to Zabbix server '%s' at %s", name, srv.url)

        api = ZabbixAPI(url=srv.url, validate_certs=srv.verify_ssl, skip_version_check=srv.skip_version_check)
        api.login(token=srv.api_token)

        version = api.api_version()
        logger.info("Connected to '%s' — Zabbix %s", name, version)
        return api

    def _get_client(self, name: str) -> ZabbixAPI:
        """Get or create a client for the given server."""
        if name not in self._clients:
            self._clients[name] = self._connect(name)
        return self._clients[name]

    def _reconnect(self, name: str) -> ZabbixAPI:
        """Force reconnect to a server."""
        logger.warning("Reconnecting to Zabbix server '%s'", name)
        self._clients.pop(name, None)
        client = self._connect(name)
        self._clients[name] = client
        return client

    def resolve_server(self, server: str | None) -> str:
        """Resolve server name, falling back to default."""
        if server:
            if server not in self._config.zabbix_servers:
                available = ", ".join(self.server_names)
                raise ValueError(
                    f"Unknown Zabbix server '{server}'. Available: {available}"
                )
            return server
        default = self.default_server
        if default is None:
            raise ValueError("No Zabbix servers configured")
        return default

    def call(self, server: str, method: str, params: Any) -> Any:
        """Execute a Zabbix API call with rate limiting and auto-reconnect."""
        self._rate_limiter.check()
        client = self._get_client(server)
        try:
            return self._do_call(client, method, params)
        except ProcessingError as e:
            error_msg = str(e).lower()
            if "not authorised" in error_msg or "session" in error_msg or "re-login" in error_msg:
                client = self._reconnect(server)
                return self._do_call(client, method, params)
            raise

    # Strict format: "object.method" — only ASCII letters, single dot separator.
    _METHOD_RE = re.compile(r"^[a-zA-Z]+\.[a-zA-Z]+$")

    def _do_call(self, client: ZabbixAPI, method: str, params: Any) -> Any:
        """Execute the actual API call by traversing the method path."""
        if not self._METHOD_RE.match(method):
            raise ValueError(
                f"Invalid API method format: '{method}'. "
                f"Expected 'object.method' (e.g. 'host.get')."
            )
        parts = method.split(".")
        obj: Any = client
        for part in parts:
            obj = getattr(obj, part)
        # Array-based methods (delete, history.clear, etc.) need positional arg
        if isinstance(params, list):
            return obj(params)
        return obj(**params)

    def check_connection(self, server: str) -> None:
        """Verify connectivity to a Zabbix server (for health checks)."""
        client = self._get_client(server)
        client.api_version()

    def get_version(self, server: str) -> str:
        """Return the Zabbix API version string for the given server."""
        client = self._get_client(server)
        return str(client.api_version())

    def check_write(self, server: str) -> None:
        """Raise ReadOnlyError if the server is read-only."""
        srv = self.get_server_config(server)
        if srv.read_only:
            raise ReadOnlyError(
                f"Server '{server}' is configured as read-only. "
                f"Set read_only = false in config to allow write operations."
            )

    def close(self) -> None:
        """Logout and close all client connections."""
        for name, client in self._clients.items():
            try:
                client.logout()
                logger.info("Disconnected from '%s'", name)
            except Exception:
                logger.warning("Failed to logout from '%s'", name, exc_info=True)
        self._clients.clear()
