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

# zabbix_utils ships with `User-Agent: zabbix_utils/<ver>` and no
# Origin / Referer. Cloudflare and similar WAFs that sit in front of
# many Zabbix frontends 403 those requests as "non-browser bot" -
# reported 2026-04-27 as Test Connection flapping ("obcas OK obcas ze
# to nejde, debilne"). Empirically, sending a Chrome-shaped
# User-Agent + same-origin Origin/Referer headers cleared 10/10
# probes against a Cloudflare-fronted Zabbix that was previously
# 9/10 blocked.
#
# The library has no constructor hook for headers, so we wrap
# `urllib.request.urlopen` inside the zabbix_utils.api module with a
# function that mutates the outgoing Request before forwarding. The
# wrap is scoped to that one module via `_zb_api_mod.ul.urlopen`, so
# it does NOT affect any other urllib calls in the process (admin
# portal HTTP fetches, update_check GitHub poll, etc.).
try:
    import zabbix_utils.api as _zb_api_mod
    import urllib.request as _ul

    _BROWSER_UA = (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    )
    _orig_urlopen = _zb_api_mod.ul.urlopen

    def _patched_urlopen(req, *args, **kwargs):
        # Only mutate Request objects (not bare URL strings).
        if isinstance(req, _ul.Request):
            req.add_header("User-Agent", _BROWSER_UA)
            req.add_header("Accept", "application/json, text/plain, */*")
            req.add_header("Accept-Language", "en-US,en;q=0.9")
            # Origin / Referer derived from the request URL host.
            try:
                from urllib.parse import urlsplit
                parts = urlsplit(req.full_url)
                origin = f"{parts.scheme}://{parts.netloc}"
                req.add_header("Origin", origin)
                req.add_header("Referer", origin + "/")
            except Exception:
                pass
        return _orig_urlopen(req, *args, **kwargs)

    _zb_api_mod.ul.urlopen = _patched_urlopen
except Exception:
    pass

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
    """Manages connections to multiple Zabbix servers with lazy connect and auto-reconnect.

    Thread-safety: tool handlers run under `asyncio.to_thread`, so two
    concurrent first-calls for the same server can race on dict
    assignment and leak a connection. We serialize connect/reconnect
    per server with an RLock. Read-only lookups (server_names,
    default_server, get_version) are intentionally lock-free because
    the underlying dicts are only mutated behind the lock and Python's
    GIL makes single reads atomic.
    """

    def __init__(self, config: AppConfig) -> None:
        self._config = config
        self._clients: dict[str, ZabbixAPI] = {}
        self._versions: dict[str, str] = {}
        self._rate_limiter = _RateLimiter(config.server.rate_limit)
        self._lock = threading.RLock()

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

        # A hung Zabbix frontend must not stall the MCP thread pool
        # indefinitely. zabbix-utils accepts `timeout` seconds on the
        # ZabbixAPI constructor and plumbs it through to urllib. The
        # 300 s default matches Zabbix PHP frontend's max_execution_time
        # so expensive exports / long history.get ranges can complete.
        timeout = getattr(srv, "request_timeout", 300) or 300
        api = ZabbixAPI(
            url=srv.url,
            validate_certs=srv.verify_ssl,
            skip_version_check=srv.skip_version_check,
            timeout=timeout,
        )
        api.login(token=srv.api_token)

        version = api.api_version()
        logger.info("Connected to '%s' - Zabbix %s", name, version)
        return api

    def _get_client(self, name: str) -> ZabbixAPI:
        """Get or create a client for the given server."""
        # Fast path: already connected, return without taking the lock.
        client = self._clients.get(name)
        if client is not None:
            return client
        # Slow path: at most one thread creates the connection.
        with self._lock:
            client = self._clients.get(name)
            if client is None:
                client = self._connect(name)
                self._clients[name] = client
            return client

    def _reconnect(self, name: str) -> ZabbixAPI:
        """Force reconnect to a server."""
        logger.warning("Reconnecting to Zabbix server '%s'", name)
        with self._lock:
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

    def call_with_session(self, server: str, method: str, params: Any, sessionid: str) -> Any:
        """Execute a Zabbix API call authenticated with an arbitrary session id.

        The standard ``call()`` path always uses the configured
        ``api_token`` for ``[zabbix.<name>]`` - which works for every
        regular tool. ``user.logout`` / ``user.checkAuthentication``
        / ``userdirectory.test`` are special: they verify or
        invalidate the session belonging to the CALLER. Using the
        configured api_token on those would either invalidate that
        token (logout) or always fail (checkAuthentication looks up
        the ``sessions`` table which has no row for an api_token).

        This helper bypasses the cached ``zabbix_utils.ZabbixAPI``
        client and posts a raw JSON-RPC request to ``api_jsonrpc.php``
        with the supplied ``sessionid`` in the ``auth`` field. Used
        only by tools that explicitly opt in via an ``auth_sessionid``
        argument from the caller (typically the value returned by a
        prior ``user.login`` call).
        """
        import json as _json
        import ssl as _ssl
        import urllib.request as _urllib_request
        srv = self.get_server_config(server)
        url = srv.url.rstrip("/") + "/api_jsonrpc.php"
        # Zabbix 6.4+ moved auth out of the body and onto the
        # ``Authorization: Bearer`` header. Older Zabbix versions
        # accept either; the header path works on every supported
        # version so use it unconditionally.
        # ``user.checkAuthentication`` validates a session id passed in
        # the body as ``sessionid``. The MCP wrapper exposes this via
        # the ``auth_sessionid`` arg for ergonomic reasons (one place
        # to put the session id), so when the caller omits the body
        # ``sessionid`` we copy ``auth_sessionid`` into it. Otherwise
        # the call would fail with "missing parameter sessionid".
        if method == "user.checkAuthentication":
            params = dict(params or {})
            params.setdefault("sessionid", sessionid)
        body = _json.dumps({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1,
        }).encode("utf-8")
        ctx = _ssl.create_default_context()
        if not srv.verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
        # ``user.checkAuthentication`` is the one method Zabbix REJECTS
        # when called WITH an Authorization header ("must be called
        # without authorization header"). The session id goes only
        # into the body params for that method; for everything else
        # we still forward it as a Bearer header.
        headers = {"Content-Type": "application/json-rpc"}
        if method != "user.checkAuthentication":
            headers["Authorization"] = f"Bearer {sessionid}"
        req = _urllib_request.Request(url, data=body, headers=headers)
        with _urllib_request.urlopen(req, timeout=srv.request_timeout, context=ctx) as resp:
            data = _json.loads(resp.read().decode("utf-8"))
        if "error" in data:
            err = data["error"]
            from zabbix_utils.exceptions import APIRequestError
            # zabbix_utils ``APIRequestError.__init__`` reaches into a
            # nested ``body`` field for masking; satisfy that contract.
            raise APIRequestError({
                "code": err.get("code"),
                "message": err.get("message", ""),
                "data": err.get("data", ""),
                "body": {"method": method, "params": params},
            })
        return data.get("result")

    def call(self, server: str, method: str, params: Any) -> Any:
        """Execute a Zabbix API call with rate limiting and auto-reconnect.

        Auto-reconnect now covers TWO error classes:
        - auth / session errors from ProcessingError (server bounced
          us with re-login required)
        - connection-class errors (ConnectionError, TimeoutError,
          OSError, ssl.SSLError) - these mean the cached TCP/TLS
          socket was killed (NAT idle timeout, server restart, TLS
          session expiry) and the next call needs a fresh connect.
          Without this retry the cached broken client kept poisoning
          every subsequent call until process restart - reported as
          "validation flaky / sometimes OK sometimes fails".
        """
        import ssl
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
        except (ConnectionError, TimeoutError, ssl.SSLError, OSError):
            client = self._reconnect(server)
            return self._do_call(client, method, params)

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

    def check_connection(self, server: str) -> dict:
        """Verify connectivity and token auth to a Zabbix server.

        Returns dict with 'api_ok' and 'token_ok' status.
        Raises on connection failure.

        - Always uses a fresh client (force-reconnect) so the result
          reflects the *current* state of the Zabbix server, not a
          cached connection broken by TLS session expiry, NAT idle
          timeout, or a Zabbix daemon restart.
        - Retries up to 3 times on transient 403 / 429 / 5xx because
          Cloudflare-style WAFs in front of Zabbix randomly challenge
          direct JSON-RPC POSTs (no browser cookies, no JA3 match).
          The user-visible symptom was Test Connection flapping
          between OK and Error - reported 2026-04-27 as "obcas OK
          obcas ze to nejde, debilne". 1 + 1.5 + 2.5 s back-off
          gives the WAF time to cool off without making the user
          wait forever for a genuinely-unreachable server.
        """
        import time as _time
        delays = (0.0, 1.0, 1.5, 2.5)  # 4 attempts total
        last_exc: Exception | None = None
        for delay in delays:
            if delay:
                _time.sleep(delay)
            try:
                client = self._reconnect(server)
                client.api_version()
                try:
                    client.host.get(limit=1, output=["hostid"])
                    return {"api_ok": True, "token_ok": True}
                except Exception:
                    return {"api_ok": True, "token_ok": False}
            except Exception as exc:
                last_exc = exc
                msg = str(exc).lower()
                # Only retry on transient WAF-style hiccups. Genuine
                # config errors (DNS, TLS cert, refused) fail fast.
                if not ("403" in msg or "429" in msg or "502" in msg or "503" in msg or "504" in msg or "timed out" in msg or "timeout" in msg):
                    raise
        assert last_exc is not None
        raise last_exc

    def get_version(self, server: str) -> str:
        """Return the Zabbix API version string for the given server (cached)."""
        if server not in self._versions:
            client = self._get_client(server)
            self._versions[server] = str(client.api_version())
        return self._versions[server]

    def check_write(self, server: str) -> None:
        """Raise ReadOnlyError if the server is read-only."""
        srv = self.get_server_config(server)
        if srv.read_only:
            raise ReadOnlyError(
                f"Server '{server}' is configured as read-only. "
                f"Set read_only = false in config to allow write operations."
            )

    def close(self) -> None:
        """Close all client connections. Skip logout for token-based auth."""
        for name, client in self._clients.items():
            try:
                # Token-based auth does not use sessions — logout is a no-op
                # that would generate a warning. Only logout for session-based auth.
                if not self.get_server_config(name).api_token:
                    client.logout()
                logger.info("Disconnected from '%s'", name)
            except Exception:
                logger.warning("Failed to disconnect from '%s'", name, exc_info=True)
        self._clients.clear()
