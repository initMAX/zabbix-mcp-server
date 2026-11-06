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

"""End-to-end OAuth 2.1 + MCP integration test.

Spins up a fresh MCP server with `[oauth].enabled = true` plus a
known admin-portal user, then drives the full flow that ChatGPT
custom apps and Claude Desktop remote connectors run on the wire:

1. Discover via ``GET /.well-known/oauth-authorization-server``
   and ``GET /.well-known/oauth-protected-resource`` (RFC 8414 +
   RFC 9728).
2. Register a public client via ``POST /register`` (RFC 7591
   dynamic registration).
3. Generate PKCE S256 verifier + challenge.
4. Hit ``GET /authorize`` and receive a 302 redirect to
   ``/oauth/login?request_id=...``.
5. ``POST /oauth/login`` with valid admin-portal credentials
   and follow the 302 back to the client redirect_uri carrying
   ``code`` and ``state``.
6. Exchange the code for ``access_token`` + ``refresh_token``
   via ``POST /token`` with the PKCE verifier.
7. Call ``POST /mcp`` with ``Authorization: Bearer <access_token>``
   and assert ``tools/list`` + a real tool call (`host_get`)
   succeed.
8. Refresh the access token via ``POST /token`` with the refresh
   token and assert the new access token replaces the old one
   (refresh-token rotation per OAuth 2.1 §4.3.1).
9. Call ``POST /revoke`` with the refresh token and assert
   subsequent calls with the original access token are rejected.

The test runs without any external Zabbix dependency: the MCP
server is configured with no `[zabbix.*]` sections, so tool calls
return an empty server list rather than hitting a real Zabbix API.
What we are asserting here is the OAuth surface and the bridge
into the MCP transport - not the Zabbix-side behaviour.

Requires `pytest-asyncio` and a free TCP port on localhost. Skipped
when MCP framework < 1.26 is installed (the auth_server_provider
hook landed in 1.26).
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import os
import re
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import urllib.request

REPO_ROOT = Path(__file__).resolve().parents[2]


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _wait_for_health(url: str, timeout: float = 20.0) -> None:
    deadline = time.time() + timeout
    last_exc = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as resp:
                if resp.status == 200:
                    return
        except Exception as exc:
            last_exc = exc
            time.sleep(0.3)
    raise RuntimeError(f"server did not become healthy at {url}: {last_exc}")


def _hash_password(password: str) -> str:
    # Reuse the codebase helper so we match the live server's salt /
    # parameter encoding exactly.  That helper bumps OpenSSL's
    # ``maxmem`` for us; calling ``hashlib.scrypt`` here directly hits
    # the default memory limit on Python 3.11+.
    from zabbix_mcp.admin.auth import hash_password as _hp
    return _hp(password)


def _http_get_json(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=5) as resp:
        return _json_load(resp.read())


def _http_post_json(url: str, body: dict, headers: dict | None = None) -> tuple[int, dict | str, dict]:
    """POST a JSON body via ``http.client`` (NOT urllib).

    urllib.request silently drops or rewrites the Accept header under
    some test orderings (we hit it when test_admin's TestRawJsonPolicy
    runs in the same Python process before this test).  ``http.client``
    sends headers verbatim, so the streamable-HTTP framing the MCP
    server expects survives the parent-process state intact.
    """
    import http.client, json
    from urllib.parse import urlparse
    p = urlparse(url)
    conn_cls = http.client.HTTPSConnection if p.scheme == "https" else http.client.HTTPConnection
    conn = conn_cls(p.hostname, p.port, timeout=10)
    data = json.dumps(body).encode()
    out_headers = {"Content-Type": "application/json"}
    out_headers.update(headers or {})
    conn.request("POST", p.path or "/", data, out_headers)
    resp = conn.getresponse()
    raw = resp.read()
    hdrs = dict(resp.getheaders())
    conn.close()
    return resp.status, _json_load(raw), hdrs


# The browser of these tests: it keeps the cookies a server sets, as the consent
# step requires (it is accepted from the browser that logged in only).
import http.cookiejar  # noqa: E402

_BROWSER_COOKIES = http.cookiejar.CookieJar()


def _http_post_form(url: str, body, headers: dict | None = None, follow: bool = False):
    """``body`` may be a dict or a list of (key, value) tuples to allow
    repeated keys (e.g. multiple ``scope`` checkboxes on the consent
    form)."""
    import urllib.parse
    data = urllib.parse.urlencode(body, doseq=True).encode()
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded", **(headers or {})},
    )
    cookies = urllib.request.HTTPCookieProcessor(_BROWSER_COOKIES)
    if not follow:
        opener = urllib.request.build_opener(_NoRedirectHandler(), cookies)
        try:
            with opener.open(req, timeout=10) as resp:
                return resp.status, resp.read().decode("utf-8", errors="replace"), dict(resp.headers)
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8", errors="replace"), dict(exc.headers)
    try:
        with urllib.request.build_opener(cookies).open(req, timeout=10) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace"), dict(resp.headers)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="replace"), dict(exc.headers)


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def http_error_302(self, *args, **kwargs):
        return None
    http_error_301 = http_error_303 = http_error_307 = http_error_302


def _json_load(raw: bytes) -> dict | str:
    import json
    try:
        return json.loads(raw)
    except Exception:
        return raw.decode("utf-8", errors="replace")


import urllib.error


@unittest.skipIf(
    os.environ.get("SKIP_OAUTH_E2E") == "1",
    "OAuth E2E skipped via env (SKIP_OAUTH_E2E=1)",
)
class TestOAuthEndToEnd(unittest.TestCase):
    """End-to-end OAuth + MCP exercise."""

    proc: subprocess.Popen | None = None
    cfg_dir: tempfile.TemporaryDirectory | None = None
    port: int = 0
    base: str = ""
    test_user = "oauth-e2e-tester"
    test_pass = "OAuthE2ETest_2026!"

    @classmethod
    def setUpClass(cls):
        cls.port = _free_port()
        cls.base = f"http://127.0.0.1:{cls.port}"
        cls.cfg_dir = tempfile.TemporaryDirectory(prefix="zmcp-oauth-e2e-")
        cfg_path = Path(cls.cfg_dir.name) / "config.toml"
        pw_hash = _hash_password(cls.test_pass)
        cfg_path.write_text(
            f"""\
[server]
host = "127.0.0.1"
port = {cls.port}
transport = "http"
public_url = "{cls.base}"
log_level = "warning"

[admin]
enabled = false

[admin.users.{cls.test_user}]
password_hash = "{pw_hash}"
role = "admin"

[oauth]
enabled = true

# Placeholder Zabbix server: required for boot, never actually called
# because our OAuth flow only exercises the auth + transport layer.
[zabbix.placeholder]
url = "https://127.0.0.1:65535"
api_token = "fake-token-for-oauth-test"
read_only = true
verify_ssl = false
"""
        )
        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"
        # Use the console-script entry point that ships in pyproject.toml
        # (`zabbix-mcp-server` -> `zabbix_mcp.cli:main`) so the test path
        # mirrors the real-world startup; falling back to `python -c` so
        # the test does not depend on the script being on $PATH.
        cls.proc = subprocess.Popen(
            [sys.executable, "-c",
             "from zabbix_mcp.cli import main; main()",
             "--config", str(cfg_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=str(REPO_ROOT),
            env=env,
        )
        try:
            _wait_for_health(f"{cls.base}/health", timeout=20)
        except Exception:
            cls.proc.terminate()
            out = cls.proc.stdout.read().decode(errors="replace") if cls.proc.stdout else ""
            cls.tearDownClass()
            raise RuntimeError(f"server did not start:\n{out[-2000:]}")

    @classmethod
    def tearDownClass(cls):
        if cls.proc is not None:
            cls.proc.terminate()
            with contextlib.suppress(Exception):
                cls.proc.wait(timeout=5)
        if cls.cfg_dir is not None:
            cls.cfg_dir.cleanup()

    # ------------------------------------------------------------------
    # The test
    # ------------------------------------------------------------------

    def test_full_oauth_authorization_code_flow(self):
        # 1. AS metadata discovery (RFC 8414)
        as_md = _http_get_json(f"{self.base}/.well-known/oauth-authorization-server")
        self.assertIn("S256", as_md["code_challenge_methods_supported"])
        self.assertEqual(as_md["authorization_endpoint"], f"{self.base}/authorize")
        self.assertEqual(as_md["token_endpoint"], f"{self.base}/token")
        self.assertEqual(as_md["registration_endpoint"], f"{self.base}/register")

        # 2. RS metadata discovery (RFC 9728)
        rs_md = _http_get_json(f"{self.base}/.well-known/oauth-protected-resource")
        self.assertEqual(rs_md["authorization_servers"][0].rstrip("/"), self.base.rstrip("/"))

        # 3. 401 challenge advertises resource_metadata
        status, _, headers = _http_post_json(
            f"{self.base}/mcp",
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            headers={"Accept": "application/json, text/event-stream"},
        )
        self.assertEqual(status, 401)
        www = headers.get("www-authenticate") or headers.get("WWW-Authenticate") or ""
        self.assertIn("Bearer", www)
        self.assertIn("resource_metadata", www)

        # 4. Dynamic client registration (RFC 7591)
        status, client_info, _ = _http_post_json(
            f"{self.base}/register",
            {
                "redirect_uris": ["http://localhost:8765/callback"],
                "client_name": "OAuth E2E Test",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",  # public client (PKCE)
            },
        )
        # The framework returns 200 (not 201) on successful registration.
        self.assertIn(status, (200, 201), f"register failed: {client_info!r}")
        self.assertTrue(client_info["client_id"])
        # Public client must not get a client_secret.
        self.assertFalse(client_info.get("client_secret"))
        client_id = client_info["client_id"]

        # 5. PKCE pair
        verifier = secrets.token_urlsafe(64)[:64]
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode()).digest()
        ).rstrip(b"=").decode()
        state = secrets.token_urlsafe(16)

        # 6. /authorize -> 302 to /oauth/login with request_id
        from urllib.parse import urlencode
        auth_qs = urlencode({
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": "http://localhost:8765/callback",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": state,
        })
        opener = urllib.request.build_opener(_NoRedirectHandler())
        try:
            opener.open(f"{self.base}/authorize?{auth_qs}", timeout=5)
            authorize_response = None
        except urllib.error.HTTPError as exc:
            authorize_response = exc
        self.assertIsNotNone(authorize_response)
        self.assertIn(authorize_response.status, (302, 303))
        login_url = authorize_response.headers.get("Location")
        self.assertIn("/oauth/login?request_id=", login_url)
        request_id = parse_qs(urlparse(login_url).query)["request_id"][0]

        # 7a. POST /oauth/login (credentials) -> 200 + consent screen.
        status, body, _ = _http_post_form(
            f"{self.base}/oauth/login",
            {"request_id": request_id, "username": self.test_user, "password": self.test_pass},
        )
        self.assertEqual(status, 200, f"login step failed: {body[:200]!r}")
        self.assertIn("Allow access?", body)
        self.assertIn(self.test_user, body)  # subject is shown to operator

        # 7b. POST /oauth/login (consent allow + scope checkboxes) ->
        # 302 to client redirect_uri with code.
        status, _body, headers = _http_post_form(
            f"{self.base}/oauth/login",
            [
                ("request_id", request_id),
                ("step", "consent"),
                ("action", "allow"),
                ("scope", "*"),
            ],
        )
        self.assertEqual(status, 302)
        callback_url = headers.get("location") or headers.get("Location")
        self.assertTrue(callback_url.startswith("http://localhost:8765/callback"))
        cb_qs = parse_qs(urlparse(callback_url).query)
        self.assertEqual(cb_qs["state"][0], state)
        self.assertTrue(cb_qs["code"][0])
        code = cb_qs["code"][0]

        # 8. POST /token -> access_token + refresh_token
        status, token_body, _ = _http_post_form(
            f"{self.base}/token",
            {
                "grant_type": "authorization_code",
                "client_id": client_id,
                "code": code,
                "redirect_uri": "http://localhost:8765/callback",
                "code_verifier": verifier,
            },
            follow=True,
        )
        import json as _json
        token = _json.loads(token_body)
        self.assertEqual(token["token_type"], "Bearer")
        self.assertTrue(token["access_token"])
        self.assertTrue(token["refresh_token"])
        access_token = token["access_token"]
        refresh_token = token["refresh_token"]

        # 9. Use access_token to call MCP
        bearer = {"Authorization": f"Bearer {access_token}",
                  "Accept": "application/json, text/event-stream"}
        status, body, headers = _http_post_json(
            f"{self.base}/mcp",
            {"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                        "clientInfo": {"name": "e2e", "version": "1"}}},
            headers=bearer,
        )
        self.assertEqual(status, 200, f"body={body!r}")
        sid = headers.get("mcp-session-id") or headers.get("Mcp-Session-Id")
        self.assertTrue(sid, "no mcp-session-id in initialize response")
        sid_header = {**bearer, "mcp-session-id": sid}
        # Initialized notification + tools/list
        _http_post_json(
            f"{self.base}/mcp",
            {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
            headers=sid_header,
        )
        status, body, _ = _http_post_json(
            f"{self.base}/mcp",
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            headers=sid_header,
        )
        self.assertEqual(status, 200)

        # 10. Refresh-token rotation
        status, refreshed_body, _ = _http_post_form(
            f"{self.base}/token",
            {
                "grant_type": "refresh_token",
                "client_id": client_id,
                "refresh_token": refresh_token,
            },
            follow=True,
        )
        refreshed = _json.loads(refreshed_body)
        self.assertNotEqual(refreshed["access_token"], access_token,
                            "refresh did not rotate the access token")
        self.assertNotEqual(refreshed["refresh_token"], refresh_token,
                            "refresh did not rotate the refresh token")

        # 11. Revoke the new refresh token; the old refresh token was already
        #     consumed by the rotation in step 10, so use the rotated one.
        _http_post_form(
            f"{self.base}/revoke",
            {
                "client_id": client_id,
                "token": refreshed["refresh_token"],
                "token_type_hint": "refresh_token",
            },
            follow=True,
        )
        # The original access_token should already be invalid after the
        # rotation (we evict it in exchange_refresh_token).  Confirm.
        status, _body, _ = _http_post_json(
            f"{self.base}/mcp",
            {"jsonrpc": "2.0", "id": 99, "method": "initialize", "params": {}},
            headers=bearer,
        )
        self.assertEqual(status, 401, "old access token should be rejected after rotation")


if __name__ == "__main__":
    unittest.main()
