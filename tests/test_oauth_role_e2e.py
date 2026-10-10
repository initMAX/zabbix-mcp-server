#
# Zabbix MCP Server
# Copyright (C) 2026 initMAX s.r.o.
# Licensed under the GNU Affero General Public License v3.
# See LICENSE for details.
#

"""End-to-end: a viewer's OAuth token cannot write, an operator's can.

Boots the real server, runs the real browser-less authorization code
flow (register, authorize, login, consent, token) for a ``viewer`` and
an ``operator`` portal account, then calls tools over the MCP endpoint.
The Zabbix server is a placeholder nobody listens on, so a call that
passes authorization fails with a connection error - which is exactly
the distinction under test: "read-only" versus "got through to Zabbix".
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import secrets
import subprocess
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

from tests.test_oauth_e2e import (
    REPO_ROOT, _NoRedirectHandler, _free_port, _hash_password, _http_post_form,
    _http_post_json, _wait_for_health,
)


def _rpc(body):
    """Unwrap a JSON or SSE-framed JSON-RPC response body."""
    if isinstance(body, dict):
        return body
    text = body if isinstance(body, str) else body.decode(errors="replace")
    for line in text.splitlines():
        if line.startswith("data: "):
            return json.loads(line[6:])
    return json.loads(text)


class TestOAuthRoleEndToEnd(unittest.TestCase):
    proc = None
    cfg_dir = None
    users = {"viewer": "Viewer_Pass_2026!", "operator": "Operator_Pass_2026!"}

    @classmethod
    def setUpClass(cls):
        cls.port = _free_port()
        cls.base = f"http://127.0.0.1:{cls.port}"
        cls.cfg_dir = tempfile.TemporaryDirectory(prefix="zmcp-oauth-role-")
        cfg = Path(cls.cfg_dir.name) / "config.toml"
        users = "".join(
            f'[admin.users.{role}1]\npassword_hash = "{_hash_password(pw)}"\nrole = "{role}"\n\n'
            for role, pw in cls.users.items()
        )
        cfg.write_text(f'''[server]
host = "127.0.0.1"
port = {cls.port}
transport = "http"
public_url = "{cls.base}"
log_level = "warning"

[admin]
enabled = false

{users}[oauth]
enabled = true

# Writable on purpose: the server-level read_only must not be what
# stops the viewer. Nothing listens here; a call that passes
# authorization fails on the connection instead.
[zabbix.placeholder]
url = "https://127.0.0.1:65535"
api_token = "fake"
read_only = false
verify_ssl = false
''')
        env = os.environ.copy(); env["PYTHONUNBUFFERED"] = "1"
        cls.proc = subprocess.Popen(
            [sys.executable, "-c", "from zabbix_mcp.cli import main; main()", "--config", str(cfg)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=str(REPO_ROOT), env=env,
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

    # -- the real flow ---------------------------------------------------

    def _tokens_for(self, role, scopes=("monitoring",)):
        status, client_info, _ = _http_post_json(f"{self.base}/register", {
            "redirect_uris": ["http://localhost:8765/callback"], "client_name": f"role e2e {role}",
            "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"],
            "token_endpoint_auth_method": "none",
        })
        self.assertIn(status, (200, 201), client_info)
        client_id = client_info["client_id"]
        verifier = secrets.token_urlsafe(64)[:64]
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        qs = urlencode({"response_type": "code", "client_id": client_id,
                        "redirect_uri": "http://localhost:8765/callback",
                        "code_challenge": challenge, "code_challenge_method": "S256", "state": "s"})
        opener = urllib.request.build_opener(_NoRedirectHandler())
        try:
            opener.open(f"{self.base}/authorize?{qs}", timeout=5); resp = None
        except urllib.error.HTTPError as exc:
            resp = exc
        request_id = parse_qs(urlparse(resp.headers.get("Location")).query)["request_id"][0]
        status, body, _ = _http_post_form(f"{self.base}/oauth/login", {
            "request_id": request_id, "username": f"{role}1", "password": self.users[role]})
        self.assertEqual(status, 200, body[:200])
        status, _b, headers = _http_post_form(f"{self.base}/oauth/login",
            [("request_id", request_id), ("step", "consent"), ("action", "allow")]
            + [("scope", s) for s in scopes])
        self.assertEqual(status, 302, _b[:300])
        code = parse_qs(urlparse(headers.get("location") or headers.get("Location")).query)["code"][0]
        status, token_body, _ = _http_post_form(f"{self.base}/token", {
            "grant_type": "authorization_code", "client_id": client_id, "code": code,
            "redirect_uri": "http://localhost:8765/callback", "code_verifier": verifier}, follow=True)
        tok = json.loads(token_body)
        self.assertTrue(tok.get("access_token"), token_body)
        return client_id, tok

    def _session(self, access_token):
        bearer = {"Authorization": f"Bearer {access_token}", "Accept": "application/json, text/event-stream"}
        status, body, headers = _http_post_json(f"{self.base}/mcp", {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                       "clientInfo": {"name": "role-e2e", "version": "1"}}}, headers=bearer)
        self.assertEqual(status, 200, body)
        sid = headers.get("mcp-session-id") or headers.get("Mcp-Session-Id")
        h = {**bearer, "mcp-session-id": sid}
        _http_post_json(f"{self.base}/mcp", {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}, headers=h)
        return h

    def _call(self, h, tool, args):
        status, body, _ = _http_post_json(f"{self.base}/mcp", {
            "jsonrpc": "2.0", "id": 7, "method": "tools/call",
            "params": {"name": tool, "arguments": args}}, headers=h)
        self.assertEqual(status, 200, body)
        res = _rpc(body).get("result", {})
        text = "".join(c.get("text", "") for c in res.get("content", []))
        return bool(res.get("isError")), text

    def _read_resource(self, h, uri):
        status, body, _ = _http_post_json(f"{self.base}/mcp", {
            "jsonrpc": "2.0", "id": 8, "method": "resources/read", "params": {"uri": uri}}, headers=h)
        self.assertEqual(status, 200, body)
        return _rpc(body)

    # -- tests -----------------------------------------------------------

    def test_viewer_is_read_only_operator_is_not(self):
        _, viewer = self._tokens_for("viewer")
        hv = self._session(viewer["access_token"])
        is_err, text = self._call(hv, "host_create", {"params": {"host": "x", "groups": [{"groupid": "1"}]}})
        self.assertTrue(is_err)
        self.assertIn("read-only", text)
        self.assertIn("oauth:", text)
        # A read within the scope is authorized: it reaches the
        # placeholder Zabbix and fails on the connection, not on auth.
        is_err, text = self._call(hv, "host_get", {"limit": 1})
        self.assertTrue(is_err)
        self.assertNotIn("read-only", text)
        self.assertNotIn("not authorized", text)

        _, operator = self._tokens_for("operator")
        ho = self._session(operator["access_token"])
        is_err, text = self._call(ho, "host_create", {"params": {"host": "x", "groups": [{"groupid": "1"}]}})
        self.assertTrue(is_err)  # the placeholder is unreachable...
        self.assertNotIn("read-only", text)  # ...but authorization let it through

    def test_viewer_stays_read_only_after_refresh(self):
        client_id, viewer = self._tokens_for("viewer")
        status, body, _ = _http_post_form(f"{self.base}/token", {
            "grant_type": "refresh_token", "client_id": client_id,
            "refresh_token": viewer["refresh_token"]}, follow=True)
        refreshed = json.loads(body)
        h = self._session(refreshed["access_token"])
        is_err, text = self._call(h, "host_delete", {"ids": ["1"]})
        self.assertTrue(is_err)
        self.assertIn("read-only", text)

    def test_viewer_cannot_grant_a_scope_outside_the_cap(self):
        # The cap is unchanged by this release: a viewer still cannot
        # take "users" or "*".
        with self.assertRaises(AssertionError):
            self._tokens_for("viewer", scopes=("users",))

    def test_resources_honour_scope(self):
        # "alerts" does not cover hosts: the resource is refused before
        # any Zabbix call.
        _, operator = self._tokens_for("operator", scopes=("alerts",))
        h = self._session(operator["access_token"])
        reply = self._read_resource(h, "zabbix://placeholder/hosts")
        err = json.dumps(reply)
        self.assertIn("scope does not include 'host'", err)
        # With monitoring the guard passes and the placeholder answers
        # with a connection error instead.
        _, operator2 = self._tokens_for("operator", scopes=("monitoring",))
        h2 = self._session(operator2["access_token"])
        reply = json.dumps(self._read_resource(h2, "zabbix://placeholder/hosts"))
        self.assertNotIn("scope does not include", reply)
        self.assertNotIn("not authorized", reply)


if __name__ == "__main__":
    unittest.main()
