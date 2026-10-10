#
# Zabbix MCP Server
# Copyright (C) 2026 initMAX s.r.o.
# Licensed under the GNU Affero General Public License v3.
# See LICENSE for details.
#

"""OAuth tokens must carry the portal role, and a viewer must be read-only.

Reported privately (2026-10-07, following SECURITY.md): every OAuth
access token was published with ``read_only=False`` whatever the role
of the portal user who consented. The scope cap keeps a viewer to
``monitoring`` and ``extensions``, but ``monitoring`` contains
host / item / trigger create-update-delete, so a viewer - documented as
read-only - got write tools on every writable server. The same report
noted that the MCP resources (zabbix://<server>/hosts, ...) never ran
the token authorization check.
"""

from __future__ import annotations

import asyncio
import json
import unittest
from unittest.mock import patch

from mcp.shared.auth import OAuthClientInformationFull

from zabbix_mcp.client import ClientManager
from zabbix_mcp.config import AppConfig, ServerConfig, ZabbixServerConfig
from zabbix_mcp.oauth_provider import ZmcpOAuthProvider, _PendingAuthorization, _read_only_for_role
from zabbix_mcp.token_store import TokenInfo, check_token_authorization, current_token_info


def _provider() -> ZmcpOAuthProvider:
    return ZmcpOAuthProvider(public_url="http://127.0.0.1:1", token_store=None)


def _mint(provider, role, scopes=("monitoring",)):
    return provider._mint_token_pair(
        client_id="c", scopes=list(scopes), subject=f"{role}1", role=role, resource=None,
    )


def _load(provider, access_token) -> TokenInfo:
    """What the server publishes for this token on a request.

    asyncio.run gives the coroutine a copy of the context, so the
    contextvar is read inside it, the way a tool handler would.
    """
    async def _run():
        current_token_info.set(None)
        at = await provider.load_access_token(access_token)
        assert at is not None, "token not accepted"
        info = current_token_info.get()
        assert info is not None, "token not published to the contextvar"
        return info
    info = asyncio.run(_run())
    current_token_info.set(info)  # so check_token_authorization sees it in the test
    return info


class TestRoleToReadOnly(unittest.TestCase):

    def tearDown(self):
        current_token_info.set(None)

    def test_viewer_token_is_read_only(self):
        p = _provider()
        info = _load(p, _mint(p, "viewer").access_token)
        self.assertTrue(info.read_only)
        self.assertEqual(info.scopes, ["monitoring"])

    def test_operator_and_admin_tokens_may_write(self):
        p = _provider()
        self.assertFalse(_load(p, _mint(p, "operator").access_token).read_only)
        self.assertFalse(_load(p, _mint(p, "admin").access_token).read_only)

    def test_missing_or_unknown_role_fails_closed(self):
        p = _provider()
        self.assertTrue(_load(p, _mint(p, "").access_token).read_only)
        self.assertTrue(_load(p, _mint(p, "superuser").access_token).read_only)
        for role, expected in (("viewer", True), ("Viewer", True), ("operator", False), ("ADMIN", False), (None, True)):
            with self.subTest(role=role):
                self.assertEqual(_read_only_for_role(role), expected)

    def test_viewer_cannot_write_hosts_even_with_monitoring_scope(self):
        # The reporter's reproduction, run against the real check with
        # the TokenInfo the provider now builds for a viewer.
        p = _provider()
        _load(p, _mint(p, "viewer").access_token)
        for prefix in ("host", "item", "trigger"):
            with self.subTest(prefix=prefix):
                err = check_token_authorization("any", tool_prefix=prefix, is_write=True)
                self.assertIsNotNone(err)
                self.assertIn("read-only", err)
        # Reads within the scope still work.
        self.assertIsNone(check_token_authorization("any", tool_prefix="host"))

    def test_refresh_keeps_the_role(self):
        # A refresh after the access token is gone used to lose the
        # subject; it must not lose the role either, in either direction.
        p = _provider()
        client = OAuthClientInformationFull(client_id="c")
        for role, expected in (("viewer", True), ("operator", False)):
            with self.subTest(role=role):
                pair = _mint(p, role)
                p._access_tokens.pop(pair.access_token, None)  # AT evicted / expired
                rt = asyncio.run(p.load_refresh_token(client, pair.refresh_token))
                self.assertIsNotNone(rt)
                new = asyncio.run(p.exchange_refresh_token(client, rt, []))
                info = _load(p, new.access_token)
                self.assertEqual(info.read_only, expected)
                self.assertEqual(info.name, f"oauth:c:{role}1")

    def test_consent_passes_the_role_onto_the_code(self):
        # complete_pending -> code -> exchange: the role rides along.
        from mcp.server.auth.provider import AuthorizationParams
        from pydantic import AnyUrl
        p = _provider()
        client = OAuthClientInformationFull(client_id="c", redirect_uris=[AnyUrl("http://127.0.0.1:9/cb")])
        params = AuthorizationParams(
            state=None, scopes=["monitoring"], code_challenge="x" * 43,
            redirect_uri=AnyUrl("http://127.0.0.1:9/cb"), redirect_uri_provided_explicitly=True,
        )
        p.stash_pending("req1", _PendingAuthorization(client, params))
        p.complete_pending("req1", ["monitoring"], subject="viewer1", role="viewer")
        code = next(iter(p._codes.values()))
        self.assertEqual(getattr(code, "_role", None), "viewer")
        pair = asyncio.run(p.exchange_authorization_code(client, code))
        self.assertTrue(_load(p, pair.access_token).read_only)


class TestResourcesRunTheAuthorizationCheck(unittest.TestCase):

    def setUp(self):
        from mcp.server.mcpserver import MCPServer
        from zabbix_mcp.server import _register_resources, _register_tools
        self.cfg = AppConfig(server=ServerConfig(), zabbix_servers={
            "prod": ZabbixServerConfig(name="prod", url="http://localhost", api_token="t", read_only=True),
        })
        self.mgr = ClientManager(self.cfg)
        self.mcp = MCPServer(name="test")
        _register_tools(self.mcp, self.mgr)
        _register_resources(self.mcp, self.mgr)

    def tearDown(self):
        current_token_info.set(None)

    def _read(self, uri):
        by_uri = {str(r.uri): r for r in self.mcp._resource_manager.list_resources()}
        self.assertIn(uri, by_uri)
        return asyncio.run(by_uri[uri].read())

    def _set_token(self, **kw):
        base = dict(id="t", name="t", token_hash="sha256:x")
        base.update(kw)
        current_token_info.set(TokenInfo(**base))

    def test_token_bound_to_another_server_is_refused(self):
        self._set_token(allowed_servers=["staging"])
        with patch.object(self.mgr, "call", return_value=[]) as call:
            for uri in ("zabbix://prod/hosts", "zabbix://prod/problems", "zabbix://prod/hostgroups", "zabbix://prod/templates"):
                with self.subTest(uri=uri), self.assertRaises(Exception) as ctx:
                    self._read(uri)
                self.assertIn("not authorized for server 'prod'", str(ctx.exception))
        call.assert_not_called()

    def test_scope_without_the_data_is_refused(self):
        self._set_token(scopes=["alerts"])
        with patch.object(self.mgr, "call", return_value=[]) as call:
            with self.assertRaises(Exception) as ctx:
                self._read("zabbix://prod/hosts")
            self.assertIn("scope does not include 'host'", str(ctx.exception))
            with self.assertRaises(Exception):
                self._read("zabbix://prod/templates")  # "template" is data_collection
        call.assert_not_called()

    def test_wildcard_token_reads(self):
        self._set_token(scopes=["*"])
        with patch.object(self.mgr, "call", return_value=[{"hostid": "1"}]):
            self.assertEqual(json.loads(self._read("zabbix://prod/hosts")), [{"hostid": "1"}])

    def test_no_token_context_reads(self):
        # stdio: no token at all, resources keep working.
        with patch.object(self.mgr, "call", return_value=[]):
            self.assertEqual(json.loads(self._read("zabbix://prod/hostgroups")), [])


if __name__ == "__main__":
    unittest.main()
