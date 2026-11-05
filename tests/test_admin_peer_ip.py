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

"""``[server].trusted_proxies`` means the same on the portal as on the MCP endpoint.

The MCP endpoint has matched its entries as addresses or networks since
v1.36; the portal still compared strings. With ``["10.0.0.0/24"]`` and the
proxy at 10.0.0.5 the endpoint saw the client and the portal saw the proxy,
so every portal user shared one rate-limit bucket.
"""

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from zabbix_mcp.admin.app import _peer_ip  # noqa: E402
from zabbix_mcp.config import trusted_proxy_matcher  # noqa: E402


def _scope(peer: str, forwarded: str | None, trusted: list[str], *, prepared: bool = True) -> dict:
    admin = SimpleNamespace(trusted_proxies=trusted)
    if prepared:
        admin.is_trusted_proxy = trusted_proxy_matcher(trusted, warn=False)
    headers = [(b"x-forwarded-for", forwarded.encode())] if forwarded is not None else []
    return {"type": "http", "client": (peer, 40000), "headers": headers,
            "app": SimpleNamespace(state=SimpleNamespace(admin_app=admin))}


class TestMatcher(unittest.TestCase):
    def test_addresses_and_networks(self):
        is_trusted = trusted_proxy_matcher(["127.0.0.1", "10.0.0.0/24", "::1", "proxy.internal"], warn=False)
        for addr in ("127.0.0.1", "10.0.0.5", "10.0.0.255", "::1", "0:0:0:0:0:0:0:1", "proxy.internal"):
            self.assertTrue(is_trusted(addr), addr)
        for addr in ("127.0.0.2", "10.0.1.5", "::2", "other.internal", "", None, "not an address"):
            self.assertFalse(is_trusted(addr), addr)

    def test_an_empty_list_trusts_nobody(self):
        for entries in ([], None, ()):
            self.assertFalse(trusted_proxy_matcher(entries)("127.0.0.1"))

    def test_an_entry_that_is_no_address_is_reported_once_by_the_endpoint(self):
        with self.assertLogs("zabbix_mcp.config", level="WARNING") as logs:
            trusted_proxy_matcher(["proxy.internal"])
        self.assertIn("only match an exact string", logs.output[0])


class TestThePortal(unittest.TestCase):
    def test_a_proxy_inside_a_trusted_network_is_believed(self):
        self.assertEqual(_peer_ip(_scope("10.0.0.5", "203.0.113.9", ["10.0.0.0/24"])), "203.0.113.9")
        self.assertEqual(_peer_ip(_scope("0:0:0:0:0:0:0:1", "203.0.113.9", ["::1"])), "203.0.113.9")
        # behind two proxies of ours: the entry before them
        self.assertEqual(_peer_ip(_scope("127.0.0.1", "203.0.113.9, 10.0.0.5", ["127.0.0.1", "10.0.0.5"])), "203.0.113.9")

    def test_what_the_client_put_in_front_is_not(self):
        # a proxy that appends: "192.0.2.1" is the client's own claim
        self.assertEqual(_peer_ip(_scope("127.0.0.1", "192.0.2.1, 203.0.113.9", ["127.0.0.1"])), "203.0.113.9")
        for claim in ("192.0.2.1", "192.0.2.2", "192.0.2.3"):
            self.assertEqual(_peer_ip(_scope("10.0.0.5", f"{claim}, 203.0.113.9", ["10.0.0.0/24"])), "203.0.113.9")

    def test_anybody_else_is_not(self):
        self.assertEqual(_peer_ip(_scope("198.51.100.7", "203.0.113.9", ["10.0.0.0/24"])), "198.51.100.7")
        self.assertEqual(_peer_ip(_scope("10.0.0.5", "203.0.113.9", [])), "10.0.0.5")

    def test_without_the_header_the_peer_is_the_client(self):
        self.assertEqual(_peer_ip(_scope("10.0.0.5", None, ["10.0.0.0/24"])), "10.0.0.5")
        self.assertEqual(_peer_ip(_scope("10.0.0.5", " ", ["10.0.0.0/24"])), "10.0.0.5")

    def test_an_app_object_from_before_the_matcher(self):
        # the list alone is enough
        self.assertEqual(_peer_ip(_scope("10.0.0.5", "203.0.113.9", ["10.0.0.0/24"], prepared=False)), "203.0.113.9")

    def test_the_same_answer_as_the_mcp_endpoint(self):
        import asyncio
        from zabbix_mcp.server import _make_request_context_middleware
        from zabbix_mcp.token_store import current_client_ip
        for peer, trusted in (("10.0.0.5", ["10.0.0.0/24"]), ("0:0:0:0:0:0:0:1", ["::1"]),
                              ("198.51.100.7", ["10.0.0.0/24"]), ("10.0.0.5", [])):
            seen = {}

            async def inner(scope, receive, send):
                seen["ip"] = current_client_ip.get()

            scope = _scope(peer, "203.0.113.9", trusted)
            asyncio.run(_make_request_context_middleware(inner, trusted)(scope, None, None))
            self.assertEqual(_peer_ip(scope), seen["ip"], (peer, trusted))



class TestThePortalApp(unittest.TestCase):
    """The portal as it is served: its outermost layer and what the login makes of a request."""

    _CONFIG = """
[server]
transport = "http"
host = "127.0.0.1"
port = 8080
{proxies}

[zabbix.main]
url = "https://zabbix.example.com"
api_token = "dummy"

[admin.users.tester]
password_hash = "scrypt:131072:8:1$00000000000000000000000000000000$0000000000000000000000000000000000000000000000000000000000000000"
role = "admin"
"""

    def _admin(self, trusted: list[str]):
        import json
        import tempfile
        from unittest.mock import MagicMock
        from zabbix_mcp.admin.app import AdminApp
        from zabbix_mcp.config import load_config
        from zabbix_mcp.token_store import TokenStore
        tmp = tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False)
        tmp.write(self._CONFIG.format(proxies=f"trusted_proxies = {json.dumps(trusted)}" if trusted else ""))
        tmp.close()
        self.addCleanup(Path(tmp.name).unlink)
        return AdminApp(config=load_config(tmp.name), config_path=tmp.name, client_manager=MagicMock(),
                        token_store=TokenStore(), oauth_provider=None)

    @staticmethod
    def _failed_login(admin, peer: str, forwarded: str | None, proto: str | None = None) -> dict:
        import asyncio
        from unittest.mock import patch
        body = b"username=nobody&password=wrong"
        headers = [(b"host", b"portal.test"), (b"content-type", b"application/x-www-form-urlencoded"),
                   (b"content-length", str(len(body)).encode())]
        if forwarded is not None:
            headers.append((b"x-forwarded-for", forwarded.encode()))
        if proto is not None:
            headers.append((b"x-forwarded-proto", proto.encode()))
        scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "POST",
                 "scheme": "http", "path": "/login", "raw_path": b"/login", "query_string": b"", "root_path": "",
                 "headers": headers, "client": (peer, 40000), "server": ("127.0.0.1", 9090)}
        out = {"audit": []}

        async def receive():
            return {"type": "http.request", "body": body, "more_body": False}

        async def send(message):
            if message["type"] == "http.response.start":
                out["status"] = message["status"]

        with patch("zabbix_mcp.admin.app.write_audit", side_effect=lambda *a, **k: out["audit"].append(k.get("ip"))):
            asyncio.run(admin.app(scope, receive, send))
        out["counted_for"] = set(admin.rate_limiter._attempts)
        return out

    def test_the_outermost_layer_is_the_one_that_resolves_the_proxy(self):
        from zabbix_mcp.admin.app import _ForwardedMiddleware
        admin = self._admin(["10.0.0.5"])
        self.assertIsInstance(admin.app, _ForwardedMiddleware)
        self.assertIs(admin.app.state.admin_app, admin)

    def test_a_failed_login_is_counted_for_the_client_the_proxy_reports(self):
        admin = self._admin(["10.0.0.5"])
        seen = self._failed_login(admin, "10.0.0.5", "192.0.2.1, 203.0.113.9")
        self.assertEqual(seen["counted_for"], {"203.0.113.9"})
        self.assertEqual(seen["audit"], ["203.0.113.9"])
        # whatever the caller claims in front, it stays one client
        for claim in ("192.0.2.2", "192.0.2.3"):
            self._failed_login(admin, "10.0.0.5", f"{claim}, 203.0.113.9")
        self.assertEqual(set(admin.rate_limiter._attempts), {"203.0.113.9"})
        self.assertEqual(len(admin.rate_limiter._attempts["203.0.113.9"]), 3)

    def test_a_proxy_that_is_not_listed_is_not_believed_loopback_included(self):
        # until v1.41 uvicorn believed a loopback peer on its own: a new claimed
        # address for every attempt was a new counter
        admin = self._admin([])
        for claim in ("192.0.2.1", "192.0.2.2", "192.0.2.3"):
            seen = self._failed_login(admin, "127.0.0.1", claim)
        self.assertEqual(seen["counted_for"], {"127.0.0.1"})
        self.assertEqual(len(admin.rate_limiter._attempts["127.0.0.1"]), 3)

    def test_the_scheme_a_listed_proxy_reports_reaches_the_request(self):
        # what the Secure flag of the session cookie goes by (request.url.scheme)
        from zabbix_mcp.admin.app import _ForwardedMiddleware
        from zabbix_mcp.config import trusted_proxy_matcher
        seen = {}

        async def inner(scope, receive, send):
            seen.update(scheme=scope["scheme"], client=scope["client"])

        inner.state = None
        import asyncio
        for trusted, want in ((["127.0.0.1"], ("https", ("203.0.113.9", 0))), ([], ("http", ("127.0.0.1", 40000)))):
            app = _ForwardedMiddleware(inner, trusted_proxy_matcher(trusted, warn=False))
            scope = {"type": "http", "scheme": "http", "client": ("127.0.0.1", 40000),
                     "headers": [(b"x-forwarded-for", b"203.0.113.9"), (b"x-forwarded-proto", b"https")]}
            asyncio.run(app(scope, None, None))
            self.assertEqual((seen["scheme"], seen["client"]), want, trusted)


if __name__ == "__main__":
    unittest.main()
