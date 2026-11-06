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

"""Whose address is the client's behind a reverse proxy.

Until v1.41 it was the first entry of ``X-Forwarded-For``. A proxy that
appends to the header (nginx with ``$proxy_add_x_forwarded_for``) leaves
what the client sent in front, so the first entry is the client's own claim:
a token limited to ``allowed_ips`` could be used from anywhere by naming an
allowed address, and the login throttle could be passed by naming a new one
for every attempt. The address is now the one the nearest trusted proxy
wrote, and a token limited to addresses is refused when the address is
unknown or is not one.

That was the path of a proxy on another host (a container, a load balancer).
A proxy on the server's own host never reached it: uvicorn's own proxy
handling believes every loopback peer, whether ``trusted_proxies`` lists it
or not, and had replaced the peer before the middleware ran. Right for a
proxy that writes the header, and an open door behind one that passes the
client's header through. uvicorn is now started without that handling, and
``config.resolve_forwarded`` is the one place that says who the client is.
"""

import asyncio
import hashlib
import secrets
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from zabbix_mcp.config import forwarded_client, trusted_proxy_matcher  # noqa: E402
from zabbix_mcp.server import _make_request_context_middleware  # noqa: E402
from zabbix_mcp.token_store import TokenStore, current_client_ip, current_request_base  # noqa: E402

LOCAL = trusted_proxy_matcher(["127.0.0.1"], warn=False)
CHAIN = trusted_proxy_matcher(["127.0.0.1", "10.0.0.0/24", "2001:db8:1::/48"], warn=False)


def _seen_by_the_server(forwarded: str | None, *, peer: str = "127.0.0.1", trusted=("127.0.0.1",)) -> str | None:
    """The client address a request ends up with, through the real middleware."""
    seen = {}

    async def inner(scope, receive, send):
        seen["ip"] = current_client_ip.get()

    headers = [(b"x-forwarded-for", forwarded.encode())] if forwarded is not None else []
    scope = {"type": "http", "client": (peer, 40000), "scheme": "http", "headers": headers}
    asyncio.run(_make_request_context_middleware(inner, list(trusted))(scope, None, None))
    return seen["ip"]


class TestWhichEntry(unittest.TestCase):
    def test_a_proxy_that_sets_the_header(self):
        self.assertEqual(forwarded_client("203.0.113.9", LOCAL), "203.0.113.9")

    def test_a_proxy_that_appends_to_what_the_client_sent(self):
        self.assertEqual(forwarded_client("10.1.1.7, 203.0.113.9", LOCAL), "203.0.113.9")
        self.assertEqual(forwarded_client("a, b, 10.1.1.7,203.0.113.9", LOCAL), "203.0.113.9")

    def test_a_chain_of_our_own_proxies(self):
        self.assertEqual(forwarded_client("203.0.113.9, 10.0.0.5", CHAIN), "203.0.113.9")
        self.assertEqual(forwarded_client("192.0.2.1, 203.0.113.9, 10.0.0.5, 10.0.0.6", CHAIN), "203.0.113.9")
        self.assertEqual(forwarded_client("203.0.113.9, 2001:db8:1::5", CHAIN), "203.0.113.9")

    def test_a_port_is_not_part_of_the_address(self):
        self.assertEqual(forwarded_client("203.0.113.9:51234", LOCAL), "203.0.113.9")
        self.assertEqual(forwarded_client("[2001:db8:9::1]:443", LOCAL), "2001:db8:9::1")
        self.assertEqual(forwarded_client("2001:db8:9::1", LOCAL), "2001:db8:9::1")
        self.assertEqual(forwarded_client("203.0.113.9, 10.0.0.5:8443", CHAIN), "203.0.113.9")

    def test_nothing_but_proxies(self):
        # the client was one of them: the left-most, as uvicorn's own handling had it
        self.assertEqual(forwarded_client("127.0.0.1", CHAIN), "127.0.0.1")
        self.assertEqual(forwarded_client("10.0.0.5, 127.0.0.1", CHAIN), "10.0.0.5")

    def test_nothing(self):
        for header in ("", " ", ",", " , "):
            self.assertIsNone(forwarded_client(header, CHAIN), header)


class TestThroughTheServer(unittest.TestCase):
    def test_the_address_the_proxy_wrote(self):
        self.assertEqual(_seen_by_the_server("203.0.113.9"), "203.0.113.9")
        self.assertEqual(_seen_by_the_server("10.1.1.7, 203.0.113.9"), "203.0.113.9")

    def test_without_a_usable_header_the_peer(self):
        self.assertEqual(_seen_by_the_server(None), "127.0.0.1")
        self.assertEqual(_seen_by_the_server("127.0.0.1"), "127.0.0.1")

    def test_a_peer_that_is_no_trusted_proxy_is_not_asked(self):
        self.assertEqual(_seen_by_the_server("10.1.1.7", peer="198.51.100.4"), "198.51.100.4")
        self.assertEqual(_seen_by_the_server("10.1.1.7", peer="198.51.100.4", trusted=()), "198.51.100.4")

    def test_a_new_claim_for_every_attempt_is_one_client(self):
        # what the login throttles count by
        keys = {_seen_by_the_server(f"192.0.2.{n}, 203.0.113.9") for n in range(1, 60)}
        self.assertEqual(keys, {"203.0.113.9"})


def _through(trusted, *, peer="127.0.0.1", scheme="http", kind="http", inner_layers=lambda app: app, **headers):
    """One request through the outermost layer of the MCP endpoint; what the inside saw."""
    seen = {}

    async def inner(scope, receive, send):
        seen.update(passed=True, ip=current_client_ip.get(), base=current_request_base.get(),
                    client=scope.get("client"), scheme=scope.get("scheme"))

    async def send(message):
        if message["type"] == "http.response.start":
            seen["status"] = message["status"]

    pairs = []
    for name, value in headers.items():
        for line in (value if isinstance(value, list) else [value]):
            pairs.append((name.replace("_", "-").encode(), line.encode()))
    scope = {"type": kind, "client": (peer, 40000), "scheme": scheme, "headers": pairs}
    asyncio.run(_make_request_context_middleware(inner_layers(inner), list(trusted))(scope, None, send))
    seen["scope_untouched"] = scope["client"] == (peer, 40000) and scope["scheme"] == scheme
    return seen


class TestTheServerDecidesAlone(unittest.TestCase):
    """uvicorn runs without its own proxy handling, which believed every loopback peer."""

    def test_both_servers_start_uvicorn_without_it(self):
        import inspect
        import uvicorn
        from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware
        from zabbix_mcp import server

        async def app(scope, receive, send):
            pass

        # what uvicorn does with the settings both servers are started with ...
        config = uvicorn.Config(app, **server._UVICORN_PROXY_SETTINGS)
        config.load()
        self.assertNotIsInstance(config.loaded_app, ProxyHeadersMiddleware)
        # ... and with its own defaults, which is what they were started with before
        default = uvicorn.Config(app)
        default.load()
        self.assertIsInstance(default.loaded_app, ProxyHeadersMiddleware)
        # both listeners get those settings: the portal through uvicorn.run, the MCP
        # endpoint through _serve, which hands them to uvicorn as they are
        source = inspect.getsource(server.run_server)
        self.assertEqual(source.count("**_UVICORN_PROXY_SETTINGS"), 2)
        self.assertEqual(source.count("uvicorn.run("), 1)
        self.assertEqual(source.count("_serve(asgi_app, uvicorn_kwargs, "), 1)
        self.assertIn("uvicorn.Config(asgi_app, **uvicorn_kwargs)", inspect.getsource(server._serve))

    def test_a_proxy_that_is_not_listed_is_not_believed(self):
        # v1.41 and before: a local relay that passed the client's header through
        # let the client choose its address, with or without trusted_proxies
        for peer in ("10.0.0.5", "198.51.100.4"):
            seen = _through([], peer=peer, x_forwarded_for="10.1.1.7", x_forwarded_proto="https",
                            x_forwarded_host="mcp.example.com")
            self.assertEqual(seen["ip"], peer, peer)
            self.assertEqual(seen["client"], (peer, 40000), peer)
            self.assertEqual(seen["scheme"], "http", peer)
            self.assertIsNone(seen["base"], peer)

    def test_a_local_proxy_that_is_not_listed_leaves_the_client_unknown(self):
        # It forwards somebody, and nobody vouched for whom. Taking it for a local
        # client would open every allowlist that contains 127.0.0.1 (uvicorn used
        # to resolve such a proxy, so this is what an upgrade without the config
        # line looks like): the address is unknown and the allowlists refuse.
        for peer in ("127.0.0.1", "::1", "127.0.0.9", "::ffff:127.0.0.1"):
            seen = _through([], peer=peer, x_forwarded_for="10.1.1.7", x_forwarded_proto="https",
                            x_forwarded_host="mcp.example.com")
            self.assertIsNone(seen["ip"], peer)
            self.assertEqual(seen["client"], (peer, 40000), peer)
            self.assertEqual(seen["scheme"], "http", peer)
            self.assertIsNone(seen["base"], peer)
        # a local client that forwards nobody is a local client
        self.assertEqual(_through([], peer="127.0.0.1")["ip"], "127.0.0.1")
        self.assertEqual(_through([], peer="127.0.0.1", x_forwarded_proto="https")["ip"], "127.0.0.1")

    def test_localhost_as_an_entry_means_loopback(self):
        # the peer is always an address; the name worked until v1.41 only because uvicorn believed loopback anyway
        for peer in ("127.0.0.1", "::1"):
            self.assertEqual(_through(["localhost"], peer=peer, x_forwarded_for="203.0.113.9")["ip"], "203.0.113.9", peer)
        self.assertEqual(_through(["LocalHost"], peer="10.0.0.5", x_forwarded_for="203.0.113.9")["ip"], "10.0.0.5")

    def test_a_listed_proxy_on_the_same_host(self):
        seen = _through(["127.0.0.1"], x_forwarded_for="10.1.1.7, 203.0.113.9", x_forwarded_proto="https",
                        x_forwarded_host="mcp.example.com")
        self.assertEqual(seen["ip"], "203.0.113.9")
        # the scope itself, so that everything further in agrees
        self.assertEqual(seen["client"], ("203.0.113.9", 0))
        self.assertEqual(seen["scheme"], "https")
        # and the link address, which a same-host proxy could never give before
        self.assertEqual(seen["base"], "https://mcp.example.com")
        # the caller's scope is not written to
        self.assertTrue(seen["scope_untouched"])

    def test_a_listed_proxy_on_another_host(self):
        seen = _through(["10.0.0.0/24"], peer="10.0.0.5", x_forwarded_for="10.1.1.7, 203.0.113.9",
                        x_forwarded_proto="https", x_forwarded_host="mcp.example.com")
        self.assertEqual((seen["ip"], seen["client"], seen["scheme"], seen["base"]),
                         ("203.0.113.9", ("203.0.113.9", 0), "https", "https://mcp.example.com"))

    def test_a_load_balancer_in_front_of_the_proxy(self):
        header = "192.0.2.1, 203.0.113.9, 10.0.0.9"
        self.assertEqual(_through(["127.0.0.1", "10.0.0.9"], x_forwarded_for=header)["ip"], "203.0.113.9")
        # not listed, the balancer is the client
        self.assertEqual(_through(["127.0.0.1"], x_forwarded_for=header)["ip"], "10.0.0.9")

    def test_several_header_lines_are_one_list(self):
        seen = _through(["127.0.0.1"], x_forwarded_for=["10.1.1.7", "203.0.113.9"])
        self.assertEqual(seen["ip"], "203.0.113.9")

    def test_the_scheme_is_the_nearest_hop_s_and_only_http_or_https(self):
        self.assertEqual(_through(["127.0.0.1"], x_forwarded_for="203.0.113.9", x_forwarded_proto="http, https")["scheme"], "https")
        self.assertEqual(_through(["127.0.0.1"], scheme="https", x_forwarded_for="203.0.113.9", x_forwarded_proto="HTTP")["scheme"], "http")
        for value in ("ftp", "javascript", "", "https://evil"):
            self.assertEqual(_through(["127.0.0.1"], x_forwarded_for="203.0.113.9", x_forwarded_proto=value)["scheme"], "http", value)
        self.assertEqual(_through(["127.0.0.1"], kind="websocket", scheme="ws", x_forwarded_for="203.0.113.9",
                                  x_forwarded_proto="https")["scheme"], "wss")

    def test_a_trusted_proxy_without_the_header_is_the_client(self):
        seen = _through(["127.0.0.1"])
        self.assertEqual((seen["ip"], seen["client"]), ("127.0.0.1", ("127.0.0.1", 40000)))

    def test_allowed_hosts_goes_by_the_same_address(self):
        from zabbix_mcp.server import _IPAllowlistMiddleware

        def with_list(app):
            return _IPAllowlistMiddleware(app, ["10.1.1.0/24"])

        # a client inside the list, through the listed proxy
        self.assertTrue(_through(["127.0.0.1"], inner_layers=with_list, x_forwarded_for="10.1.1.7").get("passed"))
        # a stranger naming an allowed address: the proxy's own entry counts
        seen = _through(["127.0.0.1"], inner_layers=with_list, x_forwarded_for="10.1.1.7, 198.51.100.4")
        self.assertEqual((seen.get("passed"), seen.get("status")), (None, 403))
        # the same through a proxy nobody listed: before, this was let in
        seen = _through([], inner_layers=with_list, x_forwarded_for="10.1.1.7")
        self.assertEqual((seen.get("passed"), seen.get("status")), (None, 403))
        # and garbage is refused, not an error
        seen = _through(["127.0.0.1"], inner_layers=with_list, x_forwarded_for="garbage")
        self.assertEqual((seen.get("passed"), seen.get("status")), (None, 403))


class TestAnUpgradeDoesNotOpenAnAllowlist(unittest.TestCase):
    """The layers as ``run_server`` puts them together, for the configurations an upgrade meets."""

    @staticmethod
    def _request(allowed_hosts, trusted, *, peer="127.0.0.1", forwarded=None):
        from types import SimpleNamespace
        from zabbix_mcp.server import _wrap_http_app
        seen = {}

        async def inner(scope, receive, send):
            seen.update(passed=True, ip=current_client_ip.get())

        async def send(message):
            if message["type"] == "http.response.start":
                seen["status"] = message["status"]

        app = _wrap_http_app(inner, SimpleNamespace(allowed_hosts=allowed_hosts, cors_origins=None, trusted_proxies=trusted))
        headers = [(b"x-forwarded-for", forwarded.encode())] if forwarded is not None else []
        asyncio.run(app({"type": "http", "client": (peer, 40000), "scheme": "http", "headers": headers}, None, send))
        return seen

    def test_a_list_with_loopback_behind_a_local_proxy_that_is_not_listed(self):
        # v1.41: uvicorn resolved the proxy, the stranger was 198.51.100.4 and got a 403.
        # Seen as 127.0.0.1 it would pass this list.
        allowed = ["127.0.0.1", "10.0.0.0/24"]
        seen = self._request(allowed, None, forwarded="198.51.100.4")
        self.assertEqual((seen.get("passed"), seen.get("status")), (None, 403))
        seen = self._request(allowed, [], forwarded="10.0.0.7, 198.51.100.4")
        self.assertEqual((seen.get("passed"), seen.get("status")), (None, 403))
        # once the proxy is listed the list works as it did
        self.assertTrue(self._request(allowed, ["127.0.0.1"], forwarded="10.0.0.7").get("passed"))
        seen = self._request(allowed, ["127.0.0.1"], forwarded="198.51.100.4")
        self.assertEqual((seen.get("passed"), seen.get("status")), (None, 403))
        # and a local client that forwards nobody is still let in
        self.assertTrue(self._request(allowed, None).get("passed"))

    def test_a_token_limited_to_addresses_is_refused_for_an_unknown_client(self):
        import hashlib
        import secrets
        raw = "zmcp_" + secrets.token_hex(24)
        store = TokenStore()
        store.load_from_config({"limited": {"name": "limited", "allowed_ips": ["127.0.0.1", "10.1.1.0/24"],
                                            "token_hash": "sha256:" + hashlib.sha256(raw.encode()).hexdigest()}})
        # behind the local proxy that is not listed
        seen = self._request(None, None, forwarded="198.51.100.4")
        self.assertTrue(seen.get("passed"))
        self.assertIsNone(seen["ip"])
        self.assertIsNone(store.verify(raw, client_ip=seen["ip"]))
        # a local client, and a client behind the listed proxy
        self.assertIsNotNone(store.verify(raw, client_ip=self._request(None, None)["ip"]))
        self.assertIsNotNone(store.verify(raw, client_ip=self._request(None, ["127.0.0.1"], forwarded="10.1.1.7")["ip"]))
        self.assertIsNone(store.verify(raw, client_ip=self._request(None, ["127.0.0.1"], forwarded="198.51.100.4")["ip"]))

    def test_a_proxy_on_another_host_that_is_in_the_list_itself(self):
        # "only my proxy may connect": what such a list did before the client could be named
        seen = self._request(["10.0.0.5"], ["10.0.0.5"], peer="10.0.0.5", forwarded="198.51.100.4")
        self.assertTrue(seen.get("passed"))
        self.assertEqual(seen["ip"], "198.51.100.4")
        # the list can now name the clients instead
        self.assertTrue(self._request(["10.1.1.0/24"], ["10.0.0.5"], peer="10.0.0.5", forwarded="10.1.1.7").get("passed"))
        seen = self._request(["10.1.1.0/24"], ["10.0.0.5"], peer="10.0.0.5", forwarded="198.51.100.4")
        self.assertEqual((seen.get("passed"), seen.get("status")), (None, 403))
        # a local proxy in the list does not open it: 127.0.0.1 is there for local clients
        seen = self._request(["127.0.0.1"], ["127.0.0.1"], forwarded="198.51.100.4")
        self.assertEqual((seen.get("passed"), seen.get("status")), (None, 403))

    def test_the_order_of_the_layers(self):
        # the allowlist has to see the address the outermost layer resolved
        seen = self._request(["10.1.1.0/24"], ["127.0.0.1"], forwarded="10.1.1.7")
        self.assertTrue(seen.get("passed"))
        self.assertEqual(seen["ip"], "10.1.1.7")


class TestTheOperatorIsTold(unittest.TestCase):
    """After an upgrade a proxy on the same host has to be listed; the log says so, once."""

    def test_headers_from_a_local_peer_that_is_not_listed(self):
        from zabbix_mcp.config import ignored_forwarded_warner
        note = ignored_forwarded_warner(trusted_proxy_matcher([], warn=False))
        scope = {"type": "http", "client": ("127.0.0.1", 40000), "headers": [(b"x-forwarded-for", b"203.0.113.9")]}
        with self.assertLogs("zabbix_mcp.config", level="WARNING") as logs:
            note(scope)
            note(scope)
            note(dict(scope, client=("10.0.0.5", 1)))
        self.assertEqual(len(logs.output), 2)
        self.assertIn("127.0.0.1 are ignored: it is not listed in [server].trusted_proxies", logs.output[0])
        self.assertIn("10.0.0.5", logs.output[1])

    def test_nothing_is_said_when_there_is_nothing_to_say(self):
        from zabbix_mcp.config import ignored_forwarded_warner
        note = ignored_forwarded_warner(trusted_proxy_matcher(["127.0.0.1"], warn=False))
        with self.assertNoLogs("zabbix_mcp.config", level="WARNING"):
            # a listed proxy; a local peer without the headers; a client on the internet with them
            note({"type": "http", "client": ("127.0.0.1", 1), "headers": [(b"x-forwarded-for", b"203.0.113.9")]})
            note({"type": "http", "client": ("10.0.0.5", 1), "headers": [(b"accept", b"*/*")]})
            # (a globally routable address: Python counts the documentation ranges as private)
            note({"type": "http", "client": ("93.184.216.34", 1), "headers": [(b"x-forwarded-for", b"10.1.1.7")]})
            note({"type": "lifespan"})

    def test_it_does_not_fill_the_log(self):
        from zabbix_mcp.config import ignored_forwarded_warner
        note = ignored_forwarded_warner(trusted_proxy_matcher([], warn=False), limit=3)
        with self.assertLogs("zabbix_mcp.config", level="WARNING") as logs:
            for n in range(1, 40):
                note({"type": "http", "client": (f"10.0.0.{n}", 1), "headers": [(b"x-forwarded-for", b"203.0.113.9")]})
        self.assertEqual(len(logs.output), 3)


class TestAllowedHosts(unittest.TestCase):
    """``[server].allowed_hosts`` goes by the address the HTTP server reports."""

    @staticmethod
    def _status(client) -> int | str:
        from zabbix_mcp.server import _IPAllowlistMiddleware
        sent = []

        async def inner(scope, receive, send):
            sent.append("passed")

        async def send(message):
            if message["type"] == "http.response.start":
                sent.append(message["status"])

        app = _IPAllowlistMiddleware(inner, ["10.1.1.0/24"])
        asyncio.run(app({"type": "http", "client": client, "headers": []}, None, send))
        return sent[0]

    def test_inside_and_outside_the_list(self):
        self.assertEqual(self._status(("10.1.1.7", 40000)), "passed")
        self.assertEqual(self._status(("198.51.100.4", 40000)), 403)

    def test_an_address_that_is_none_is_refused_not_an_error(self):
        # what a forwarded header of garbage turns the peer into; it used to raise (HTTP 500)
        for address in ("garbage", "", "10.1.1.7.evil", "unknown"):
            self.assertEqual(self._status((address, 0)), 403, repr(address))


class TestTheTokenAllowlist(unittest.TestCase):
    def setUp(self):
        self.raw = "zmcp_" + secrets.token_hex(24)
        digest = "sha256:" + hashlib.sha256(self.raw.encode()).hexdigest()
        self.store = TokenStore()
        self.store.load_from_config({
            "limited": {"name": "limited", "token_hash": digest, "allowed_ips": ["10.1.1.0/24"]},
        })
        self.free_raw = "zmcp_" + secrets.token_hex(24)
        self.free = TokenStore()
        self.free.load_from_config({
            "free": {"name": "free", "token_hash": "sha256:" + hashlib.sha256(self.free_raw.encode()).hexdigest()},
        })

    def test_naming_an_allowed_address_does_not_let_a_stranger_in(self):
        # a client at 198.51.100.4 sends "X-Forwarded-For: 10.1.1.7"; nginx appends its address
        client = _seen_by_the_server("10.1.1.7, 198.51.100.4")
        self.assertEqual(client, "198.51.100.4")
        self.assertIsNone(self.store.verify(self.raw, client_ip=client))

    def test_a_client_inside_the_allowlist_is_let_in(self):
        client = _seen_by_the_server("10.1.1.7")
        self.assertIsNotNone(self.store.verify(self.raw, client_ip=client))
        # whatever it claims on top
        client = _seen_by_the_server("198.51.100.4, 10.1.1.7")
        self.assertIsNotNone(self.store.verify(self.raw, client_ip=client))

    def test_an_address_that_is_none_is_refused(self):
        for client in (None, "", "x", "unknown", "10.1.1.7.evil", "10.1.1.7 ", "10.1.1.7, 10.1.1.8"):
            self.assertIsNone(self.store.verify(self.raw, client_ip=client), repr(client))
        # what a header of garbage ends up as
        self.assertIsNone(self.store.verify(self.raw, client_ip=_seen_by_the_server("10.1.1.7, x")))

    def test_a_token_without_a_list_does_not_care(self):
        for client in (None, "x", "198.51.100.4"):
            self.assertIsNotNone(self.free.verify(self.free_raw, client_ip=client), repr(client))


if __name__ == "__main__":
    unittest.main()
