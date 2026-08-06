#
# Zabbix MCP Server
# Copyright (C) 2026 initMAX s.r.o.
# Licensed under the GNU Affero General Public License v3.
# See LICENSE for details.
#

"""The ASGI middleware that publishes per-request context.

Two things ride on this: the client IP a token's IP allowlist is checked
against, and the public base URL a report download link is built from.
Both must be per-request and must not survive the request - a value that
leaked from one request into the next would check the wrong IP, or put
another tenant's hostname in a link.

Driven through the real middleware object, not a copy of its logic.
"""

from __future__ import annotations

import asyncio
import unittest

from zabbix_mcp.server import _make_request_context_middleware
from zabbix_mcp.token_store import current_client_ip, current_request_base


def _scope(peer="127.0.0.1", **headers):
    return {
        "type": "http",
        "client": (peer, 51234),
        "scheme": "http",
        "headers": [(k.replace("_", "-").encode(), v.encode()) for k, v in headers.items()],
    }


def _observe(scope, trusted_proxies=("127.0.0.1",)):
    """Run one request and report what the inner app saw."""
    seen = {}

    async def inner(scope, receive, send):
        seen["ip"] = current_client_ip.get()
        seen["base"] = current_request_base.get()

    app = _make_request_context_middleware(inner, list(trusted_proxies))
    asyncio.run(app(scope, None, None))
    return seen


class TestForwardedHandling(unittest.TestCase):

    def test_trusted_proxy_declares_the_public_base(self):
        seen = _observe(_scope(x_forwarded_host="mcp.example.com",
                               x_forwarded_proto="https"))
        self.assertEqual(seen["base"], "https://mcp.example.com")

    def test_untrusted_peer_cannot_declare_anything(self):
        seen = _observe(_scope(peer="203.0.113.9",
                               x_forwarded_host="evil.example.com",
                               x_forwarded_proto="https"))
        self.assertIsNone(seen["base"])
        self.assertEqual(seen["ip"], "203.0.113.9")

    def test_client_ip_still_comes_from_the_first_xff_entry(self):
        # Opposite end of the chain from X-Forwarded-Host, deliberately:
        # here the original client is what an IP allowlist wants.
        seen = _observe(_scope(x_forwarded_for="198.51.100.7, 10.0.0.1"))
        self.assertEqual(seen["ip"], "198.51.100.7")

    def test_no_forwarded_headers_means_no_base(self):
        # A bare Host is never enough - see _forwarded_base_from_headers.
        seen = _observe(_scope(host="mcp.example.com"))
        self.assertIsNone(seen["base"])


class TestTrustedProxyMatching(unittest.TestCase):

    def test_cidr_entry_matches_a_peer_inside_it(self):
        seen = _observe(_scope(peer="10.0.0.7", x_forwarded_host="mcp.example.com",
                               x_forwarded_proto="https"),
                        trusted_proxies=["10.0.0.0/24"])
        self.assertEqual(seen["base"], "https://mcp.example.com")

    def test_cidr_entry_does_not_match_outside_it(self):
        seen = _observe(_scope(peer="10.0.1.7", x_forwarded_host="mcp.example.com",
                               x_forwarded_proto="https"),
                        trusted_proxies=["10.0.0.0/24"])
        self.assertIsNone(seen["base"])

    def test_ipv6_matches_regardless_of_spelling(self):
        seen = _observe(_scope(peer="0:0:0:0:0:0:0:1", x_forwarded_host="mcp.example.com",
                               x_forwarded_proto="https"),
                        trusted_proxies=["::1"])
        self.assertEqual(seen["base"], "https://mcp.example.com")


class TestContextIsolation(unittest.TestCase):

    def test_context_does_not_survive_the_request(self):
        _observe(_scope(x_forwarded_host="mcp.example.com", x_forwarded_proto="https"))
        self.assertIsNone(current_request_base.get())
        self.assertIsNone(current_client_ip.get())

    def test_concurrent_requests_do_not_see_each_others_values(self):
        # The failure this guards against: request B's report link
        # carrying request A's hostname.
        seen = []

        async def inner(scope, receive, send):
            # Yield in the middle so the two requests genuinely interleave.
            before = current_request_base.get()
            await asyncio.sleep(0)
            seen.append((before, current_request_base.get()))

        app = _make_request_context_middleware(inner, ["127.0.0.1"])

        async def main():
            await asyncio.gather(
                app(_scope(x_forwarded_host="a.example.com", x_forwarded_proto="https"),
                    None, None),
                app(_scope(x_forwarded_host="b.example.com", x_forwarded_proto="http"),
                    None, None),
            )

        asyncio.run(main())
        for before, after in seen:
            self.assertEqual(before, after)
        self.assertEqual(sorted(b for b, _ in seen),
                         ["http://b.example.com", "https://a.example.com"])


if __name__ == "__main__":
    unittest.main()
