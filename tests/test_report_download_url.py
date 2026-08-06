#
# Zabbix MCP Server
# Copyright (C) 2026 initMAX s.r.o.
# Licensed under the GNU Affero General Public License v3.
# See LICENSE for details.
#

"""Report download URLs must never be a dead link.

The model hands the URL straight to a human, so a wrong one is worse
than none: it 404s, and it sends a live report id - the credential -
to whatever answers at that address. A link is therefore only built
from an address somebody explicitly vouched for: [server].public_url,
or X-Forwarded-Host from a peer in trusted_proxies. Never the local
bind, and never a bare Host header - the SDK pins that to loopback
whenever no host allowlist is configured, which is precisely the
proxied deployment where a link matters.
"""

from __future__ import annotations

import unittest

from zabbix_mcp.config import AppConfig, ServerConfig
from zabbix_mcp.server import _forwarded_base_from_headers, _report_download_base
from zabbix_mcp.token_store import current_request_base


def _hdrs(**kw):
    return {k.replace("_", "-").encode(): v.encode() for k, v in kw.items()}


class TestForwardedBase(unittest.TestCase):
    """What a trusted proxy declares the public address to be."""

    def test_host_and_proto(self):
        self.assertEqual(
            _forwarded_base_from_headers(
                _hdrs(x_forwarded_host="mcp.example.com", x_forwarded_proto="https")),
            "https://mcp.example.com")

    def test_plain_http_is_fine(self):
        self.assertEqual(
            _forwarded_base_from_headers(
                _hdrs(x_forwarded_host="mcp.lan:8080", x_forwarded_proto="http")),
            "http://mcp.lan:8080")

    def test_last_element_of_a_chain_wins(self):
        # A proxy that appends leaves the client's own value in front, so
        # the nearest hop is the one this server can vouch for. This is
        # the opposite end from X-Forwarded-For, on purpose.
        self.assertEqual(
            _forwarded_base_from_headers(
                _hdrs(x_forwarded_host="attacker.tld, real.example.com",
                      x_forwarded_proto="https, https")),
            "https://real.example.com")

    def test_bare_host_header_is_never_used(self):
        # The SDK pins Host to loopback with no allowlist configured, so
        # trusting it reintroduces the 127.0.0.1 link this guards against.
        self.assertIsNone(_forwarded_base_from_headers(_hdrs(host="mcp.example.com")))

    def test_proto_is_required(self):
        self.assertIsNone(_forwarded_base_from_headers(_hdrs(x_forwarded_host="mcp.example.com")))

    def test_ipv6_literal(self):
        self.assertEqual(
            _forwarded_base_from_headers(
                _hdrs(x_forwarded_host="[fd00::1]:8080", x_forwarded_proto="http")),
            "http://[fd00::1]:8080")

    def test_garbage_hosts_are_refused(self):
        for bad in ("mcp.example.com/evil", "mcp.example.com?x=1", "http://elsewhere",
                    "mcp.example.com\r\nX-Evil: 1", "mcp example.com", "", "@evil.com"):
            self.assertIsNone(
                _forwarded_base_from_headers(
                    _hdrs(x_forwarded_host=bad, x_forwarded_proto="https")), repr(bad))


class TestDownloadBase(unittest.TestCase):
    """Whether a link may be offered at all."""

    def setUp(self):
        current_request_base.set(None)

    def tearDown(self):
        current_request_base.set(None)

    def _cfg(self, **kw):
        return AppConfig(server=ServerConfig(**kw))

    def test_public_url_wins(self):
        current_request_base.set("http://127.0.0.1:8080")
        url, reason = _report_download_base(
            self._cfg(public_url="https://mcp.example.com"), "http")
        self.assertEqual(url, "https://mcp.example.com")
        self.assertIsNone(reason)

    def test_public_url_trailing_slash_trimmed(self):
        url, _ = _report_download_base(self._cfg(public_url="https://mcp.example.com/"), "http")
        self.assertEqual(url, "https://mcp.example.com")

    def test_falls_back_to_what_a_trusted_proxy_declared(self):
        current_request_base.set("https://mcp.example.com")
        url, reason = _report_download_base(self._cfg(), "http")
        self.assertEqual(url, "https://mcp.example.com")
        self.assertIsNone(reason)

    def test_nothing_vouched_for_means_no_link(self):
        # The regression this test exists for: with the shipped default
        # (bind 127.0.0.1, no public_url, proxy in front) an inferred
        # link sent a remote user to their OWN machine, handing a live
        # report id to whatever answers there. Both the bind and the bare
        # Host resolve to loopback in that shape, so neither may be used.
        url, reason = _report_download_base(self._cfg(host="127.0.0.1", port=8080), "http")
        self.assertIsNone(url)
        self.assertIn("public_url", reason)

    def test_stdio_has_no_listener(self):
        current_request_base.set("http://127.0.0.1:8080")
        url, reason = _report_download_base(self._cfg(), "stdio")
        self.assertIsNone(url)
        self.assertIn("stdio", reason)


if __name__ == "__main__":
    unittest.main()
