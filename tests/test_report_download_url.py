#
# Zabbix MCP Server
# Copyright (C) 2026 initMAX s.r.o.
# Licensed under the GNU Affero General Public License v3.
# See LICENSE for details.
#

"""Report download URLs must never be a dead link.

The model hands the URL straight to a human, so a wrong one is worse
than none: it 404s, and it sends a live report id to whatever answers
at that address. The address the caller itself dialled is the only one
this server knows the caller can reach, so that - not the local bind -
is what the link is built from.
"""

from __future__ import annotations

import unittest

from zabbix_mcp.config import AppConfig, ServerConfig
from zabbix_mcp.server import _report_download_base, _request_base_from_headers
from zabbix_mcp.token_store import current_request_base


def _hdrs(**kw):
    return {k.replace("_", "-").encode(): v.encode() for k, v in kw.items()}


class TestRequestBaseFromHeaders(unittest.TestCase):
    """What the caller dialled, as read off the wire."""

    def test_plain_host(self):
        self.assertEqual(
            _request_base_from_headers(_hdrs(host="mcp.example.com"), "http", False),
            "http://mcp.example.com")

    def test_host_with_port_is_kept(self):
        self.assertEqual(
            _request_base_from_headers(_hdrs(host="mcp.example.com:8080"), "http", False),
            "http://mcp.example.com:8080")

    def test_forwarded_headers_ignored_from_untrusted_peer(self):
        # Any client can send these; only a configured proxy is believed.
        h = _hdrs(host="127.0.0.1:8080", x_forwarded_host="evil.example.com",
                  x_forwarded_proto="https")
        self.assertEqual(_request_base_from_headers(h, "http", False), "http://127.0.0.1:8080")

    def test_forwarded_headers_honoured_from_trusted_proxy(self):
        # The production shape: TLS terminates upstream, so the scheme
        # can only come from the proxy.
        h = _hdrs(host="127.0.0.1:8080", x_forwarded_host="mcp.example.com",
                  x_forwarded_proto="https")
        self.assertEqual(_request_base_from_headers(h, "http", True), "https://mcp.example.com")

    def test_first_entry_of_a_forwarded_chain_wins(self):
        h = _hdrs(x_forwarded_host="mcp.example.com, inner.lan", x_forwarded_proto="https, http")
        self.assertEqual(_request_base_from_headers(h, "http", True), "https://mcp.example.com")

    def test_ipv6_literal_host(self):
        self.assertEqual(
            _request_base_from_headers(_hdrs(host="[fd00::1]:8080"), "http", False),
            "http://[fd00::1]:8080")

    def test_garbage_hosts_are_refused(self):
        # A Host that is not a bare authority could smuggle a path, a
        # query or a second origin into the link handed to the user.
        for bad in ("mcp.example.com/evil", "mcp.example.com?x=1", "http://elsewhere",
                    "mcp.example.com\r\nX-Evil: 1", "mcp example.com", "", "@evil.com"):
            self.assertIsNone(
                _request_base_from_headers(_hdrs(host=bad), "http", False), repr(bad))

    def test_missing_host_header(self):
        self.assertIsNone(_request_base_from_headers({}, "http", False))


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

    def test_falls_back_to_the_address_the_caller_dialled(self):
        current_request_base.set("https://mcp.example.com")
        url, reason = _report_download_base(self._cfg(), "http")
        self.assertEqual(url, "https://mcp.example.com")
        self.assertIsNone(reason)

    def test_local_bind_is_never_advertised_on_its_own(self):
        # The regression this test exists for: with the shipped default
        # (bind 127.0.0.1, no public_url, proxy in front) a bind-derived
        # link sent a remote user to their OWN machine, handing a live
        # report id to whatever answers there.
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
