#
# Zabbix MCP Server
# Copyright (C) 2026 initMAX s.r.o.
# Licensed under the GNU Affero General Public License v3.
# See LICENSE for details.
#

"""OAuth tokens carry the zone of the user who consented (issue #75).

``TokenInfo.timezone`` is the top of the zone chain, and a static
``[tokens.X]`` entry gets it from config. An OAuth-issued token (a
claude.ai / ChatGPT connector) has no config row, so the zone is
resolved at consent - the portal user's explicit ``timezone``, else the
zone the browser reported - and rides on the authorization code, the
access token and the refresh token the way the role does since v1.37.3.
"""

from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mcp.server.auth.provider import AuthorizationParams
from mcp.shared.auth import OAuthClientInformationFull
from pydantic import AnyUrl

from zabbix_mcp import oauth_login
from zabbix_mcp.admin.auth import hash_password
from zabbix_mcp.oauth_provider import ZmcpOAuthProvider, _PendingAuthorization, _timezone_or_none
from zabbix_mcp.token_store import TokenInfo, current_token_info


def _provider() -> ZmcpOAuthProvider:
    return ZmcpOAuthProvider(public_url="http://127.0.0.1:1", token_store=None)


def _mint(provider, timezone, role="operator", scopes=("monitoring",)):
    return provider._mint_token_pair(
        client_id="c", scopes=list(scopes), subject="op1", role=role, timezone=timezone, resource=None,
    )


def _load(provider, access_token) -> TokenInfo:
    """What the server publishes for this token on a request."""
    async def _run():
        current_token_info.set(None)
        at = await provider.load_access_token(access_token)
        assert at is not None, "token not accepted"
        info = current_token_info.get()
        assert info is not None, "token not published to the contextvar"
        return info
    return asyncio.run(_run())


_REDIRECT = AnyUrl("http://127.0.0.1:9/cb")


def _pending(scopes=("monitoring",)):
    client = OAuthClientInformationFull(client_id="c", redirect_uris=[_REDIRECT])
    params = AuthorizationParams(
        state=None, scopes=list(scopes), code_challenge="x" * 43,
        redirect_uri=_REDIRECT, redirect_uri_provided_explicitly=True,
    )
    return client, _PendingAuthorization(client, params)


class TestZoneRidesTheTokens(unittest.TestCase):

    def tearDown(self):
        current_token_info.set(None)

    def test_access_token_publishes_the_zone(self):
        p = _provider()
        info = _load(p, _mint(p, "Europe/London").access_token)
        self.assertEqual(info.timezone, "Europe/London")
        self.assertFalse(info.read_only, "the role still decides read_only")

    def test_no_zone_publishes_none(self):
        p = _provider()
        self.assertIsNone(_load(p, _mint(p, None).access_token).timezone)
        self.assertIsNone(_load(p, _mint(p, "").access_token).timezone)

    def test_unknown_zone_is_dropped_not_fatal(self):
        p = _provider()
        self.assertIsNone(_load(p, _mint(p, "Mars/Olympus").access_token).timezone)
        for raw, expected in (("Europe/Prague", "Europe/Prague"), ("utc", "UTC"), ("System", "system"),
                              ("  ", None), (None, None), ("Nowhere/Land", None), (42, None)):
            with self.subTest(raw=raw):
                self.assertEqual(_timezone_or_none(raw), expected)

    def test_refresh_keeps_the_zone(self):
        p = _provider()
        client = OAuthClientInformationFull(client_id="c")
        pair = _mint(p, "Asia/Tokyo")
        p._access_tokens.pop(pair.access_token, None)  # AT evicted / expired
        rt = asyncio.run(p.load_refresh_token(client, pair.refresh_token))
        self.assertIsNotNone(rt)
        self.assertEqual(getattr(rt, "_timezone", None), "Asia/Tokyo")
        new = asyncio.run(p.exchange_refresh_token(client, rt, []))
        self.assertEqual(_load(p, new.access_token).timezone, "Asia/Tokyo")
        # ...and across a second rotation.
        rt2 = asyncio.run(p.load_refresh_token(client, new.refresh_token))
        new2 = asyncio.run(p.exchange_refresh_token(client, rt2, []))
        self.assertEqual(_load(p, new2.access_token).timezone, "Asia/Tokyo")

    def test_consent_passes_the_zone_onto_the_code_then_the_tokens(self):
        p = _provider()
        client, pending = _pending()
        p.stash_pending("req1", pending)
        p.complete_pending("req1", ["monitoring"], subject="op1", role="operator", timezone="Europe/London")
        code = next(iter(p._codes.values()))
        self.assertEqual(getattr(code, "_timezone", None), "Europe/London")
        self.assertEqual(getattr(code, "_role", None), "operator")
        pair = asyncio.run(p.exchange_authorization_code(client, code))
        self.assertEqual(getattr(p._access_tokens[pair.access_token], "_timezone", None), "Europe/London")
        self.assertEqual(getattr(p._refresh_tokens[pair.refresh_token], "_timezone", None), "Europe/London")
        self.assertEqual(_load(p, pair.access_token).timezone, "Europe/London")

    def test_consent_without_a_zone_leaves_the_tokens_zoneless(self):
        p = _provider()
        client, pending = _pending()
        p.stash_pending("req1", pending)
        p.complete_pending("req1", ["monitoring"], subject="op1", role="operator")
        code = next(iter(p._codes.values()))
        self.assertIsNone(getattr(code, "_timezone", "missing"))
        pair = asyncio.run(p.exchange_authorization_code(client, code))
        self.assertIsNone(_load(p, pair.access_token).timezone)


# ---------------------------------------------------------------------------
# Login + consent views: which zone wins
# ---------------------------------------------------------------------------

_PASSWORD = "Operator_Pass_2026!"


def _consent_cookie(response) -> str:
    """The value of the consent cookie the login step set."""
    for name, value in response.raw_headers:
        if name == b"set-cookie" and value.startswith(oauth_login.CONSENT_COOKIE.encode() + b"_"):
            return value.split(b";")[0].split(b"=", 1)[1].decode()
    raise AssertionError("the login step set no consent cookie")


class _Form(dict):
    def getlist(self, key):
        v = self.get(key, [])
        return list(v) if isinstance(v, (list, tuple)) else [v]


class TestConsentResolvesTheZone(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False)
        h = hash_password(_PASSWORD)
        tmp.write(f'''
[admin.users.zoned]
password_hash = "{h}"
role = "operator"
timezone = "Asia/Tokyo"

[admin.users.plain]
password_hash = "{h}"
role = "operator"

[admin.users.broken]
password_hash = "{h}"
role = "operator"
timezone = "Mars/Olympus"
''')
        tmp.close()
        self.path = tmp.name
        self.config = SimpleNamespace(_config_path=self.path)
        self._audit = patch("zabbix_mcp.admin.audit_writer.write_audit")
        self.audit = self._audit.start()

    def tearDown(self):
        self._audit.stop()
        Path(self.path).unlink(missing_ok=True)
        current_token_info.set(None)

    def _consent(self, username, login_browser_zone=None, consent_browser_zone=None):
        """Run the real login + consent handlers; return the minted code."""
        p = _provider()
        _client, pending = _pending()
        p.stash_pending("req1", pending)
        login = _Form(username=username, password=_PASSWORD)
        if login_browser_zone is not None:
            login["browser_timezone"] = login_browser_zone
        resp = oauth_login._handle_login_step(p, pending, "req1", login, "127.0.0.1", self.config)
        self.assertEqual(resp.status_code, 200, "login must reach the consent screen")
        consent = _Form(action="allow", scope=["monitoring"])
        if consent_browser_zone is not None:
            consent["browser_timezone"] = consent_browser_zone
        nonce = _consent_cookie(resp)
        resp = oauth_login._handle_consent_step(p, pending, "req1", consent, "127.0.0.1", nonce)
        self.assertEqual(resp.status_code, 302, "consent must redirect back to the client")
        return next(iter(p._codes.values()))

    def _audited_zone(self):
        for call in self.audit.call_args_list:
            if call.kwargs.get("action") == "oauth.consent_granted":
                return call.kwargs["details"]["timezone"]
        self.fail("no oauth.consent_granted audit row")

    def test_user_zone_beats_browser_zone(self):
        code = self._consent("zoned", consent_browser_zone="Europe/London")
        self.assertEqual(getattr(code, "_timezone", None), "Asia/Tokyo")
        self.assertEqual(self._audited_zone(), "Asia/Tokyo")

    def test_browser_zone_when_the_user_has_none(self):
        code = self._consent("plain", consent_browser_zone="Europe/London")
        self.assertEqual(getattr(code, "_timezone", None), "Europe/London")
        self.assertEqual(self._audited_zone(), "Europe/London")

    def test_browser_zone_from_the_login_form_is_the_fallback(self):
        # JS filled the login form but the consent form came back bare.
        code = self._consent("plain", login_browser_zone="Europe/Berlin")
        self.assertEqual(getattr(code, "_timezone", None), "Europe/Berlin")
        # ...and the consent form's value wins over the login form's.
        code = self._consent("plain", login_browser_zone="Europe/Berlin", consent_browser_zone="Europe/London")
        self.assertEqual(getattr(code, "_timezone", None), "Europe/London")

    def test_invalid_browser_zone_is_ignored_silently(self):
        code = self._consent("plain", consent_browser_zone="Not/AZone")
        self.assertIsNone(getattr(code, "_timezone", "missing"))
        self.assertIsNone(self._audited_zone())

    def test_no_zone_anywhere_is_none(self):
        code = self._consent("plain")
        self.assertIsNone(getattr(code, "_timezone", "missing"))
        self.assertIsNone(self._audited_zone())

    def test_unknown_user_zone_in_config_does_not_block_login(self):
        code = self._consent("broken", consent_browser_zone="Europe/London")
        self.assertEqual(getattr(code, "_timezone", None), "Europe/London", "falls through to the browser")

    def test_verify_admin_user_returns_the_zone(self):
        ok, role, tz = oauth_login._verify_admin_user(self.config, "zoned", _PASSWORD)
        self.assertEqual((ok, role, tz), (True, "operator", "Asia/Tokyo"))
        ok, role, tz = oauth_login._verify_admin_user(self.config, "plain", _PASSWORD)
        self.assertEqual((ok, role, tz), (True, "operator", None))
        self.assertEqual(oauth_login._verify_admin_user(self.config, "zoned", "wrong"), (False, "", None))


if __name__ == "__main__":
    unittest.main()


class TestImplicitFlagTravels(unittest.TestCase):
    """A browser-reported zone is marked implicit on the code, the tokens and the TokenInfo;
    an operator's zone is not."""

    def test_implicit_flag_rides_code_token_refresh(self):
        p = _provider()
        client, pending = _pending()
        p.stash_pending("req1", pending)
        p.complete_pending("req1", ["monitoring"], subject="op1", role="operator",
                           timezone="Europe/London", timezone_implicit=True)
        code = next(iter(p._codes.values()))
        self.assertTrue(getattr(code, "_timezone_implicit", False))
        pair = asyncio.run(p.exchange_authorization_code(client, code))
        self.assertTrue(getattr(p._access_tokens[pair.access_token], "_timezone_implicit", False))
        info = _load(p, pair.access_token)
        self.assertEqual((info.timezone, info.timezone_implicit), ("Europe/London", True))
        rt = asyncio.run(p.load_refresh_token(client, pair.refresh_token))
        new = asyncio.run(p.exchange_refresh_token(client, rt, []))
        info = _load(p, new.access_token)
        self.assertEqual((info.timezone, info.timezone_implicit), ("Europe/London", True))
        current_token_info.set(None)

    def test_operator_zone_is_explicit(self):
        p = _provider()
        client, pending = _pending()
        p.stash_pending("req1", pending)
        p.complete_pending("req1", ["monitoring"], subject="op1", role="operator", timezone="Europe/London")
        code = next(iter(p._codes.values()))
        pair = asyncio.run(p.exchange_authorization_code(client, code))
        info = _load(p, pair.access_token)
        self.assertEqual((info.timezone, info.timezone_implicit), ("Europe/London", False))
        current_token_info.set(None)

    def test_consent_view_marks_the_browser_zone_implicit(self):
        """oauth_login passes timezone_implicit=True only when the user has no zone of their own."""
        import inspect
        src = inspect.getsource(oauth_login)
        self.assertIn("timezone_implicit = bool(timezone) and not bool(getattr(pending, \"authenticated_timezone\", None))", src)


if __name__ == "__main__":
    unittest.main()
