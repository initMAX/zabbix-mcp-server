#
# Zabbix MCP Server
# Copyright (C) 2026 initMAX s.r.o.
# Licensed under the GNU Affero General Public License v3.
# See LICENSE for details.
#

"""The admin portal exposes the four ``timezone`` keys (issue #75).

Drives the real ``server_create`` / ``server_edit`` / ``token_create`` /
``token_detail`` / ``settings_update`` / ``user_create`` / ``user_detail``
handlers with a stub request, so
what the forms write is exactly what ``load_config`` and the token store
accept at the next boot: a valid zone lands under its key, an empty
field removes the key (never ``timezone = ""``), an unknown zone is
refused with the same error rendering the form already uses.
"""

from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from zabbix_mcp.admin.config_writer import load_config_document
from zabbix_mcp.admin.views import servers as server_views
from zabbix_mcp.admin.views import settings as settings_views
from zabbix_mcp.admin.views import tokens as token_views
from zabbix_mcp.admin.views import users as user_views
from zabbix_mcp.config import load_config
from zabbix_mcp.token_store import TokenStore

_BASE = """
[server]
transport = "http"
host = "127.0.0.1"
port = 8080

[zabbix.main]
url = "https://zabbix.example.com"
api_token = "dummy"

[zabbix.zoned]
url = "https://zabbix2.example.com"
api_token = "dummy"
timezone = "Europe/London"

[tokens.t1]
name = "Client one"
token_hash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
scopes = ["*"]
allowed_servers = ["*"]

[tokens.t2]
name = "Client two"
token_hash = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
scopes = ["*"]
allowed_servers = ["*"]
timezone = "Asia/Tokyo"

[admin.users.tester]
password_hash = "scrypt:131072:8:1$00000000000000000000000000000000$0000000000000000000000000000000000000000000000000000000000000000"
role = "admin"

[admin.users.plain]
password_hash = "scrypt:131072:8:1$00000000000000000000000000000000$0000000000000000000000000000000000000000000000000000000000000000"
role = "operator"

[admin.users.zoned]
password_hash = "scrypt:131072:8:1$00000000000000000000000000000000$0000000000000000000000000000000000000000000000000000000000000000"
role = "viewer"
timezone = "Asia/Tokyo"
"""


class _Req:
    """Just enough of a Starlette Request for the handlers."""

    def __init__(self, admin_app, form: dict, method="POST", path_params=None):
        self.app = SimpleNamespace(state=SimpleNamespace(admin_app=admin_app))
        self._form = form
        self.method = method
        self.path_params = path_params or {}
        self.client = SimpleNamespace(host="127.0.0.1")
        self.query_params = {}

    async def form(self):
        return self._form


def _admin_app(path: str):
    from zabbix_mcp.admin.app import AdminApp
    store = TokenStore()
    store.load_from_config({k: dict(v) for k, v in load_config_document(path).get("tokens", {}).items()})
    app = AdminApp(config=load_config(path), config_path=path,
                   client_manager=MagicMock(), token_store=store, oauth_provider=None)
    app.client_manager.server_names = ["main", "zoned"]
    app.client_manager.skipped_servers = {}
    app.require_auth = lambda request: SimpleNamespace(role="admin", user="tester")
    app.render = MagicMock(return_value="rendered")   # capture the re-render context
    return app


def _run(coro):
    return asyncio.run(coro)


def _flash(resp) -> str:
    """The flash cookies a redirect carries, for asserting on the error text."""
    return " ".join(v.decode() for k, v in resp.raw_headers if k == b"set-cookie")


class _Base(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False)
        tmp.write(_BASE); tmp.close()
        self.path = tmp.name
        self.app = _admin_app(self.path)
        self._patches = [
            patch.object(server_views, "write_audit"),
            patch.object(token_views, "write_audit"),
            patch.object(user_views, "write_audit"),
            patch("zabbix_mcp.admin.audit_writer.write_audit"),
        ]
        for p in self._patches:
            p.start()

    def tearDown(self):
        for p in self._patches:
            p.stop()
        Path(self.path).unlink(missing_ok=True)

    def _server(self, name):
        return dict(load_config_document(self.path).get("zabbix", {}).get(name, {}))

    def _token(self, token_id):
        return dict(load_config_document(self.path).get("tokens", {}).get(token_id, {}))

    def _server_section(self):
        return dict(load_config_document(self.path).get("server", {}))

    def _user(self, username):
        return dict(load_config_document(self.path).get("admin", {}).get("users", {}).get(username, {}))


# ---------------------------------------------------------------------------
# [zabbix.<name>].timezone
# ---------------------------------------------------------------------------
class TestServerForm(_Base):

    def _create(self, **form):
        base = {"name": "new", "url": "https://zabbix3.example.com", "api_token": "tok",
                "username": "", "password": "", "request_timeout": "300", "verify_ssl": "on"}
        base.update(form)
        resp = _run(server_views.server_create(_Req(self.app, base)))
        ctx = self.app.render.call_args.args[2] if self.app.render.called else None
        return resp, ctx

    def _edit(self, name, **form):
        base = {"name": name, "url": "", "api_token": "", "username": "", "password": "",
                "request_timeout": "300", "frontend_username": "", "frontend_password": "",
                "verify_ssl": "on", "_cfg_mtime": ""}
        base.update(form)
        return _run(server_views.server_edit(_Req(self.app, base, path_params={"server_name": name})))

    def test_create_writes_a_valid_zone(self):
        self._create(timezone="Europe/Prague")
        self.assertEqual(self._server("new")["timezone"], "Europe/Prague")
        self.assertEqual(load_config(self.path).zabbix_servers["new"].timezone, "Europe/Prague")

    def test_create_normalises_utc_and_system(self):
        self._create(name="a", timezone="utc")
        self._create(name="b", timezone="System")
        self.assertEqual(self._server("a")["timezone"], "UTC")
        self.assertEqual(self._server("b")["timezone"], "system")

    def test_create_with_empty_zone_writes_no_key(self):
        self._create(timezone="   ")
        e = self._server("new")
        self.assertTrue(e)
        self.assertNotIn("timezone", e)

    def test_create_rejects_an_unknown_zone_with_the_form_error(self):
        _, ctx = self._create(timezone="Mars/Olympus")
        self.assertIn("Time zone is invalid", ctx["add_form_error"])
        self.assertIn("Mars/Olympus", ctx["add_form_error"])
        self.assertEqual(ctx["form_timezone"], "Mars/Olympus", "typed value is echoed back")
        self.assertEqual(ctx["form_api_token"], "tok", "the rest of the form survives")
        self.assertEqual(self._server("new"), {})

    def test_edit_saves_a_valid_zone(self):
        resp = self._edit("main", url="https://zabbix.example.com", timezone="America/New_York")
        self.assertEqual(resp.status_code, 303)
        self.assertEqual(self._server("main")["timezone"], "America/New_York")
        load_config(self.path)   # and the loader accepts what the form wrote

    def test_edit_updates_an_existing_zone(self):
        self._edit("zoned", url="https://zabbix2.example.com", timezone="Europe/Berlin")
        self.assertEqual(self._server("zoned")["timezone"], "Europe/Berlin")

    def test_edit_with_empty_field_removes_the_key(self):
        self._edit("zoned", url="https://zabbix2.example.com", timezone="")
        e = self._server("zoned")
        self.assertNotIn("timezone", e)
        self.assertEqual(e["url"], "https://zabbix2.example.com", "nothing else touched")
        self.assertNotIn('timezone = ""', Path(self.path).read_text())
        self.assertEqual(load_config(self.path).zabbix_servers["zoned"].timezone, "")

    def test_edit_rejects_an_unknown_zone_and_keeps_the_stored_one(self):
        resp = self._edit("zoned", url="https://zabbix2.example.com", timezone="Nowhere/Land")
        self.assertEqual(resp.status_code, 303)      # redirected back with the error flash
        self.assertIn("Time zone is invalid", _flash(resp))
        self.assertEqual(self._server("zoned")["timezone"], "Europe/London", "nothing changed")

    def test_edit_form_renders_the_stored_zone(self):
        _run(server_views.server_edit(_Req(self.app, {}, method="GET", path_params={"server_name": "zoned"})))
        ctx = self.app.render.call_args.args[2]
        self.assertEqual(ctx["server"]["timezone"], "Europe/London")


# ---------------------------------------------------------------------------
# [tokens.<id>].timezone
# ---------------------------------------------------------------------------
class TestTokenForm(_Base):

    def _create(self, **form):
        base = {"name": "Fresh client", "scopes": "*", "allowed_servers": "*",
                "ip_allowlist": "", "expires_at": ""}
        base.update(form)
        _run(token_views.token_create(_Req(self.app, base)))
        return self.app.render.call_args.args[2]

    def _edit(self, token_id, **form):
        base = {"name": "", "scopes": "*", "allowed_servers": "*", "ip_allowlist": "",
                "expires_at": "", "_cfg_mtime": ""}
        base.update(form)
        return _run(token_views.token_detail(_Req(self.app, base, path_params={"token_id": token_id})))

    def test_create_writes_the_zone_and_the_store_picks_it_up(self):
        ctx = self._create(timezone="Europe/Prague")
        self.assertIn("created_token", ctx)
        token_id = ctx["token_id"]
        self.assertEqual(self._token(token_id)["timezone"], "Europe/Prague")
        self.assertEqual(self.app.token_store.get_token(token_id).timezone, "Europe/Prague")

    def test_create_with_empty_zone_writes_no_key(self):
        ctx = self._create(timezone="")
        self.assertNotIn("timezone", self._token(ctx["token_id"]))
        self.assertIsNone(self.app.token_store.get_token(ctx["token_id"]).timezone)

    def test_create_rejects_an_unknown_zone(self):
        ctx = self._create(timezone="Mars/Olympus")
        self.assertIn("Time zone is invalid", ctx["error"])
        self.assertEqual(ctx["form_timezone"], "Mars/Olympus")
        self.assertEqual(ctx["form_name"], "Fresh client", "typed values survive the error")
        self.assertNotIn("fresh_client", load_config_document(self.path).get("tokens", {}))

    def test_create_duplicate_from_prefills_the_zone(self):
        req = _Req(self.app, {}, method="GET")
        req.query_params = {"duplicate_from": "t2"}
        _run(token_views.token_create(req))
        ctx = self.app.render.call_args.args[2]
        self.assertEqual(ctx["form_timezone"], "Asia/Tokyo")

    def test_edit_sets_the_zone(self):
        resp = self._edit("t1", timezone="Europe/Prague")
        self.assertEqual(resp.status_code, 303)
        self.assertEqual(self._token("t1")["timezone"], "Europe/Prague")
        self.assertEqual(self.app.token_store.get_token("t1").timezone, "Europe/Prague")
        self.assertTrue(self.app.restart_needed)

    def test_edit_updates_the_zone(self):
        self._edit("t2", timezone="utc")
        self.assertEqual(self._token("t2")["timezone"], "UTC")
        self.assertEqual(self.app.token_store.get_token("t2").timezone, "UTC")

    def test_edit_with_empty_field_removes_the_key(self):
        self._edit("t2", timezone="")
        e = self._token("t2")
        self.assertNotIn("timezone", e)
        self.assertEqual(e["name"], "Client two", "nothing else touched")
        self.assertNotIn('timezone = ""', Path(self.path).read_text())
        self.assertIsNone(self.app.token_store.get_token("t2").timezone)
        self.assertTrue(self.app.restart_needed, "clearing the zone is a change")

    def test_edit_rejects_an_unknown_zone_and_keeps_the_stored_one(self):
        resp = self._edit("t2", timezone="Nowhere/Land")
        self.assertEqual(resp.status_code, 303)
        self.assertIn("Time zone is invalid", _flash(resp))
        self.assertEqual(self._token("t2")["timezone"], "Asia/Tokyo")

    def test_detail_page_shows_the_zone(self):
        _run(token_views.token_detail(_Req(self.app, {}, method="GET", path_params={"token_id": "t2"})))
        ctx = self.app.render.call_args.args[2]
        self.assertEqual(ctx["token"].timezone, "Asia/Tokyo")


# ---------------------------------------------------------------------------
# [server].timezone
# ---------------------------------------------------------------------------
class TestSettingsForm(_Base):

    def _save(self, **form):
        base = {"host": "127.0.0.1", "port": "8080", "transport": "http", "_cfg_mtime": ""}
        base.update(form)
        return _run(settings_views.settings_update(_Req(self.app, base, path_params={"section": "server"})))

    def test_timezone_is_an_allowed_server_key(self):
        self.assertIn("timezone", settings_views.SECTION_CONFIG["server"]["allowed_keys"])

    def test_saves_a_valid_zone(self):
        resp = self._save(timezone="Europe/Prague")
        self.assertEqual(resp.status_code, 303)
        self.assertEqual(self._server_section()["timezone"], "Europe/Prague")
        self.assertEqual(load_config(self.path).server.timezone, "Europe/Prague")

    def test_normalises_the_spelling(self):
        self._save(timezone="utc")
        self.assertEqual(self._server_section()["timezone"], "UTC")

    def test_empty_field_removes_the_key(self):
        self._save(timezone="Europe/Prague")
        self._save(timezone="")
        self.assertNotIn("timezone", self._server_section())
        self.assertNotIn('timezone = ""', Path(self.path).read_text())

    def test_rejects_an_unknown_zone(self):
        resp = self._save(timezone="Mars/Olympus")
        self.assertEqual(resp.status_code, 303)
        self.assertIn("Time zone is invalid", _flash(resp))
        self.assertNotIn("timezone", self._server_section())

    def test_settings_view_exposes_the_stored_zone(self):
        self._save(timezone="Europe/Prague")
        _run(settings_views.settings_view(_Req(self.app, {}, method="GET")))
        ctx = self.app.render.call_args.args[2]
        self.assertEqual(ctx["settings"]["timezone"], "Europe/Prague")


# ---------------------------------------------------------------------------
# [admin.users.<name>].timezone - what the OAuth consent step hands the tokens
# ---------------------------------------------------------------------------
class TestUserForm(_Base):

    def _create(self, **form):
        base = {"username": "fresh", "password": "Fresh_Pass_2026", "role": "operator"}
        base.update(form)
        resp = _run(user_views.user_create(_Req(self.app, base)))
        ctx = self.app.render.call_args.args[2] if self.app.render.called else None
        return resp, ctx

    def _edit(self, username, **form):
        base = {"password": "", "confirm_password": "", "current_password": "", "role": "", "_cfg_mtime": ""}
        base.update(form)
        return _run(user_views.user_detail(_Req(self.app, base, path_params={"username": username})))

    def test_create_writes_a_valid_zone(self):
        resp, _ = self._create(timezone="Europe/Prague")
        self.assertEqual(resp.status_code, 303)
        u = self._user("fresh")
        self.assertEqual(u["timezone"], "Europe/Prague")
        self.assertEqual(u["role"], "operator")

    def test_create_normalises_the_spelling(self):
        self._create(username="ab", timezone="utc")
        self.assertEqual(self._user("ab")["timezone"], "UTC")

    def test_create_with_empty_zone_writes_no_key(self):
        self._create(timezone="   ")
        u = self._user("fresh")
        self.assertTrue(u)
        self.assertNotIn("timezone", u)
        self.assertNotIn('timezone = ""', Path(self.path).read_text())

    def test_create_rejects_an_unknown_zone_with_the_form_error(self):
        _, ctx = self._create(timezone="Mars/Olympus")
        self.assertIn("Time zone is invalid", ctx["error"])
        self.assertEqual(ctx["form_timezone"], "Mars/Olympus", "typed value is echoed back")
        self.assertEqual(ctx["form_username"], "fresh", "the rest of the form survives")
        self.assertEqual(self._user("fresh"), {})

    def test_edit_sets_the_zone(self):
        resp = self._edit("plain", timezone="America/New_York")
        self.assertEqual(resp.status_code, 303)
        self.assertEqual(self._user("plain")["timezone"], "America/New_York")
        self.assertEqual(self._user("plain")["role"], "operator", "nothing else touched")
        self.assertTrue(self.app.restart_needed)

    def test_edit_updates_the_zone(self):
        self._edit("zoned", timezone="Europe/Berlin")
        self.assertEqual(self._user("zoned")["timezone"], "Europe/Berlin")

    def test_edit_with_empty_field_removes_the_key(self):
        self._edit("zoned", timezone="")
        u = self._user("zoned")
        self.assertNotIn("timezone", u)
        self.assertEqual(u["role"], "viewer", "nothing else touched")
        self.assertNotIn('timezone = ""', Path(self.path).read_text())

    def test_edit_rejects_an_unknown_zone_and_keeps_the_stored_one(self):
        self._edit("zoned", timezone="Nowhere/Land")
        ctx = self.app.render.call_args.args[2]
        self.assertIn("Time zone is invalid", ctx["error"])
        self.assertEqual(ctx["edit_timezone"], "Nowhere/Land", "typed value is echoed back")
        self.assertEqual(self._user("zoned")["timezone"], "Asia/Tokyo", "nothing changed")

    def test_edit_form_renders_the_stored_zone(self):
        _run(user_views.user_detail(_Req(self.app, {}, method="GET", path_params={"username": "zoned"})))
        ctx = self.app.render.call_args.args[2]
        self.assertEqual(ctx["edit_timezone"], "Asia/Tokyo")
        _run(user_views.user_detail(_Req(self.app, {}, method="GET", path_params={"username": "plain"})))
        self.assertEqual(self.app.render.call_args.args[2]["edit_timezone"], "")

    def test_oauth_login_sees_the_zone(self):
        # The consent step reads the same key through _verify_admin_user.
        from types import SimpleNamespace as _NS
        from unittest.mock import patch as _patch
        from zabbix_mcp import oauth_login
        self._edit("plain", timezone="Europe/Prague")
        with _patch("zabbix_mcp.admin.auth.verify_password", return_value=True):
            ok, role, tz = oauth_login._verify_admin_user(_NS(_config_path=self.path), "plain", "x")
        self.assertEqual((ok, role, tz), (True, "operator", "Europe/Prague"))


class TestTokenReportSwitches(_Base):
    """#109: the two report switches round-trip through the portal (create and edit)."""

    _create = TestTokenForm._create
    _edit = TestTokenForm._edit

    def test_create_defaults_write_no_keys(self):
        ctx = self._create(allow_report="1")
        entry = self._token(ctx["token_id"])
        self.assertNotIn("allow_report", entry)
        self.assertNotIn("allow_report_email", entry)
        token = self.app.token_store.get_token(ctx["token_id"])
        self.assertTrue(token.allow_report)
        self.assertFalse(token.allow_report_email)

    def test_create_with_mail_and_without_generation(self):
        ctx = self._create(allow_report_email="1")
        entry = self._token(ctx["token_id"])
        self.assertIs(entry["allow_report"], False)
        self.assertIs(entry["allow_report_email"], True)

    def test_edit_sets_and_clears_them(self):
        self._edit("t1", _report_fields="1", allow_report="1", allow_report_email="1")
        self.assertTrue(self.app.token_store.get_token("t1").allow_report_email)
        self._edit("t1", _report_fields="1", allow_report="1")
        self.assertFalse(self.app.token_store.get_token("t1").allow_report_email)
        self.assertTrue(self.app.token_store.get_token("t1").allow_report)

    def test_a_form_without_the_switches_leaves_them(self):
        self._edit("t1", _report_fields="1", allow_report="1", allow_report_email="1")
        self._edit("t1")                       # a page opened before the update
        token = self.app.token_store.get_token("t1")
        self.assertTrue(token.allow_report)
        self.assertTrue(token.allow_report_email)


if __name__ == "__main__":
    unittest.main()

