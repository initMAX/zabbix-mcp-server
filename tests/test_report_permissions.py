"""Report generation and report mail per token (#109).

v1.42.2 made save_to_file and email_to writes, so a read-only token could no longer mail
a report, and the only way back was a token with every write right. A token now has two
switches of its own: allow_report (generation, on by default as before) and
allow_report_email (mail to the configured recipients, off by default), and neither
gives any other write.
"""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from zabbix_mcp.server import report_permission_error  # noqa: E402
from zabbix_mcp.token_store import TokenInfo, TokenStore, check_token_authorization, current_token_info  # noqa: E402


def _token(**kw):
    base = dict(id="t", name="t", token_hash="sha256:" + "0" * 64, read_only=True)
    base.update(kw)
    return TokenInfo(**base)


class _As:
    def __init__(self, token):
        self.token = token

    def __enter__(self):
        self.reset = current_token_info.set(self.token)

    def __exit__(self, *a):
        current_token_info.reset(self.reset)


class TestWhatAReportTokenMayDo(unittest.TestCase):
    def test_a_read_only_token_generates_but_does_not_deliver_by_default(self):
        with _As(_token()):
            self.assertIsNone(report_permission_error("s"))
            self.assertIn("email_to sends mail", report_permission_error("s", email_to="ops@example.com"))
            self.assertIn("save_to_file", report_permission_error("s", save_to_file=True))

    def test_report_email_allows_the_mail_and_nothing_else(self):
        with _As(_token(allow_report_email=True)):
            self.assertIsNone(report_permission_error("s", email_to=["ops@example.com"]))
            self.assertIn("save_to_file", report_permission_error("s", save_to_file=True))
            # still read-only for every other write
            self.assertIn("read-only", check_token_authorization("s", tool_prefix="host", is_write=True))

    def test_generation_can_be_turned_off(self):
        with _As(_token(allow_report=False, read_only=False)):
            self.assertIn("may not generate reports", report_permission_error("s"))
            self.assertIn("may not generate reports", report_permission_error("s", email_to="a@example.com"))

    def test_a_write_token_delivers_as_before(self):
        with _As(_token(read_only=False)):
            self.assertIsNone(report_permission_error("s", save_to_file=True, email_to="a@example.com"))

    def test_no_token_stdio_is_unchanged(self):
        self.assertIsNone(report_permission_error("s", save_to_file=True, email_to="a@example.com"))


class TestTheSwitchesInConfig(unittest.TestCase):
    def _load(self, extra: str):
        with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as f:
            f.write('[tokens.a]\nname = "a"\ntoken_hash = "sha256:' + "1" * 64 + '"\n' + extra)
        import tomllib
        cfg = tomllib.loads(Path(f.name).read_text())
        store = TokenStore()
        store.load_from_config(cfg.get("tokens", {}))
        return store.get_token("a")

    def test_defaults_and_values(self):
        t = self._load("")
        self.assertTrue(t.allow_report)
        self.assertFalse(t.allow_report_email)
        t = self._load("allow_report = false\nallow_report_email = true\n")
        self.assertFalse(t.allow_report)
        self.assertTrue(t.allow_report_email)

    def test_a_string_is_not_a_yes(self):
        t = self._load('allow_report_email = "true"\n')
        self.assertFalse(t.allow_report_email)


if __name__ == "__main__":
    unittest.main()
