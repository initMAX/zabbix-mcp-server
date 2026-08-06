#
# Zabbix MCP Server
# Copyright (C) 2026 initMAX s.r.o.
# Licensed under the GNU Affero General Public License v3.
# See LICENSE for details.
#

"""The admin portal must not be able to write a config the loader rejects.

Report delivery is configured in the UI (issue #68), so every key the
Settings form can write has to survive ``load_config`` - otherwise a
save bricks the next start, which is exactly the failure mode the
form-level validation exists to prevent. This pins the contract
between the two.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from zabbix_mcp.admin.views.settings import SECTION_CONFIG, BOOL_KEYS, LIST_KEYS
from zabbix_mcp.config import ConfigError, load_config

_BASE = """
[server]
transport = "http"
auth_token = "test-token-0123456789abcdef0123456789abcdef"

[zabbix.main]
url = "https://zabbix.example.com"
api_token = "dummy"
"""


def _load(extra: str):
    with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as fh:
        fh.write(_BASE + extra)
        path = fh.name
    try:
        return load_config(path)
    finally:
        Path(path).unlink(missing_ok=True)


class TestSettingsSectionRegistry(unittest.TestCase):

    def test_report_sections_registered(self):
        self.assertEqual(SECTION_CONFIG["report_delivery"]["toml_section"], "reporting")
        self.assertEqual(SECTION_CONFIG["report_email"]["toml_section"], "reporting.email")

    def test_report_sections_are_admin_only(self):
        # They hold SMTP credentials and a filesystem path.
        for name in ("report_delivery", "report_email"):
            self.assertEqual(SECTION_CONFIG[name]["min_role"], "admin", name)

    def test_toggle_and_list_keys_declared(self):
        # A checkbox not in BOOL_KEYS lands in TOML as the string "on";
        # a list field not in LIST_KEYS lands as one long string.
        for key in ("use_starttls", "use_ssl", "download_urls"):
            self.assertIn(key, BOOL_KEYS)
        self.assertIn("allowed_recipients", LIST_KEYS)

    def test_download_urls_toggle_is_writable(self):
        self.assertIn("download_urls",
                      SECTION_CONFIG["report_delivery"]["allowed_keys"])


class TestUiWritableConfigLoads(unittest.TestCase):
    """Everything the form can produce must parse."""

    def test_full_delivery_block(self):
        with tempfile.TemporaryDirectory() as out_dir:
            cfg = _load(f"""
[reporting]
output_dir = "{out_dir}"
link_ttl = 900
link_max_reports = 8
download_urls = false

[reporting.email]
enabled = true
smtp_host = "smtp.example.com"
smtp_port = 587
smtp_user = "bot"
smtp_password = "secret"
from_address = "zabbix@example.com"
use_starttls = true
use_ssl = false
timeout = 30
allowed_recipients = ["ops@example.com", "*@example.com"]
""")
            self.assertEqual(cfg.reporting.output_dir, out_dir)
            self.assertEqual(cfg.reporting.link_ttl, 900)
            self.assertEqual(cfg.reporting.link_max_reports, 8)
            # An unchecked checkbox writes `false`, not a missing key.
            self.assertFalse(cfg.reporting.download_urls)
            self.assertTrue(cfg.reporting.email.enabled)
            self.assertEqual(cfg.reporting.email.allowed_recipients,
                             ["ops@example.com", "*@example.com"])

    def test_email_left_disabled_needs_nothing_else(self):
        cfg = _load("[reporting.email]\nenabled = false\n")
        self.assertFalse(cfg.reporting.email.enabled)

    def test_loader_and_form_agree_email_needs_allowlist(self):
        # The form refuses this too; if the loader ever stopped
        # refusing it, an AI client could mail anywhere.
        with self.assertRaises(ConfigError):
            _load("""
[reporting.email]
enabled = true
smtp_host = "smtp.example.com"
from_address = "zabbix@example.com"
allowed_recipients = []
""")

    def test_loader_and_form_agree_on_ttl_bounds(self):
        for bad in ("link_ttl = 5", "link_ttl = 999999", "link_max_reports = 0"):
            with self.assertRaises(ConfigError, msg=bad):
                _load(f"[reporting]\n{bad}\n")

    def test_relative_output_dir_refused(self):
        with self.assertRaises(ConfigError):
            _load('[reporting]\noutput_dir = "reports"\n')


if __name__ == "__main__":
    unittest.main()
