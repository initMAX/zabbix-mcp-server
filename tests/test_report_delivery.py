#
# Zabbix MCP Server
# Copyright (C) 2026 initMAX s.r.o.
# Licensed under the GNU Affero General Public License v3.
# See LICENSE for details.
#

"""Issue #68: out-of-band delivery of generated PDF reports.

Both channels are operator-fenced - the AI client asks for delivery but
never picks the destination. These tests pin the fence: no writing
without a configured directory, no path escapes, no mailing to an
address the operator did not allowlist.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from zabbix_mcp.config import ReportEmailConfig
from zabbix_mcp.reporting import delivery

PDF = b"%PDF-1.4 fake report payload"


class TestFilename(unittest.TestCase):

    def test_filename_is_sanitised_and_stamped(self):
        name = delivery.build_filename("availability", "42")
        self.assertTrue(name.startswith("zabbix-availability-42-"))
        self.assertTrue(name.endswith(".pdf"))

    def test_hostile_components_cannot_inject_path_separators(self):
        name = delivery.build_filename("../../etc/passwd", "a/b")
        self.assertNotIn("/", name)
        self.assertNotIn("..", name)


class TestSaveReport(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_saves_and_returns_path(self):
        path = delivery.save_report(PDF, self.dir, "report.pdf")
        self.assertTrue(Path(path).is_file())
        self.assertEqual(Path(path).read_bytes(), PDF)

    def test_refuses_when_not_configured(self):
        with self.assertRaises(delivery.DeliveryError) as ctx:
            delivery.save_report(PDF, "", "report.pdf")
        self.assertIn("output_dir", str(ctx.exception))

    def test_refuses_missing_directory(self):
        with self.assertRaises(delivery.DeliveryError):
            delivery.save_report(PDF, str(Path(self.dir) / "nope"), "report.pdf")

    def test_traversal_in_filename_cannot_escape(self):
        # Even if a future caller supplies the name, it stays put.
        path = delivery.save_report(PDF, self.dir, "../../escaped.pdf")
        self.assertEqual(Path(path).parent, Path(self.dir).resolve())


class TestRecipientAllowlist(unittest.TestCase):

    def test_empty_allowlist_permits_nothing(self):
        self.assertFalse(delivery.recipient_allowed("ops@example.com", []))
        self.assertFalse(delivery.recipient_allowed("ops@example.com", None))

    def test_exact_match_case_insensitive(self):
        self.assertTrue(delivery.recipient_allowed("OPS@Example.com", ["ops@example.com"]))

    def test_domain_wildcard(self):
        self.assertTrue(delivery.recipient_allowed("anyone@example.com", ["*@example.com"]))
        self.assertFalse(delivery.recipient_allowed("anyone@evil.com", ["*@example.com"]))


class TestSendEmail(unittest.TestCase):

    def _cfg(self, **kw):
        base = dict(
            enabled=True, smtp_host="smtp.example.com", smtp_port=587,
            from_address="zabbix@example.com",
            allowed_recipients=["ops@example.com"],
        )
        base.update(kw)
        return ReportEmailConfig(**base)

    def test_refuses_when_disabled(self):
        with self.assertRaises(delivery.DeliveryError):
            delivery.send_report_email(
                PDF, "r.pdf", ["ops@example.com"],
                email_config=self._cfg(enabled=False), subject="s", body="b")

    def test_refuses_recipient_outside_allowlist(self):
        with self.assertRaises(delivery.DeliveryError) as ctx:
            delivery.send_report_email(
                PDF, "r.pdf", ["attacker@evil.com"],
                email_config=self._cfg(), subject="s", body="b")
        self.assertIn("allowed_recipients", str(ctx.exception))

    def test_refuses_oversized_attachment(self):
        big = b"x" * ((delivery.MAX_ATTACHMENT_MB + 1) * 1024 * 1024)
        with self.assertRaises(delivery.DeliveryError) as ctx:
            delivery.send_report_email(
                big, "r.pdf", ["ops@example.com"],
                email_config=self._cfg(), subject="s", body="b")
        self.assertIn("attachment limit", str(ctx.exception))

    def test_sends_with_attachment(self):
        smtp = MagicMock()
        smtp.__enter__ = MagicMock(return_value=smtp)
        smtp.__exit__ = MagicMock(return_value=False)
        with patch("smtplib.SMTP", return_value=smtp) as ctor:
            sent = delivery.send_report_email(
                PDF, "report.pdf", ["ops@example.com"],
                email_config=self._cfg(smtp_user="u", smtp_password="p"),
                subject="Zabbix report", body="body")
        self.assertEqual(sent, ["ops@example.com"])
        ctor.assert_called_once()
        smtp.starttls.assert_called_once()
        smtp.login.assert_called_once_with("u", "p")
        msg = smtp.send_message.call_args.args[0]
        self.assertEqual(msg["Subject"], "Zabbix report")
        self.assertEqual(msg["To"], "ops@example.com")
        attachments = [part for part in msg.iter_attachments()]
        self.assertEqual(len(attachments), 1)
        self.assertEqual(attachments[0].get_filename(), "report.pdf")
        self.assertEqual(attachments[0].get_payload(decode=True), PDF)

    def test_smtp_failure_surfaces_without_credentials(self):
        with patch("smtplib.SMTP", side_effect=OSError("connection refused")):
            with self.assertRaises(delivery.DeliveryError) as ctx:
                delivery.send_report_email(
                    PDF, "r.pdf", ["ops@example.com"],
                    email_config=self._cfg(smtp_password="hunter2"),
                    subject="s", body="b")
        self.assertNotIn("hunter2", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
