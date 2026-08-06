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

"""Out-of-band delivery for generated PDF reports (issue #68).

A full PDF returned inline as base64 can blow past an LLM's context
window or a proxy's read timeout, so the report never arrives. This
module lets the operator hand the payload to the filesystem or to a
mailbox instead, and the tool returns a short receipt.

Both channels are **opt-in and operator-fenced** - an AI client can
only ask for delivery, never choose where:

* ``[reporting].output_dir`` must be set before a report can be
  written, filenames are generated server-side (no caller-supplied
  paths), and the resolved path is asserted to stay inside that
  directory.
* ``[reporting.email]`` must be enabled AND list the recipient in
  ``allowed_recipients`` - a wildcard entry like ``*@example.com``
  permits a whole domain. Without the allowlist an LLM could mail
  monitoring data to an arbitrary address.
"""

from __future__ import annotations

import fnmatch
import logging
import re
import smtplib
import time
from email.message import EmailMessage
from pathlib import Path

logger = logging.getLogger("zabbix_mcp.reporting.delivery")

# Report type / company can come from the caller; keep only characters
# that are safe in a filename on every supported platform.
_SAFE_CHARS = re.compile(r"[^A-Za-z0-9._-]+")

MAX_ATTACHMENT_MB = 25


class DeliveryError(Exception):
    """Raised when a delivery channel is unavailable or refused."""


def _safe_component(value: str, fallback: str = "report") -> str:
    cleaned = _SAFE_CHARS.sub("-", (value or "").strip()).strip("-.")
    return cleaned[:60] or fallback


def build_filename(report_type: str, hostgroupid: str) -> str:
    """Server-side filename: caller never supplies a path component."""
    stamp = time.strftime("%Y%m%d-%H%M%S")
    return f"zabbix-{_safe_component(report_type)}-{_safe_component(hostgroupid, 'group')}-{stamp}.pdf"


def save_report(pdf_bytes: bytes, output_dir: str, filename: str) -> str:
    """Write *pdf_bytes* into *output_dir*, return the absolute path.

    Raises DeliveryError when saving is not configured or the resolved
    path would escape the configured directory.
    """
    if not output_dir:
        raise DeliveryError(
            "Saving reports to disk is not enabled. The operator must set "
            "[reporting].output_dir in config.toml."
        )
    base = Path(output_dir).expanduser().resolve()
    if not base.is_dir():
        raise DeliveryError(
            f"[reporting].output_dir does not exist or is not a directory: {base}"
        )
    target = (base / Path(filename).name).resolve()
    # Defence in depth: filename is generated server-side, but a future
    # caller-supplied name must never walk out of the directory.
    if not target.is_relative_to(base):
        raise DeliveryError("Refusing to write outside [reporting].output_dir.")
    target.write_bytes(pdf_bytes)
    try:
        target.chmod(0o640)
    except OSError:
        pass
    logger.info("Report written to %s (%d bytes)", target, len(pdf_bytes))
    return str(target)


def recipient_allowed(address: str, allowed: list[str] | None) -> bool:
    """True when *address* matches the operator's allowlist.

    Entries are compared case-insensitively and may use a glob, so
    ``*@example.com`` permits the whole domain. An empty allowlist
    permits nothing - mailing is opt-in per recipient by design.
    """
    if not allowed:
        return False
    addr = address.strip().lower()
    return any(fnmatch.fnmatch(addr, pattern.strip().lower()) for pattern in allowed)


def send_report_email(
    pdf_bytes: bytes,
    filename: str,
    recipients: list[str],
    *,
    email_config,
    subject: str,
    body: str,
) -> list[str]:
    """Mail the report as an attachment. Returns the accepted recipients.

    Raises DeliveryError when the channel is disabled, a recipient is
    not allowlisted, or the attachment is oversized.
    """
    if not getattr(email_config, "enabled", False):
        raise DeliveryError(
            "Emailing reports is not enabled. The operator must configure "
            "[reporting.email] in config.toml."
        )
    if not recipients:
        raise DeliveryError("No recipients given.")

    refused = [r for r in recipients if not recipient_allowed(r, email_config.allowed_recipients)]
    if refused:
        raise DeliveryError(
            f"Recipient(s) not permitted by [reporting.email].allowed_recipients: "
            f"{', '.join(refused)}"
        )

    size_mb = len(pdf_bytes) / (1024 * 1024)
    if size_mb > MAX_ATTACHMENT_MB:
        raise DeliveryError(
            f"Report is {size_mb:.1f} MB, above the {MAX_ATTACHMENT_MB} MB attachment limit. "
            f"Save it to disk instead."
        )

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = email_config.from_address
    msg["To"] = ", ".join(recipients)
    msg.set_content(body)
    msg.add_attachment(
        pdf_bytes, maintype="application", subtype="pdf", filename=filename,
    )

    timeout = int(getattr(email_config, "timeout", 30) or 30)
    try:
        if email_config.use_ssl:
            smtp: smtplib.SMTP = smtplib.SMTP_SSL(
                email_config.smtp_host, email_config.smtp_port, timeout=timeout)
        else:
            smtp = smtplib.SMTP(email_config.smtp_host, email_config.smtp_port, timeout=timeout)
        with smtp:
            if email_config.use_starttls and not email_config.use_ssl:
                smtp.starttls()
            if email_config.smtp_user:
                smtp.login(email_config.smtp_user, email_config.smtp_password)
            smtp.send_message(msg)
    except DeliveryError:
        raise
    except Exception as exc:  # noqa: BLE001 - surfaced to the operator
        logger.exception("Sending report email failed")
        # Keep the message operator-useful but free of credentials.
        raise DeliveryError(f"SMTP delivery failed: {type(exc).__name__}: {exc}") from None

    logger.info("Report %s emailed to %s", filename, ", ".join(recipients))
    return list(recipients)
