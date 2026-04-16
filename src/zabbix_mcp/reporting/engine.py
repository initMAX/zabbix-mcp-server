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

"""PDF report generation engine using Jinja2 templates and weasyprint."""

from __future__ import annotations

import base64
import logging
import math
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger("zabbix_mcp.reporting")

try:
    import jinja2
    import jinja2.sandbox
    import weasyprint

    REPORTING_AVAILABLE = True
except ImportError:
    REPORTING_AVAILABLE = False

TEMPLATE_DIR = Path(__file__).parent / "templates"
# Custom templates added via the admin portal live here. `load_custom_templates`
# validates that every configured `template_file` path resolves inside this
# directory to prevent directory-traversal attacks.
CUSTOM_TEMPLATE_DIR = Path("/etc/zabbix-mcp/templates")

_ALLOWED_LOGO_EXTENSIONS = {".png", ".jpg", ".jpeg", ".svg"}

_MIME_TYPES = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".svg": "image/svg+xml",
}

_REPORT_TEMPLATES = {
    "availability": "availability.html",
    "capacity_host": "capacity_host.html",
    "capacity_network": "capacity_network.html",
    "backup": "backup.html",
}


def _compute_gauge_arc_path(percentage: float) -> str:
    """Compute an SVG arc path for a semicircular gauge.

    The gauge spans from 180 degrees (left) to 0 degrees (right) in a
    semicircle centered at (100, 100) with radius 80.  The *percentage*
    value (0-100) maps linearly onto this arc.
    """
    percentage = max(0.0, min(100.0, percentage))
    angle_deg = 180.0 - (percentage / 100.0) * 180.0
    angle_rad = math.radians(angle_deg)
    end_x = 100.0 + 80.0 * math.cos(angle_rad)
    end_y = 100.0 - 80.0 * math.sin(angle_rad)
    large_arc = 1 if percentage > 50 else 0
    return f"M 20 100 A 80 80 0 {large_arc} 1 {end_x:.1f} {end_y:.1f}"


def _read_logo_as_base64(logo_path: str) -> str | None:
    """Safely read a logo file and return a base64 data URI.

    Returns ``None`` when the path is invalid, not a regular file,
    a symbolic link, or has a disallowed extension.
    """
    raw_path = Path(logo_path)

    # Security: reject symlinks BEFORE resolving (prevents TOCTOU)
    if raw_path.is_symlink():
        logger.warning("Logo path is a symbolic link, rejecting: %s", logo_path)
        return None

    path = raw_path.resolve()

    if not path.is_file():
        logger.warning("Logo path is not a regular file: %s", logo_path)
        return None

    ext = path.suffix.lower()
    if ext not in _ALLOWED_LOGO_EXTENSIONS:
        logger.warning(
            "Logo extension '%s' not allowed (allowed: %s)",
            ext,
            ", ".join(sorted(_ALLOWED_LOGO_EXTENSIONS)),
        )
        return None

    mime = _MIME_TYPES[ext]
    data = path.read_bytes()
    encoded = base64.b64encode(data).decode("ascii")
    return f"data:{mime};base64,{encoded}"


class ReportEngine:
    """Generate professional PDF reports from Zabbix data."""

    def __init__(
        self,
        logo_path: str | None = None,
        company_name: str = "",
        subtitle: str = "IT Monitoring Service",
    ) -> None:
        if not REPORTING_AVAILABLE:
            raise RuntimeError(
                "Reporting dependencies not installed. "
                "Install with: pip install jinja2 weasyprint"
            )
        self.logo_path = logo_path
        self.company_name = company_name
        self.subtitle = subtitle

        # Custom templates (uploaded via the admin portal) are rendered
        # in a SandboxedEnvironment to block Python-introspection RCE
        # (e.g. `{{ ''.__class__.__mro__[1].__subclasses__() }}`). The
        # loader still covers both the built-in templates dir and the
        # operator's CUSTOM_TEMPLATE_DIR so custom entries resolve.
        loader = jinja2.FileSystemLoader([
            str(TEMPLATE_DIR),
            str(CUSTOM_TEMPLATE_DIR),
        ])
        self._env = jinja2.sandbox.SandboxedEnvironment(
            loader=loader,
            autoescape=True,
        )

    def render_pdf(self, template_name: str, context: dict) -> bytes:
        """Render an HTML template to PDF bytes."""
        template = self._env.get_template(template_name)

        # Build common context values
        logo_base64: str | None = None
        if self.logo_path:
            logo_base64 = _read_logo_as_base64(self.logo_path)

        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        common: dict = {
            "logo_base64": logo_base64,
            "company": self.company_name,
            "subtitle": self.subtitle,
            "generated_at": now,
            "page_label": "Page",
        }
        common.update(context)

        html_string = template.render(**common)

        pdf_doc = weasyprint.HTML(string=html_string).write_pdf()
        return pdf_doc

    def load_custom_templates(self, custom_templates: dict) -> None:
        """Register custom templates from config [report_templates.*].

        Security: every `template_file` must resolve inside
        CUSTOM_TEMPLATE_DIR. Absolute paths, symlinks, or `..` segments
        that escape the directory are rejected. Only the basename is
        stored so the FileSystemLoader resolves it via its configured
        search path (no absolute-path lookups).
        """
        try:
            allowed_root = CUSTOM_TEMPLATE_DIR.resolve()
        except (OSError, RuntimeError):
            logger.warning(
                "Custom template dir %s cannot be resolved; skipping all custom templates.",
                CUSTOM_TEMPLATE_DIR,
            )
            return

        for key, tmpl in custom_templates.items():
            template_file = (tmpl or {}).get("template_file", "")
            if not template_file:
                continue

            # Reject any path component that looks like a traversal.
            raw = Path(template_file)
            if raw.is_absolute():
                # Operators put the absolute path in config after the
                # admin portal uploaded the file; rewrite to just the
                # basename and verify it lives under allowed_root.
                candidate = allowed_root / raw.name
            else:
                candidate = (allowed_root / raw).resolve()

            try:
                resolved = candidate.resolve()
            except (OSError, RuntimeError):
                logger.warning(
                    "Custom template '%s' path %s cannot be resolved; skipped.",
                    key,
                    template_file,
                )
                continue

            try:
                resolved.relative_to(allowed_root)
            except ValueError:
                logger.warning(
                    "Custom template '%s' path %s escapes %s; skipped.",
                    key,
                    template_file,
                    allowed_root,
                )
                continue

            if resolved.is_symlink() or (resolved.exists() and not resolved.is_file()):
                logger.warning(
                    "Custom template '%s' path %s is not a regular file; skipped.",
                    key,
                    template_file,
                )
                continue

            # Store only the basename; FileSystemLoader will resolve it
            # against CUSTOM_TEMPLATE_DIR, never via absolute path.
            _REPORT_TEMPLATES[key] = resolved.name

    def generate_report(self, report_type: str, data: dict, **options: object) -> bytes:
        """Generate a specific report type.

        Parameters
        ----------
        report_type:
            One of ``"availability"``, ``"capacity_host"``,
            ``"capacity_network"``, ``"backup"``.
        data:
            Context dictionary produced by the corresponding
            ``fetch_*`` function in :mod:`zabbix_mcp.reporting.data_fetcher`.
        **options:
            Extra key/value pairs merged into the template context
            (e.g. ``company_name``).
        """
        template_file = _REPORT_TEMPLATES.get(report_type)
        if template_file is None:
            available = ", ".join(sorted(_REPORT_TEMPLATES))
            raise ValueError(
                f"Unknown report type '{report_type}'. Available: {available}"
            )

        context = dict(data)
        context.update(options)

        # Pre-compute derived values needed by specific templates
        if report_type == "availability":
            pct = context.get("availability_pct", 0.0)
            context["gauge_arc_path"] = _compute_gauge_arc_path(pct)

        return self.render_pdf(template_file, context)
