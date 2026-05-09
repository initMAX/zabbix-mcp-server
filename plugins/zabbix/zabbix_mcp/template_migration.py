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

"""Custom report template migration.

v1.16 shipped custom report templates at ``/var/log/zabbix-mcp/templates/``,
which was an oversight: configuration files do not belong in a log directory.
v1.17 moved them to ``/etc/zabbix-mcp/templates/``. For host installs,
``deploy/install.sh`` runs an equivalent bash migration step during
``update``. Container deployments do not use the installer, so this module
performs the migration at server startup.

The function is idempotent and non-fatal: any failure is logged as a warning
and the server continues to start.
"""

from __future__ import annotations

import logging
import shutil
from pathlib import Path

logger = logging.getLogger(__name__)

LEGACY_TEMPLATE_DIR = Path("/var/log/zabbix-mcp/templates")
CURRENT_TEMPLATE_DIR = Path("/etc/zabbix-mcp/templates")


def migrate_custom_templates(config_path: Path | str | None = None) -> None:
    """Move custom report templates from the legacy v1.16 location to the
    current v1.17+ location and rewrite ``template_file`` paths in
    ``config.toml``.

    Safe to run on every startup: no-op if the legacy directory is missing
    or already empty.
    """
    try:
        _migrate(config_path)
    except Exception as exc:  # noqa: BLE001 - never break startup
        logger.warning("Template migration failed (non-fatal): %s", exc)


def _migrate(config_path: Path | str | None) -> None:
    # Ensure the current directory exists. For containers this covers the
    # case where the volume is fresh; for bare-metal installs the installer
    # has already created it.
    try:
        CURRENT_TEMPLATE_DIR.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        # Read-only FS or service user lacks write permission. The admin
        # will see a clear error the first time they try to save a template
        # via the portal - nothing useful we can do here.
        return

    if not LEGACY_TEMPLATE_DIR.is_dir():
        return

    legacy_files = sorted(LEGACY_TEMPLATE_DIR.glob("*.html"))
    if not legacy_files:
        # Leftover empty directory - try to remove it, ignore failures.
        try:
            LEGACY_TEMPLATE_DIR.rmdir()
        except OSError:
            pass
        return

    moved: list[str] = []
    skipped: list[str] = []
    for src in legacy_files:
        dst = CURRENT_TEMPLATE_DIR / src.name
        if dst.exists():
            logger.warning(
                "Template migration: %s already exists at %s, leaving %s untouched",
                src.name, CURRENT_TEMPLATE_DIR, src,
            )
            skipped.append(src.name)
            continue
        try:
            shutil.copy2(src, dst)
            src.unlink()
            moved.append(src.name)
        except OSError as exc:
            logger.warning(
                "Template migration: failed to move %s: %s", src.name, exc,
            )
            skipped.append(src.name)

    if moved:
        logger.info(
            "Migrated %d custom report template(s) from %s to %s: %s",
            len(moved), LEGACY_TEMPLATE_DIR, CURRENT_TEMPLATE_DIR,
            ", ".join(moved),
        )
        _rewrite_config_paths(config_path)

    # Remove the legacy directory if it is empty now.
    try:
        LEGACY_TEMPLATE_DIR.rmdir()
    except OSError:
        pass


def _rewrite_config_paths(config_path: Path | str | None) -> None:
    """Rewrite ``[report_templates.*].template_file`` paths in ``config.toml``.

    Preserves comments and formatting via tomlkit.
    """
    if not config_path:
        return
    try:
        import tomlkit
    except ImportError:
        logger.warning(
            "Template migration: tomlkit not available, cannot update "
            "template_file paths in config.toml"
        )
        return

    path = Path(config_path)
    if not path.is_file():
        return

    try:
        doc = tomlkit.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - log and skip
        logger.warning(
            "Template migration: failed to parse %s: %s", path, exc,
        )
        return

    templates = doc.get("report_templates")
    if not templates:
        return

    old_prefix = str(LEGACY_TEMPLATE_DIR) + "/"
    new_prefix = str(CURRENT_TEMPLATE_DIR) + "/"
    changed = False
    for key in list(templates.keys()):
        section = templates[key]
        if not hasattr(section, "get"):
            continue
        tmpl_file = section.get("template_file")
        if isinstance(tmpl_file, str) and tmpl_file.startswith(old_prefix):
            section["template_file"] = new_prefix + tmpl_file[len(old_prefix):]
            changed = True

    if not changed:
        return

    try:
        path.write_text(tomlkit.dumps(doc), encoding="utf-8")
        logger.info(
            "Template migration: rewrote template_file paths in %s", path,
        )
    except Exception as exc:  # noqa: BLE001 - log and continue
        logger.warning(
            "Template migration: failed to write %s: %s", path, exc,
        )
