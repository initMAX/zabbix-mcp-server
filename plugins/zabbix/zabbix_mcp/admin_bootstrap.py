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

"""First-run admin user bootstrap.

On host installs, ``deploy/install.sh`` runs a ``setup_admin`` step that
auto-generates a random admin password, scrypt-hashes it, and writes
``[admin.users.admin]`` into ``config.toml`` before starting the service.
Container deployments do not use the installer, so without this module a
fresh container starts the admin portal with an empty ``[admin.users]``
table - the login page is reachable but every attempt fails, leaving the
operator locked out.

This module mirrors the installer's behaviour at server startup. It is
idempotent (no-op if any admin user already exists or if the admin portal
is disabled) and non-fatal: any failure is logged and the server
continues to start. The generated password is logged prominently at
WARNING level so the operator can fish it out of ``podman logs`` /
``docker logs`` on first launch.
"""

from __future__ import annotations

import logging
import secrets
import string
import sys
from pathlib import Path

logger = logging.getLogger(__name__)

_ADMIN_USERNAME = "admin"
_PASSWORD_LENGTH = 16


def bootstrap_admin_if_needed(config_path: Path | str | None) -> None:
    """Create a first-run admin user if the admin portal is enabled but no
    users exist yet.

    Safe to run on every startup: no-op on host installs (where
    ``install.sh setup_admin`` already wrote the admin user) and on
    subsequent container restarts (once the first-run user is in place).
    """
    try:
        _bootstrap(config_path)
    except Exception as exc:  # noqa: BLE001 - never break startup
        logger.warning(
            "Admin portal bootstrap failed (non-fatal, continuing startup): %s",
            exc,
        )


def _bootstrap(config_path: Path | str | None) -> None:
    if not config_path:
        logger.debug("Admin bootstrap: no config_path, skipping")
        return

    try:
        from zabbix_mcp.admin.config_writer import (
            load_config_document,
            save_config_document,
            TOMLKIT_AVAILABLE,
        )
    except ImportError:
        logger.debug("Admin bootstrap: admin.config_writer unavailable, skipping")
        return

    if not TOMLKIT_AVAILABLE:
        logger.warning(
            "Admin bootstrap: tomlkit not available, cannot auto-create admin user. "
            "Install tomlkit or set [admin.users.admin] manually in config.toml."
        )
        return

    import tomlkit

    path = Path(config_path)
    if not path.is_file():
        logger.debug("Admin bootstrap: %s is not a file, skipping", path)
        return

    try:
        doc = load_config_document(path)
    except Exception as exc:  # noqa: BLE001 - log and skip
        logger.warning("Admin bootstrap: failed to load %s: %s", path, exc)
        return

    admin_section = doc.get("admin")
    if admin_section is None:
        logger.debug("Admin bootstrap: no [admin] section, skipping")
        return

    if not admin_section.get("enabled", False):
        logger.debug("Admin bootstrap: admin.enabled = false, skipping")
        return

    existing_users = admin_section.get("users")
    if existing_users and len(existing_users) > 0:
        # Any user already present -> nothing to do. Idempotent on
        # container restarts and safe for host installs.
        logger.debug(
            "Admin bootstrap: %d user(s) already configured, skipping",
            len(existing_users),
        )
        return

    # Generate password + hash (reuse the canonical scrypt helper).
    from zabbix_mcp.admin.auth import hash_password
    password = _generate_password()
    password_hash = hash_password(password)

    # Build [admin.users.admin] table and write it back.
    if "users" not in admin_section:
        admin_section["users"] = tomlkit.table(is_super_table=True)

    user_table = tomlkit.table()
    user_table["password_hash"] = password_hash
    user_table["role"] = "admin"
    admin_section["users"][_ADMIN_USERNAME] = user_table

    try:
        save_config_document(path, doc)
    except Exception as exc:  # noqa: BLE001 - log and continue
        logger.error(
            "Admin bootstrap: failed to write %s: %s. The admin portal will be "
            "unreachable until you add [admin.users.admin] manually.",
            path, exc,
        )
        return

    # Print the credentials prominently. We write directly to stderr as well
    # as logging, because the configured log_file might send logger output to
    # a file (e.g. /var/log/zabbix-mcp/server.log inside a container), in
    # which case operators running `podman logs` / `docker logs` would not
    # see the banner. Writing to stderr guarantees visibility in both
    # container log streams and systemd journalctl.
    banner = "=" * 70
    lines = [
        banner,
        "ADMIN PORTAL FIRST-RUN BOOTSTRAP",
        "",
        f"  Username: {_ADMIN_USERNAME}",
        f"  Password: {password}",
        "",
        "CHANGE THIS PASSWORD on first login via the admin portal",
        "(/ -> user menu -> change password) or by editing",
        f"[admin.users.admin] in {path} directly.",
        banner,
    ]
    for line in lines:
        logger.warning(line)
    # Also write to stderr so the banner shows up in `podman logs` / stdio
    # transports even when log_file is set.
    try:
        sys.stderr.write("\n" + "\n".join(lines) + "\n\n")
        sys.stderr.flush()
    except Exception:
        pass


def _generate_password() -> str:
    """Generate a cryptographically random password."""
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(_PASSWORD_LENGTH))
