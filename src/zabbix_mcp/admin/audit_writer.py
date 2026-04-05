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

"""Audit log writer — appends JSON entries to the audit log file."""

import json
import os
import time
from pathlib import Path

AUDIT_LOG_PATH = Path("/var/log/zabbix-mcp/audit.log")

MAX_AUDIT_SIZE = 50 * 1024 * 1024  # 50 MB


def _rotate_audit_log(path: Path) -> None:
    """Simple audit log rotation."""
    backup = str(path) + ".1"
    old_backup = str(path) + ".2"
    if os.path.exists(old_backup):
        os.unlink(old_backup)
    if os.path.exists(backup):
        os.rename(backup, old_backup)
    os.rename(str(path), backup)


def write_audit(
    action: str,
    user: str = "",
    target_type: str = "",
    target_id: str = "",
    details: dict | None = None,
    ip: str = "",
) -> None:
    """Append a single audit entry as a JSON line."""
    entry = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "action": action,
        "user": user,
        "target_type": target_type,
        "target_id": target_id,
        "details": details or {},
        "ip": ip,
    }
    try:
        AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        # Rotate if audit log exceeds size limit
        if AUDIT_LOG_PATH.exists() and AUDIT_LOG_PATH.stat().st_size > MAX_AUDIT_SIZE:
            try:
                _rotate_audit_log(AUDIT_LOG_PATH)
            except OSError:
                pass
        with open(AUDIT_LOG_PATH, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        import logging
        logging.getLogger("zabbix_mcp.admin").warning("Failed to write audit log: %s", e)
