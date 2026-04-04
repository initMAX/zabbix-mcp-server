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
import time
from pathlib import Path

AUDIT_LOG_PATH = Path("/var/log/zabbix-mcp/audit.log")


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
        with open(AUDIT_LOG_PATH, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass
