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

"""Short-lived store backing ``zabbix://reports/<id>`` resource links.

The point of a resource link is that the PDF does **not** travel through
the model's context: the tool answers with a pointer, and the client
fetches the bytes over ``resources/read`` only if the user actually
wants the document. That needs somewhere to park the payload between
the two calls - this module, with the same guard rails as the task
store: a TTL so nothing lingers, and a cap so a runaway client cannot
pin memory.
"""

from __future__ import annotations

import logging
import threading
import time
import uuid

logger = logging.getLogger("zabbix_mcp.reporting.store")

DEFAULT_TTL_S = 3600          # 1 hour: long enough to click, short enough to forget
MAX_REPORTS = 20              # ~20 x a few hundred kB worst case
URI_PREFIX = "zabbix://reports/"


class ReportStore:
    """In-memory, TTL-bounded store of generated PDFs."""

    def __init__(self, ttl_s: int = DEFAULT_TTL_S, max_reports: int = MAX_REPORTS) -> None:
        self._ttl_s = ttl_s
        self._max = max_reports
        self._lock = threading.Lock()
        # report_id -> (pdf_bytes, filename, expires_at_monotonic)
        self._items: dict[str, tuple[bytes, str, float]] = {}

    def _sweep_locked(self) -> None:
        now = time.monotonic()
        for rid in [r for r, (_, _, exp) in self._items.items() if exp <= now]:
            del self._items[rid]

    def put(self, pdf_bytes: bytes, filename: str) -> str:
        """Store *pdf_bytes* and return the report id."""
        with self._lock:
            self._sweep_locked()
            # Oldest-out rather than refusing: a stale report nobody
            # fetched matters less than the one just generated.
            while len(self._items) >= self._max:
                oldest = min(self._items, key=lambda r: self._items[r][2])
                del self._items[oldest]
            rid = uuid.uuid4().hex
            self._items[rid] = (pdf_bytes, filename, time.monotonic() + self._ttl_s)
            logger.info("Stored report %s (%s, %d bytes), ttl %ds",
                        rid, filename, len(pdf_bytes), self._ttl_s)
            return rid

    def get(self, report_id: str) -> tuple[bytes, str] | None:
        """Return (pdf_bytes, filename) or None when unknown/expired."""
        with self._lock:
            self._sweep_locked()
            item = self._items.get(report_id)
            return (item[0], item[1]) if item else None

    def uri(self, report_id: str) -> str:
        return f"{URI_PREFIX}{report_id}"

    def __len__(self) -> int:
        with self._lock:
            self._sweep_locked()
            return len(self._items)
