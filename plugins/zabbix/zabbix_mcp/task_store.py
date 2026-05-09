#
# Zabbix MCP Server
# Copyright (C) 2026 initMAX s.r.o.
# Licensed under the GNU Affero General Public License v3.
# See LICENSE for details.
#

"""Bounded in-memory task store for the experimental MCP 2025-11-25 Tasks API.

The upstream ``InMemoryTaskStore`` only does lazy TTL-based cleanup and
treats a missing TTL as "live forever", which on a server hosting
multi-megabyte PDF report payloads is a memory-leak waiting to happen.
This module wraps it with three guard rails:

1. **Default TTL** - if the client did not pass ``task: {ttl: ...}`` we
   substitute :data:`DEFAULT_TTL_MS` (1 hour) so every task has a
   bounded lifetime.
2. **Ceiling** - any TTL larger than :data:`MAX_TTL_MS` (24 hours) is
   capped so a malicious client cannot pin a payload in RAM forever.
3. **Soft cap on concurrent tasks** - once :data:`MAX_LIVE_TASKS` are
   in flight, ``create_task`` raises a clear error rather than letting
   the store grow without limit. The cap is process-wide.

Plus an optional periodic sweeper (:func:`run_periodic_cleanup`) that
forces cleanup every :data:`SWEEP_INTERVAL_S` seconds so the store does
not grow during quiet periods that have no other accesses to trigger
the lazy cleanup.
"""

from __future__ import annotations

import logging

import anyio

from mcp.shared.experimental.tasks.in_memory_task_store import InMemoryTaskStore
from mcp.types import Task, TaskMetadata

logger = logging.getLogger("zabbix_mcp.task_store")

# Defaults, in milliseconds. Overridable from config in the future.
DEFAULT_TTL_MS = 60 * 60 * 1000  # 1 hour
MAX_TTL_MS = 24 * 60 * 60 * 1000  # 24 hours
MAX_LIVE_TASKS = 100
SWEEP_INTERVAL_S = 300  # 5 minutes


class TaskStoreFull(Exception):
    """Raised when ``MAX_LIVE_TASKS`` is exceeded - clients should retry later."""


class BoundedInMemoryTaskStore(InMemoryTaskStore):
    """In-memory task store with TTL bounds and a soft size cap.

    See module docstring for the rationale. Keeps the upstream
    ``InMemoryTaskStore`` semantics intact (lazy cleanup on access,
    pagination, status notifications) and only tightens what was open.
    """

    def __init__(
        self,
        page_size: int = 10,
        *,
        default_ttl_ms: int = DEFAULT_TTL_MS,
        max_ttl_ms: int = MAX_TTL_MS,
        max_live_tasks: int = MAX_LIVE_TASKS,
    ) -> None:
        super().__init__(page_size=page_size)
        self._default_ttl_ms = default_ttl_ms
        self._max_ttl_ms = max_ttl_ms
        self._max_live_tasks = max_live_tasks
        # Cleanup-then-count-then-insert is otherwise racy: two
        # concurrent ``create_task`` calls can both pass the cap check
        # before either inserts, overflowing by one. Serialize the
        # whole atomic section.
        self._create_lock = anyio.Lock()

    async def create_task(self, metadata: TaskMetadata, task_id: str | None = None) -> Task:
        # Tighten TTL: missing -> default; oversized -> cap.
        ttl = metadata.ttl
        if ttl is None:
            ttl = self._default_ttl_ms
        elif ttl > self._max_ttl_ms:
            logger.warning(
                "Client requested TTL %d ms (>%d max), capping",
                ttl, self._max_ttl_ms,
            )
            ttl = self._max_ttl_ms
        if ttl != metadata.ttl:
            metadata = metadata.model_copy(update={"ttl": ttl})

        async with self._create_lock:
            # Sweep before counting so an expired backlog does not push us over.
            self._cleanup_expired()
            if len(self._tasks) >= self._max_live_tasks:
                raise TaskStoreFull(
                    f"Task store is full ({self._max_live_tasks} live tasks). "
                    f"Wait for some to complete or expire and retry."
                )
            return await super().create_task(metadata, task_id)


async def run_periodic_cleanup(store: BoundedInMemoryTaskStore, interval_s: float = SWEEP_INTERVAL_S) -> None:
    """Sweep expired tasks at *interval_s* cadence.

    Lazy cleanup is fine when traffic is steady but a long quiet
    period can leave a finished report's payload in RAM well past its
    TTL. Spawn this as a background task on the same task group that
    runs the MCP server.
    """
    while True:
        try:
            await anyio.sleep(interval_s)
            before = len(store._tasks)
            store._cleanup_expired()
            removed = before - len(store._tasks)
            if removed:
                logger.info("Periodic cleanup removed %d expired task(s)", removed)
        except Exception:
            logger.exception("Periodic task cleanup raised; continuing")
