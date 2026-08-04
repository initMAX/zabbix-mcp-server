#
# Zabbix MCP Server
# Copyright (C) 2026 initMAX s.r.o.
# Licensed under the GNU Affero General Public License v3.
# See LICENSE for details.
#

"""Bounded in-memory task store + the official MCP tasks extension.

MCP 2026-07-28 moved tasks out of the core protocol into the
``io.modelcontextprotocol/tasks`` extension. SDK 2.0 dropped the
experimental ``InMemoryTaskStore`` / ``enable_tasks`` machinery, so this
module now owns the whole feature:

* :class:`BoundedInMemoryTaskStore` - self-contained storage with the
  same guard rails the 1.x wrapper enforced: default TTL (1 h) when the
  client omits one, a 24 h ceiling so a payload cannot be pinned in RAM
  forever, and a soft cap on live tasks with a clear retryable error.
* :class:`ZmcpTasksExtension` - an ``mcp.server.extension.Extension``
  that (a) intercepts ``tools/call`` for task-augmented tools invoked
  with ``task: {...}``, runs the real handler in the background and
  returns ``CreateTaskResult`` immediately, and (b) serves ``tasks/get``
  (poll), ``tasks/result`` (payload) and ``tasks/cancel``. ``tasks/list``
  is gone per the 2026-07-28 redesign.

The periodic sweeper (:func:`run_periodic_cleanup`) is unchanged in
spirit: it forces cleanup during quiet periods that would otherwise not
trigger the lazy sweep.
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field

import anyio

from mcp.types import (
    CallToolResult,
    CancelTaskRequestParams,
    CancelTaskResult,
    CreateTaskResult,
    GetTaskRequestParams,
    GetTaskResult,
    GetTaskPayloadRequestParams,
    Task,
    TaskMetadata,
    TextContent,
)

logger = logging.getLogger("zabbix_mcp.task_store")

# Defaults, in milliseconds. Overridable from config in the future.
DEFAULT_TTL_MS = 60 * 60 * 1000  # 1 hour
MAX_TTL_MS = 24 * 60 * 60 * 1000  # 24 hours
MAX_LIVE_TASKS = 100
SWEEP_INTERVAL_S = 300  # 5 minutes
POLL_INTERVAL_MS = 2000  # suggested client poll cadence


class TaskStoreFull(Exception):
    """Raised when ``MAX_LIVE_TASKS`` is exceeded - clients should retry later."""


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


@dataclass
class _Entry:
    task: Task
    expires_at_monotonic: float
    payload: CallToolResult | None = None
    cancel_scope: anyio.CancelScope | None = field(default=None, repr=False)


class BoundedInMemoryTaskStore:
    """In-memory task store with TTL bounds and a soft size cap.

    Self-contained since SDK 2.0 removed the experimental upstream
    store. Lazy cleanup on access + the periodic sweeper keep RAM
    bounded; ``create_task`` is serialized so two concurrent calls
    cannot both pass the cap check and overflow by one.
    """

    def __init__(
        self,
        *,
        default_ttl_ms: int = DEFAULT_TTL_MS,
        max_ttl_ms: int = MAX_TTL_MS,
        max_live_tasks: int = MAX_LIVE_TASKS,
    ) -> None:
        self._default_ttl_ms = default_ttl_ms
        self._max_ttl_ms = max_ttl_ms
        self._max_live_tasks = max_live_tasks
        self._tasks: dict[str, _Entry] = {}
        self._create_lock = anyio.Lock()

    # -- storage primitives -------------------------------------------------

    def _cleanup_expired(self) -> None:
        now = time.monotonic()
        for tid in [t for t, e in self._tasks.items() if e.expires_at_monotonic <= now]:
            del self._tasks[tid]

    async def create_task(self, metadata: TaskMetadata, task_id: str | None = None) -> Task:
        ttl = metadata.ttl
        if ttl is None:
            ttl = self._default_ttl_ms
        elif ttl > self._max_ttl_ms:
            logger.warning(
                "Client requested TTL %d ms (>%d max), capping", ttl, self._max_ttl_ms,
            )
            ttl = self._max_ttl_ms

        async with self._create_lock:
            self._cleanup_expired()
            if len(self._tasks) >= self._max_live_tasks:
                raise TaskStoreFull(
                    f"Task store is full ({self._max_live_tasks} live tasks). "
                    f"Wait for some to complete or expire and retry."
                )
            now_iso = _now_iso()
            task = Task(
                task_id=task_id or uuid.uuid4().hex,
                status="working",
                created_at=now_iso,
                last_updated_at=now_iso,
                ttl=ttl,
                poll_interval=POLL_INTERVAL_MS,
            )
            self._tasks[task.task_id] = _Entry(
                task=task,
                expires_at_monotonic=time.monotonic() + ttl / 1000.0,
            )
            return task

    def get_entry(self, task_id: str) -> _Entry | None:
        self._cleanup_expired()
        return self._tasks.get(task_id)

    def _touch(self, entry: _Entry, status: str, message: str | None = None) -> None:
        entry.task = entry.task.model_copy(update={
            "status": status,
            "status_message": message,
            "last_updated_at": _now_iso(),
        })

    def complete(self, task_id: str, payload: CallToolResult) -> None:
        entry = self._tasks.get(task_id)
        if entry is None:
            return
        entry.payload = payload
        self._touch(entry, "completed")

    def fail(self, task_id: str, message: str) -> None:
        entry = self._tasks.get(task_id)
        if entry is None:
            return
        entry.payload = CallToolResult(
            content=[TextContent(type="text", text=message)], is_error=True)
        self._touch(entry, "failed", message)

    def cancel(self, task_id: str) -> bool:
        entry = self._tasks.get(task_id)
        if entry is None or entry.task.status not in ("working", "input_required"):
            return False
        if entry.cancel_scope is not None:
            entry.cancel_scope.cancel()
        self._touch(entry, "cancelled")
        return True


class ZmcpTasksExtension:
    """``io.modelcontextprotocol/tasks`` extension for SDK 2.0.

    Built lazily (see :func:`build_tasks_extension`) so importing this
    module does not require the extension framework at import time.
    """


def build_tasks_extension(store: BoundedInMemoryTaskStore, task_augmented_tools: set[str]):
    """Return an ``Extension`` instance serving the tasks methods.

    ``task_augmented_tools`` limits which tools may be invoked in task
    mode (currently ``report_generate``); a task request on any other
    tool falls through to the normal synchronous path, mirroring the
    1.x behaviour where only advertised tools carried
    ``execution.taskSupport``.
    """
    from mcp.server.extension import Extension, MethodBinding

    class _TasksExtension(Extension):
        identifier = "io.modelcontextprotocol/tasks"

        async def intercept_tool_call(self, params, ctx, call_next):
            if params.task is None or params.name not in task_augmented_tools:
                return await call_next(ctx)

            metadata = params.task if isinstance(params.task, TaskMetadata) else TaskMetadata(
                ttl=getattr(params.task, "ttl", None))
            try:
                task = await store.create_task(metadata)
            except TaskStoreFull as exc:
                return CallToolResult(
                    content=[TextContent(type="text", text=str(exc))], is_error=True)

            entry = store.get_entry(task.task_id)

            async def _run_in_background() -> None:
                with anyio.CancelScope() as scope:
                    if entry is not None:
                        entry.cancel_scope = scope
                    try:
                        result = await call_next(ctx)
                        if isinstance(result, CallToolResult):
                            store.complete(task.task_id, result)
                        else:
                            store.complete(task.task_id, CallToolResult(
                                content=[TextContent(type="text", text=str(result))]))
                    except Exception as exc:  # noqa: BLE001 - task boundary
                        logger.exception("Task %s failed", task.task_id)
                        store.fail(task.task_id, f"Task failed: {exc}")

            import asyncio
            asyncio.get_running_loop().create_task(_run_in_background())
            # The 2026-07-28 wire surface for tools/call admits only
            # CallToolResult | InputRequiredResult - extension data rides
            # in _meta under the extension identifier. Returning the
            # legacy top-level CreateTaskResult fails serialization.
            return CallToolResult(
                content=[TextContent(
                    type="text",
                    text=(
                        f"Task {task.task_id} accepted. Poll tasks/get with "
                        f"taskId={task.task_id} until status=completed, then "
                        f"fetch the payload via tasks/result."
                    ),
                )],
                meta={
                    "io.modelcontextprotocol/tasks": CreateTaskResult(
                        task=task
                    ).model_dump(by_alias=True, exclude_none=True)["task"],
                },
            )

        def methods(self):
            async def _get(ctx, params: GetTaskRequestParams):
                entry = store.get_entry(params.task_id)
                if entry is None:
                    raise ValueError(f"Unknown or expired task: {params.task_id}")
                t = entry.task
                return GetTaskResult(
                    task_id=t.task_id, status=t.status,
                    status_message=t.status_message, created_at=t.created_at,
                    last_updated_at=t.last_updated_at, ttl=t.ttl,
                    poll_interval=t.poll_interval,
                )

            async def _result(ctx, params: GetTaskPayloadRequestParams):
                entry = store.get_entry(params.task_id)
                if entry is None:
                    raise ValueError(f"Unknown or expired task: {params.task_id}")
                if entry.payload is None:
                    raise ValueError(
                        f"Task {params.task_id} is still {entry.task.status}; "
                        f"poll tasks/get until it completes")
                return entry.payload

            async def _cancel(ctx, params: CancelTaskRequestParams):
                if not store.cancel(params.task_id):
                    raise ValueError(
                        f"Task {params.task_id} cannot be cancelled "
                        f"(unknown, expired, or already finished)")
                t = store.get_entry(params.task_id).task
                return CancelTaskResult(
                    task_id=t.task_id, status=t.status,
                    status_message=t.status_message, created_at=t.created_at,
                    last_updated_at=t.last_updated_at, ttl=t.ttl,
                    poll_interval=t.poll_interval,
                )

            return (
                MethodBinding(method="tasks/get", params_type=GetTaskRequestParams, handler=_get),
                MethodBinding(method="tasks/result", params_type=GetTaskPayloadRequestParams, handler=_result),
                MethodBinding(method="tasks/cancel", params_type=CancelTaskRequestParams, handler=_cancel),
            )

    return _TasksExtension()


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
