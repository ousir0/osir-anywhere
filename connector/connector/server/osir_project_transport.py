"""Ordered HTTP delivery for the opt-in project bridge; no credential discovery.

The caller owns authorization, history capture/versioning, and the HTTP client.
Snapshot completion is an ACK boundary, not a transaction across HTTP pages.
Queued retries provide at-least-once delivery; upserts must remain idempotent.
"""
from __future__ import annotations

import asyncio
import json
import time
from collections import deque
from collections.abc import Callable
from contextlib import AsyncExitStack, asynccontextmanager, contextmanager
from contextvars import ContextVar
from copy import deepcopy
from typing import TYPE_CHECKING, Any

import httpx

from connector.core.config import ConnectorConfig
from connector.server.auth import ConnectorAuthenticationError, ConnectorAuthenticator
from connector.server.errors import ConnectorIngestClosedError, ConnectorNetworkError
from connector.server.ingest import ConnectorIngestClient, ConnectorIngestRejectedError
from connector.server.notification_coalescer import TimelineItemNotificationCoalescer
from connector.server.runtime_rpc_payloads import server_payload_without_turn_data

if TYPE_CHECKING:
    from connector.server.osir_cloud_verification import ExistingDesktopDevice

CLOSE_TIMEOUT_SECONDS = 3.0
DELIVERY_STALL_SECONDS = 30.0
DELIVERY_HEALTH_POLL_SECONDS = 1.0
BATCH_BYTES = 500_000
SNAPSHOT_CHUNK_BYTES = 350_000


class ProjectTransportError(RuntimeError):
    """A safe permanent delivery error; contains no response body or credentials."""


class SnapshotSuperseded(RuntimeError):
    """Local activity overtook this snapshot; recapture on a later history pass."""


def _size(value: Any) -> int:
    return len(json.dumps(value, ensure_ascii=False, separators=(",", ":"),
                          allow_nan=False).encode("utf-8"))


def _batches(notifications: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    rows = []
    for row in notifications:
        if _size({"notifications": [row]}) <= BATCH_BYTES:
            rows.append(row)
            continue
        params = row.get("params", {})
        items = params.get("items")
        if row.get("method") != "timeline.sync" or not isinstance(items, list) or not items:
            raise ProjectTransportError("project notification exceeds batch limit")
        # Account for UTF-8, metadata, and the outer ingest envelope. An item
        # is atomic: splitting message contents would change the protocol.
        parts: list[dict[str, Any]] = []
        part = {**row, "params": {**params, "items": []}}
        part_size = _size({"notifications": [part]})
        for item in items:
            item_size = _size(item)
            added = item_size + bool(part["params"]["items"])
            if part_size + added > SNAPSHOT_CHUNK_BYTES:
                if part["params"]["items"]:
                    parts.append(part)
                    part = {**row, "params": {**params, "complete": False, "items": []}}
                    part_size = _size({"notifications": [part]})
                if part_size + item_size > SNAPSHOT_CHUNK_BYTES:
                    raise ProjectTransportError("project snapshot item exceeds chunk limit")
                added = item_size
            part["params"]["items"].append(item)
            part_size += added
        if part["params"]["items"]:
            parts.append(part)
        rows.extend(parts)

    batches: list[list[dict[str, Any]]] = []
    batch: list[dict[str, Any]] = []
    size = _size({"notifications": []})
    for row in rows:
        added = _size(row) + bool(batch)
        if batch and size + added > BATCH_BYTES:
            batches.append(batch)
            batch, size = [], _size({"notifications": []})
            added = _size(row)
        batch.append(row)
        size += added
    if batch:
        batches.append(batch)
    return batches


def _project(method: str, params: dict[str, Any]) -> dict[str, Any]:
    # Host explicitly retains turnId on this one lifecycle notification.
    if method == "session.turnEnded":
        return deepcopy(params)
    return server_payload_without_turn_data(params)


class _ProjectIngest(ConnectorIngestClient):
    def __init__(self, owner: ProjectTransport, client: httpx.AsyncClient, origin: str):
        self._owner = owner
        self._snapshot_uploads = 0
        super().__init__(origin, owner.token, lambda: client, lambda timeout: client)

    @property
    def has_pending(self) -> bool:
        # Keep F06's ACK watchdog active between pages and while awaiting the
        # socket lock; _posting alone only covers the current lock holder.
        return bool(self._snapshot_uploads) or super().has_pending

    def close(self, error: Exception | None = None) -> None:
        super().close(error)
        self._available.set()

    async def post_snapshot(self, notifications: list[dict[str, Any]], *, activity_revision: int):
        self._snapshot_uploads += 1
        try:
            # Split inside the first socket gate, retaining the existing
            # permanent-error handling for invalid/oversized notifications.
            pages = None
            first = True
            while True:
                async with self._post_lock:
                    self._posting = True
                    try:
                        self._owner._check_open()
                        # B can enqueue while A awaits a page ACK. Drain the
                        # bounded queue prefix before A's next page even when
                        # the worker is still in its coalescing sleep.
                        await self._drain_pending(None)
                        self._owner._check_open()
                        if first:
                            if self._owner.activity_revision != activity_revision:
                                raise SnapshotSuperseded("project snapshot superseded by local activity")
                            pages = deque(self._snapshot_batches(notifications))
                            first = False
                        if not pages:
                            return
                        await self._post_batch(pages.popleft())
                        self._owner._check_open()
                        if not pages:
                            return
                    finally:
                        self._posting = False
                # Yield even if MockTransport or cached auth completes inline.
                # Session admission stays held, so A's live cannot interleave.
                await asyncio.sleep(0)
        finally:
            self._snapshot_uploads -= 1
            if not self.has_pending and self._closed is None:
                self._available.clear()

    def _snapshot_batches(self, notifications):
        try:
            return _batches(notifications)
        except ProjectTransportError:
            safe = ProjectTransportError("project ingest permanently rejected")
            self._owner._fail(safe)
            raise safe from None

    async def _post_batch(self, notifications, *, on_progress=None):
        self._owner._check_failure()
        if self._closed is not None:
            raise self._closed
        try:
            # The post lock serializes each HTTP write. The base queued worker
            # retries the entire inflight list on transient failure, including
            # earlier acknowledged chunks: at-least-once, idempotent upserts.
            for batch in _batches(notifications):
                await super()._post_batch(batch, on_progress=on_progress)
                self._owner._last_delivery_progress = time.monotonic()
        except ConnectorNetworkError:
            # The base retry loop logs this string; never retain raw HTTP data.
            raise ConnectorNetworkError("project ingest temporarily unavailable") from None
        except (ConnectorAuthenticationError, ConnectorIngestRejectedError,
                httpx.HTTPStatusError, ProjectTransportError) as exc:
            if isinstance(exc, ConnectorAuthenticationError):
                safe = ConnectorAuthenticationError("project connector authorization rejected")
            else:
                safe = ProjectTransportError("project ingest permanently rejected")
            # A distinct error type avoids the base worker's permanent-error
            # swallow branch. Closing also wakes an otherwise idle worker.
            self._owner._fail(safe)
            raise safe from None

    async def _post_ingest_batch(self, client, access_token, notifications, *, on_progress=None):
        started, status = time.monotonic(), "network_error"
        try:
            response = await super()._post_ingest_batch(
                client, access_token, notifications, on_progress=on_progress)
            status = response.status_code
            return response
        finally:
            self._owner._emit("project-ingest-batch", count=len(notifications),
                              elapsedMs=round((time.monotonic() - started) * 1000),
                              status=status)


class _ProjectAuthenticator(ConnectorAuthenticator):
    def __init__(self, owner: ProjectTransport, config: ConnectorConfig, client: httpx.AsyncClient):
        self._owner = owner
        super().__init__(config, lambda: client, lambda timeout: client)

    async def authenticate(self) -> str:
        started, status = time.monotonic(), "failed"
        try:
            token = await super().authenticate()
            status = "ok"
            return token
        except ConnectorAuthenticationError:
            safe = ConnectorAuthenticationError("project connector authorization rejected")
            self._owner._fail(safe)
            raise safe from None
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code in {408, 429} or exc.response.status_code >= 500:
                raise ConnectorNetworkError("project authentication temporarily unavailable") from None
            safe = ProjectTransportError("project connector authentication rejected")
            self._owner._fail(safe)
            raise safe from None
        except ConnectorNetworkError:
            raise ConnectorNetworkError("project authentication temporarily unavailable") from None
        except (KeyError, ValueError, TypeError, RuntimeError):
            safe = ProjectTransportError("project connector authentication response invalid")
            self._owner._fail(safe)
            raise safe from None
        finally:
            self._owner._emit("project-auth-refresh", status=status,
                              elapsedMs=round((time.monotonic() - started) * 1000))


class ProjectTransport:
    """Per-connection transport. No tokens, payloads or IDs are emitted.

    notify() applies bounded queue backpressure and waits behind its session's
    snapshot ACKs. Other sessions may send between snapshot pages. One slow
    HTTP write still occupies the shared socket lock until ACK/failure/timeout.
    snapshot() flushes prior live output and returns only after all page ACKs.
    New activity before its upload gate raises nonfatal SnapshotSuperseded;
    same-session activity during upload is admitted after the snapshot finishes.
    run() is a single supervised worker; cancel it before calling close().
    close() independently drains for at most three seconds, then discards the
    remaining in-memory data. The caller must not commit unacknowledged history.
    """

    def __init__(self, *, client: httpx.AsyncClient, device: ExistingDesktopDevice,
                 origin: str, emit: Callable[..., None] | None = None):
        self._report = emit
        self._failure: Exception | None = None
        self._closing = False
        self._closed = False
        self._running = False
        self._close_lock = asyncio.Lock()
        self._admission_locks: dict[str | None, tuple[asyncio.Lock, int]] = {}
        self._snapshot_tasks: set[asyncio.Task[None]] = set()
        self._activity_revision = 0
        self._last_delivery_progress: float | None = None
        self._snapshot_revision: ContextVar[int | None] = ContextVar(
            "project_snapshot_revision", default=None)
        config = ConnectorConfig(server_url=origin, connector_id=device.connector_id,
                                 connector_token=device.token, sync_existing_on_connect=False)
        self._auth = _ProjectAuthenticator(self, config, client)
        self._ingest = _ProjectIngest(self, client, origin)
        self._coalescer = TimelineItemNotificationCoalescer(self._enqueue)

    def _emit(self, event: str, **fields: Any) -> None:
        if self._report is not None:
            try:
                self._report(event, **fields)
            except Exception:  # noqa: BLE001, S110 - best-effort metrics never affect delivery
                pass  # Metrics must not change delivery or expose exceptions.

    def _check_failure(self) -> None:
        if self._failure is not None:
            raise self._failure

    @property
    def activity_revision(self) -> int:
        """Local admission counter only; never included in server payloads."""
        return self._activity_revision

    def _check_open(self) -> None:
        self._check_failure()
        if self._closing or self._closed:
            raise ConnectorIngestClosedError("project transport is closed")

    def _fail(self, error: Exception) -> None:
        if self._failure is None:
            self._failure = error
        self._ingest.close(self._failure)

    async def authenticate(self) -> str:
        self._check_open()
        return await self.token(force=True)

    async def token(self, force: bool = False) -> str:
        self._check_failure()
        if self._closed:
            raise ConnectorIngestClosedError("project transport is closed")
        return await self._auth.ensure_access_token(force=force)

    async def _enqueue(self, method: str, params: dict[str, Any]) -> None:
        self._check_failure()
        await self._ingest.enqueue(method, params)

    @asynccontextmanager
    async def _admit(self, session_ids: set[str | None]):
        # Reserve all entries before awaiting; concurrent holders/waiters keep
        # the same lock alive. Sorted acquisition also supports multi-session
        # snapshots without deadlock. Missing IDs share one fallback lane.
        entries = []
        for session_id in sorted(session_ids, key=lambda value: value or ""):
            lock, users = self._admission_locks.get(session_id, (asyncio.Lock(), 0))
            self._admission_locks[session_id] = (lock, users + 1)
            entries.append((session_id, lock))
        try:
            async with AsyncExitStack() as stack:
                for _, lock in entries:
                    await stack.enter_async_context(lock)
                yield
        finally:
            for session_id, lock in entries:
                _, users = self._admission_locks[session_id]
                if users == 1:
                    del self._admission_locks[session_id]
                else:
                    self._admission_locks[session_id] = (lock, users - 1)

    async def notify(self, method: str, params: dict[str, Any]) -> None:
        self._check_open()
        # No await before this increment: a producer waiting for admission
        # must invalidate an older snapshot even before it can enqueue.
        self._activity_revision += 1
        projected = _project(method, params)
        async with self._admit({_session_id(projected)}):
            self._check_open()
            await self._coalescer.send(method, projected)

    @contextmanager
    def capture_snapshot(self):
        """Pin admission before reading history, isolated to this task/context."""
        self._check_open()
        token = self._snapshot_revision.set(self.activity_revision)
        try:
            yield
        finally:
            self._snapshot_revision.reset(token)

    async def snapshot(self, notifications: list[dict[str, Any]]) -> None:
        self._check_open()
        captured = self._snapshot_revision.get()
        activity_revision = self.activity_revision if captured is None else captured
        projected = [{"method": row["method"], "params": _project(row["method"], row["params"])}
                     for row in notifications]
        session_ids = {_session_id(row["params"]) for row in projected}
        # Hold every affected session across flush and all page ACKs. Empty
        # snapshots remain a flush barrier without blocking unrelated notify.
        async with self._admit(session_ids):
            self._check_open()
            if not projected or None in session_ids:
                await self._coalescer.close()
            else:
                for session_id in sorted(session_ids):
                    await self._coalescer.flush(session_id)
            task = asyncio.create_task(self._ingest.post_snapshot(
                projected, activity_revision=activity_revision))
            self._snapshot_tasks.add(task)
            try:
                await task
            finally:
                self._snapshot_tasks.discard(task)

    async def run(self) -> None:
        self._check_open()
        if self._running:
            raise RuntimeError("project transport worker already running")
        self._running = True
        worker = asyncio.create_task(self._ingest.flush_loop())
        health = asyncio.create_task(self._watch_delivery())
        try:
            done, _ = await asyncio.wait({worker, health}, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                task.result()
        except ConnectorIngestClosedError:
            if not self._closing:
                raise
        finally:
            worker.cancel()
            health.cancel()
            await asyncio.gather(worker, health, return_exceptions=True)
            self._running = False

    async def _watch_delivery(self) -> None:
        """A live WebSocket must not conceal a stalled HTTP data path.

        This stops the connection visibly; it never retries a turn/start RPC.
        History checkpoints still require ACK, so a reconnect can recapture.
        Successful chunks refresh the budget during a large snapshot upload.
        """
        while True:
            await asyncio.sleep(DELIVERY_HEALTH_POLL_SECONDS)
            self._check_failure()
            if not self._ingest.has_pending:
                self._last_delivery_progress = None
                continue
            now = time.monotonic()
            if self._last_delivery_progress is None:
                self._last_delivery_progress = now
            elif now - self._last_delivery_progress >= DELIVERY_STALL_SECONDS:
                error = ProjectTransportError('project delivery stalled; reconnect required')
                self._emit('project-delivery-stalled', budgetSeconds=DELIVERY_STALL_SECONDS)
                self._fail(error)
                raise error

    async def close(self) -> None:
        if self._closed:
            return
        self._closing = True
        try:
            async with asyncio.timeout(CLOSE_TIMEOUT_SECONDS):
                async with self._close_lock:
                    if self._closed:
                        return
                    if self._failure is None:
                        await self._coalescer.close()
                        await self._ingest.post_batch([])
        except (TimeoutError, ConnectorNetworkError, ConnectorAuthenticationError,
                ProjectTransportError, ConnectorIngestClosedError):
            pass  # Shutdown is bounded; permanent failures are never replayed.
        finally:
            self._ingest.close(self._failure)
            tasks = list(self._snapshot_tasks)
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await self._coalescer.abort()
            self._closed = True


def _session_id(params: dict[str, Any]) -> str | None:
    value = params.get("sessionId")
    return value if isinstance(value, str) and value else None
