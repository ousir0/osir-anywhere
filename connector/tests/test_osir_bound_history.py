"""Bound history regression: temporary workspaces and SDK-shaped fakes only."""
import asyncio
import inspect
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from openai_codex import AsyncCodex, JsonRpcError, TransportClosedError
from openai_codex.generated.v2_all import (
    AbsolutePathBuf,
    Thread,
    ThreadListParams,
    ThreadListResponse,
)

from connector.runtime_protocol import RuntimeInvalidRequestError
from connector.runtimes.codex.osir_binding import ModelBindingUnavailable
from connector.runtimes.codex.osir_bound_client import BoundCodexClient
from connector.runtimes.codex.sdk.client import CodexSdkClient
from connector.runtimes.codex.sdk.runtime_client import (
    CodexStartThreadRequest,
    CodexThreadListResult,
    CodexThreadReadResult,
    CodexThreadResult,
)
from connector.runtimes.codex.sessions.inventory import list_all_codex_threads
from tests.test_osir_bound_provider import Native
from tests.test_osir_bound_provider import fixture as fixture  # noqa: PLC0414


def row(fixture, identifier, cwd=None):
    return {"id": identifier, "cwd": str(cwd or fixture.workspace),
            "path": str(fixture.home / "sessions" / (identifier + ".jsonl"))}


class SdkHistory(Native):
    """Exercise the real SDK adapter and generated response models, no subprocess."""
    def __init__(self, fixture, count=4, delay=0):
        super().__init__()
        self.rows = {}
        self.archived = set()
        self.calls = []
        self.reads = 0
        self.inflight = 0
        self.peak = 0
        self.delay = delay
        self._client = SimpleNamespace(request=self.request)
        # The adapter calls the high-level AsyncCodex keyword interface.
        self.thread_list = self.list_native
        for index in range(count):
            identifier = f"history-{index}"
            self.rows[identifier] = Thread.model_validate({**row(fixture, identifier),
                "cliVersion": "synthetic", "createdAt": 1, "ephemeral": False,
                "modelProvider": "local", "preview": "synthetic", "sessionId": identifier,
                "source": "appServer", "status": {"type": "notLoaded"}, "historyMode": "legacy",
                "turns": [], "updatedAt": 2})
            if index % 7 == 0:
                self.archived.add(identifier)

    async def list_native(self, **kwargs):
        # Bind against the installed SDK's real callable and generated params.
        inspect.signature(AsyncCodex.thread_list).bind(self, **kwargs)
        params = ThreadListParams.model_validate(kwargs)
        self.calls.append(kwargs)
        archived = bool(params.archived)
        prefix = f"opaque:{archived}:" + "x" * 300 + ":"
        if params.cursor is not None:
            assert params.cursor.startswith(prefix)
        start = int(params.cursor[len(prefix):]) if params.cursor else 0
        selected = [r for r in self.rows.values() if (r.id in self.archived) is archived]
        page = selected[start:start + params.limit]
        end = start + len(page)
        return ThreadListResponse(data=page, nextCursor=prefix + str(end) if end < len(selected) else None)

    async def request(self, method, params, response_model):
        assert method == "thread/read" and params["includeTurns"] is False
        self.reads += 1
        self.inflight += 1
        self.peak = max(self.peak, self.inflight)
        try:
            await asyncio.sleep(self.delay)
            return response_model.model_validate({"thread": self.rows[params["threadId"]].model_dump(by_alias=True)})
        finally:
            self.inflight -= 1


def test_sdk_archive_filter_and_opaque_cursor_without_thread_archive_field(fixture):
    async def run():
        native = SdkHistory(fixture)
        client = BoundCodexClient(CodexSdkClient(native), fixture.reader(), fixture.store)
        await client.start(AsyncMock())
        try:
            assert "archived" not in Thread.model_fields
            page = await client.list_threads(limit=1, archived=False)
            assert [r["id"] for r in page.threads] == ["history-1"]
            assert len(page.next_cursor) > 256
            following = await client.list_threads(limit=1, cursor=page.next_cursor, archived=False)
            assert [r["id"] for r in following.threads] == ["history-2"]
            assert native.calls[-1]["cursor"] == page.next_cursor
            archived = await client.list_threads(archived=True)
            assert [r["id"] for r in archived.threads] == ["history-0"]
            default = await client.list_threads()
            assert {r["id"] for r in default.threads} == {"history-1", "history-2", "history-3"}
            assert "archived" not in native.calls[-1]
        finally:
            await client.stop()
    asyncio.run(run())


def test_1293_threads_42_projects_paginate_with_bounded_reads_and_restart(fixture):
    async def run():
        native = SdkHistory(fixture, count=1293, delay=0.005)
        projects = [fixture.workspace / str(index) for index in range(42)]
        for project in projects:
            project.mkdir()
        for index, thread in enumerate(native.rows.values()):
            thread.cwd = AbsolutePathBuf(str(projects[index % 42]))
        client = BoundCodexClient(CodexSdkClient(native), fixture.reader(), fixture.store)
        await client.start(AsyncMock())
        started = time.perf_counter()
        try:
            active = await list_all_codex_threads(client, archived=False, page_size=100)
            archived = await list_all_codex_threads(client, archived=True, page_size=100)
            elapsed = time.perf_counter() - started
            combined = (*active, *archived)
            assert len(active) == 1108 and len(archived) == 185
            assert len({r["id"] for r in combined}) == 1293
            assert len({r["cwd"] for r in combined}) == 42
            assert len(native.calls) == 14 and native.reads == 1293
            assert 1 < native.peak <= 8 and native.inflight == 0
            assert len(fixture.store.get(client._key)["threads"]) == 1293
            print(f"\nSYNTHETIC history: 1293 threads/42 projects, 14 pages, "
                  f"5ms/read, peak={native.peak}, elapsed={elapsed:.3f}s "
                  f"(serial read waits alone >=6.465s; not native product timing)")
        finally:
            await client.stop()
        restarted = BoundCodexClient(Native(), fixture.reader(), fixture.store)
        await restarted.start(AsyncMock())
        assert len(restarted._threads) == 1293
        await restarted.stop()
    asyncio.run(run())


@pytest.mark.parametrize("failure", [
    KeyError("missing"), FileNotFoundError(), PermissionError(), IsADirectoryError(), NotADirectoryError(),
    JsonRpcError(-32600, "thread not found: broken"),
    JsonRpcError(-32600, "no rollout found for thread id broken"),
    JsonRpcError(-32603, "failed to read rollout: Permission denied (os error 13)"),
    JsonRpcError(-32603, "failed to open rollout: Access is denied. (os error 5)"),
    JsonRpcError(-32603, "failed to read rollout: No such file or directory (os error 2)"),
])
def test_unavailable_rollout_is_skipped_without_losing_cursor_or_good_rows(fixture, failure):
    async def run():
        native = Native()
        native.rows = {i: row(fixture, i) for i in ("broken", "good", "next")}
        original = native.read_thread

        async def read(identifier, include_turns=True):
            if identifier == "broken":
                raise failure
            return await original(identifier, include_turns)

        native.read_thread = read
        client = BoundCodexClient(native, fixture.reader(), fixture.store)
        await client.start(AsyncMock())
        page = await client.list_threads(limit=1)
        assert page.threads == () and page.next_cursor == "1"
        page = await client.list_threads(limit=2)
        assert [r["id"] for r in page.threads] == ["good"] and page.next_cursor == "2"
        last = await client.list_threads(limit=2, cursor=page.next_cursor)
        assert [r["id"] for r in last.threads] == ["next"] and last.next_cursor is None
        with pytest.raises(ModelBindingUnavailable):
            await client.read_thread("broken")
        await client.stop()
    asyncio.run(run())


@pytest.mark.parametrize("failure", [
    TransportClosedError("disconnected"), BrokenPipeError(), ConnectionError(), TimeoutError(),
    JsonRpcError(-32603, "database unavailable"), JsonRpcError(-32601, "thread/read unsupported"),
    JsonRpcError(-32000, "server_overloaded"),
    JsonRpcError(-32603, "failed to open rollout: Too many open files (os error 24)"),
    ModelBindingUnavailable(),
])
def test_fatal_read_error_is_preserved_and_page_never_partially_commits(fixture, failure):
    async def run():
        native = Native()
        native.rows = {i: row(fixture, i) for i in ("good", "bad")}
        original = native.read_thread

        async def read(identifier, include_turns=True):
            if identifier == "bad":
                raise failure
            return await original(identifier, include_turns)

        native.read_thread = read
        client = BoundCodexClient(native, fixture.reader(), fixture.store)
        await client.start(AsyncMock())
        with pytest.raises(type(failure)) as raised:
            await client.list_threads()
        assert raised.value is failure
        assert client._threads == {} and fixture.store.get(client._key) is None
        await client.stop()
    asyncio.run(run())


@pytest.mark.parametrize("initial_count", [9999, 10000])
def test_capacity_never_persists_10001_and_existing_state_can_restart(fixture, initial_count):
    async def run():
        native = Native()
        client = BoundCodexClient(native, fixture.reader(), fixture.store)
        await client.start(AsyncMock())
        registered = {f"known-{i}": str(fixture.workspace) for i in range(initial_count)}
        client._threads = dict(registered)
        fixture.store.set(client._key, {"threads": registered})
        before = fixture.store.path.read_bytes()
        native.rows = {i: row(fixture, i) for i in ("new-a", "new-b")}
        with pytest.raises(RuntimeInvalidRequestError, match="10000"):
            await client.list_threads()
        assert client._threads == registered
        assert fixture.store.path.read_bytes() == before
        # Refreshing known rows at the boundary still works; no eviction/clear.
        native.rows = {"known-0": row(fixture, "known-0")}
        assert (await client.list_threads()).threads[0]["id"] == "known-0"
        await client.stop()
        restarted = BoundCodexClient(Native(), fixture.reader(), fixture.store)
        await restarted.start(AsyncMock())
        assert len(restarted._threads) == initial_count
        await restarted.stop()
    asyncio.run(run())


def test_capacity_exactly_10000_commits_then_restart_succeeds(fixture):
    async def run():
        native = Native()
        client = BoundCodexClient(native, fixture.reader(), fixture.store)
        await client.start(AsyncMock())
        client._threads = {f"known-{i}": str(fixture.workspace) for i in range(9999)}
        native.rows = {"last": row(fixture, "last")}
        await client.list_threads()
        assert len(fixture.store.get(client._key)["threads"]) == 10000
        await client.stop()
        restarted = BoundCodexClient(Native(), fixture.reader(), fixture.store)
        await restarted.start(AsyncMock())
        assert len(restarted._threads) == 10000
        await restarted.stop()
    asyncio.run(run())


def test_binding_change_during_history_reads_does_not_persist_or_grant(fixture):
    async def run():
        native = Native()
        native.rows = {"old": row(fixture, "old")}

        async def changed(identifier, include_turns=True):
            fixture.data["revision"] = "b" * 64
            fixture.write()
            return CodexThreadReadResult(native.rows[identifier])

        native.read_thread = changed
        client = BoundCodexClient(native, fixture.reader(), fixture.store)
        await client.start(AsyncMock())
        with pytest.raises(ModelBindingUnavailable):
            await client.list_threads()
        assert client._threads == {} and fixture.store.get(client._key) is None
        await client.stop()
    asyncio.run(run())


def test_all_filtered_page_preserves_native_cursor(fixture):
    async def run():
        native = Native()
        native.list_threads = AsyncMock(return_value=CodexThreadListResult(
            ({**row(fixture, "outside"), "path": str(fixture.workspace / "outside.jsonl")},), "opaque-next"))
        native.read_thread = AsyncMock()
        client = BoundCodexClient(native, fixture.reader(), fixture.store)
        await client.start(AsyncMock())
        page = await client.list_threads(cursor="opaque-input", archived=True)
        assert page.threads == () and page.next_cursor == "opaque-next"
        native.list_threads.assert_awaited_once_with(limit=100, cursor="opaque-input", archived=True)
        native.read_thread.assert_not_awaited()
        await client.stop()
    asyncio.run(run())


@pytest.mark.parametrize("change", [{"id": "other"}, {"cwd": "/different"}, {"path": "/outside.jsonl"}])
def test_readback_identity_and_home_still_required(fixture, change):
    async def run():
        native = Native()
        native.rows = {"listed": row(fixture, "listed")}
        native.read_thread = AsyncMock(return_value=CodexThreadReadResult({**native.rows["listed"], **change}))
        client = BoundCodexClient(native, fixture.reader(), fixture.store)
        await client.start(AsyncMock())
        assert (await client.list_threads()).threads == ()
        assert client._threads == {} and fixture.store.get(client._key) is None
        await client.stop()
    asyncio.run(run())


def test_cancelled_list_drains_bounded_batch_without_persisting(fixture):
    async def run():
        native = Native()
        native.rows = {f"thread-{i}": row(fixture, f"thread-{i}") for i in range(9)}
        started = asyncio.Event()
        waiting = asyncio.Event()
        active = set()
        calls = []

        async def read(identifier, include_turns=True):
            active.add(identifier)
            calls.append(identifier)
            if len(active) == 8:
                started.set()
            try:
                await waiting.wait()
            finally:
                active.remove(identifier)

        native.read_thread = read
        client = BoundCodexClient(native, fixture.reader(), fixture.store)
        await client.start(AsyncMock())
        request = asyncio.create_task(client.list_threads())
        await asyncio.wait_for(started.wait(), timeout=2)
        request.cancel()
        with pytest.raises(asyncio.CancelledError):
            await request
        assert not active and len(calls) == 8
        assert client._threads == {} and fixture.store.get(client._key) is None
        await client.stop()
    asyncio.run(run())


def test_list_filling_last_slot_during_start_does_not_poison_restart(fixture):
    async def run():
        native = Native()
        native.rows = {"last-history": row(fixture, "last-history")}
        starting = asyncio.Event()
        complete = asyncio.Event()

        async def start(request):
            starting.set()
            await complete.wait()
            return CodexThreadResult("new-during-list", {})

        native.start_thread = start
        client = BoundCodexClient(native, fixture.reader(), fixture.store)
        await client.start(AsyncMock())
        client._threads = {f"known-{i}": str(fixture.workspace) for i in range(9999)}
        request = asyncio.create_task(client.start_thread(CodexStartThreadRequest(cwd=str(fixture.workspace))))
        await asyncio.wait_for(starting.wait(), timeout=2)
        await client.list_threads()
        before = fixture.store.path.read_bytes()
        complete.set()
        with pytest.raises(RuntimeInvalidRequestError, match="10000"):
            await request
        assert len(client._threads) == 10000 and "new-during-list" not in client._threads
        assert fixture.store.path.read_bytes() == before
        await client.stop()
        restarted = BoundCodexClient(Native(), fixture.reader(), fixture.store)
        await restarted.start(AsyncMock())
        assert len(restarted._threads) == 10000
        await restarted.stop()
    asyncio.run(run())
