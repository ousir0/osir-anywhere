"""Normal product path tests; synthetic files/SDK only, no account or model I/O."""
import asyncio
import hashlib
import inspect
import json
import os
from dataclasses import asdict, replace
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from connector.core.json_kv import JsonKeyValueStore
from connector.runtime_protocol import (
    RuntimeConfig,
    RuntimeInstanceHost,
    RuntimeInstanceSpec,
    RuntimeInvalidRequestError,
    RuntimeSourceKey,
    RuntimeSupervisor,
)
from connector.runtime_protocol.host import RuntimeHostClient
from connector.runtimes import default_runtime_providers
from connector.runtimes.codex.osir_binding import (
    CATALOG_MAXIMUM,
    HOME_ENV,
    MAXIMUM,
    POLICY_ENV,
    LocalCodexBinding,
    ModelBindingUnavailable,
    read_secure,
)
from connector.runtimes.codex.osir_bound_client import BoundCodexClient
from connector.runtimes.codex.osir_bound_provider import BoundCodexProvider
from connector.runtimes.codex.osir_bound_runtime import BoundCodexRuntime, GuardedHost
from connector.runtimes.codex.provider import CodexProvider
from connector.runtimes.codex.runtime import CodexRuntime
from connector.runtimes.codex.sdk.client import CodexSdkClient, _sdk_config
from connector.runtimes.codex.sdk.runtime_client import (
    CodexModelListResult,
    CodexResumeThreadRequest,
    CodexRuntimeClient,
    CodexStartThreadRequest,
    CodexStartTurnRequest,
    CodexThreadListResult,
    CodexThreadReadResult,
    CodexThreadResult,
    CodexTurnResult,
)
from tests.test_codex_runtime import FakeHost


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    root = tmp_path.resolve()
    home = root / "codex"
    home.mkdir(mode=0o700)
    workspace = root / "acceptance-workspace"
    workspace.mkdir()
    config = (b'model = "active/a"\nmodel_reasoning_effort = "medium"\n'
        b'model_catalog_json = "catalog.json"\nmodel_provider = "local"\n'
        b'[model_providers.local]\nname = "Synthetic"\n'
        b'base_url = "http://127.0.0.1:1/v1"\nwire_api = "responses"\n'
        b'# Never connect to this fixture. secret-sentinel-comment\n')
    catalog = b'{"models":[{"slug":"active/a"},{"slug":"active/b"}]}'
    (home / "config.toml").write_bytes(config)
    (home / "catalog.json").write_bytes(catalog)
    data = {"schemaVersion": 1, "source": "osir-client", "available": True,
        "codexHome": str(home), "connectionMode": "proxy", "defaultModel": "active/a",
        "defaultReasoningEffort": "medium", "models": [
            {"id": "active/a", "title": "A"}, {"id": "active/b", "title": "B"}],
        "configSha256": hashlib.sha256(config).hexdigest(),
        "catalogSha256": hashlib.sha256(catalog).hexdigest(),
        "revision": "a" * 64, "expiresAtMs": 1030000}
    path = root / "binding.json"

    def write():
        path.write_text(json.dumps(data))
        path.chmod(0o600)
    write()
    monkeypatch.setenv("AGENT_CONNECTOR_KV_FILE", str(root / "kv.json"))
    return SimpleNamespace(home=home, workspace=workspace, path=path, data=data, write=write,
        reader=lambda: LocalCodexBinding(path, clock=lambda: 1000),
        store=JsonKeyValueStore(root / "kv.json"))


class Native:
    def __init__(self):
        self.rows = {}
        self.loaded = set()
        self.requests = []
        self.started = False
        self.stopped = False
        self.list_threads = AsyncMock(side_effect=self._list_threads)

    async def _list_threads(self, limit=100, cursor=None, archived=None):
        rows = [row for row in self.rows.values()
            if archived is None or bool(row.get("archived", False)) is archived]
        start = int(cursor or 0)
        page = rows[start:start + limit]
        following = start + len(page)
        return CodexThreadListResult(tuple(dict(row) for row in page),
            str(following) if following < len(rows) else None)

    async def start(self, handler):
        self.handler = handler
        self.started = True

    async def stop(self):
        self.stopped = True

    async def list_models(self):
        return CodexModelListResult((
            {"id": "active/a", "rawConfig": "secret-sentinel"},
            {"id": "active/b"}, {"id": "retired/other"}))

    async def start_thread(self, request):
        self.requests.append(request)
        identifier = f"thread-{len(self.rows) + 1}"
        self.rows[identifier] = {"id": identifier, "cwd": request.cwd, "turns": []}
        self.loaded.add(identifier)
        return CodexThreadResult(identifier, {"id": identifier})

    async def read_thread(self, identifier, include_turns=True):
        return CodexThreadReadResult(dict(self.rows[identifier]))

    async def start_turn(self, request):
        self.requests.append(request)
        return CodexTurnResult("turn-1", {"id": "turn-1"})

    def thread_loaded(self, identifier):
        return identifier in self.loaded

    async def update_thread_settings(self, identifier, settings):
        self.requests.append(dict(settings))
        return True

    async def interrupt_turn(self, request):
        self.requests.append(request)
        return CodexTurnResult(request.turn_id, {})


def provider_for(fixture, native, **kwargs):
    def factory(config, *, local_binding):
        assert config.values["codexHome"] == str(local_binding.home)
        assert local_binding.native_config()["model_provider"] == "local"
        return native
    return BoundCodexProvider(binding_factory=fixture.reader,
        sdk_checker=lambda: {"available": True}, sdk_client_factory=factory, **kwargs)


def test_product_factory_uses_formal_provider_and_upstream_keeps_original(monkeypatch):
    monkeypatch.delenv(POLICY_ENV, raising=False)
    assert type(default_runtime_providers()[0]) is CodexProvider
    monkeypatch.setenv(POLICY_ENV, "required-v1")
    assert type(default_runtime_providers()[0]) is BoundCodexProvider
    monkeypatch.setenv(POLICY_ENV, "disable")
    assert type(default_runtime_providers()[0]) is BoundCodexProvider
    assert asyncio.run(default_runtime_providers()[0].discover()).available is False


def test_missing_product_home_never_guesses_user_home(monkeypatch):
    monkeypatch.delenv(HOME_ENV, raising=False)
    with pytest.raises(ModelBindingUnavailable):
        LocalCodexBinding.for_product()


def test_native_catalog_over_descriptor_limit_can_bind_and_validate_config(fixture):
    # Native catalogs carry repeated model instructions, not just IDs. Reproduce
    # the installed catalog's size without reading any real user configuration.
    catalog = json.dumps({"models": [{"slug": "active/a",
        "instructions": "x" * 2_825_443}]}).encode()
    assert MAXIMUM < len(catalog) < CATALOG_MAXIMUM
    (fixture.home / "catalog.json").write_bytes(catalog)
    fixture.data["catalogSha256"] = hashlib.sha256(catalog).hexdigest()
    fixture.write()
    assert fixture.reader().read().default_model == "active/a"
    config = asyncio.run(provider_for(fixture, Native()).validate_config({}))
    assert config.metadata["modelBinding"] == "osir-client"
    # The larger catalog retains exact-byte integrity checks.
    with (fixture.home / "catalog.json").open("ab") as stream:
        stream.write(b" ")
    with pytest.raises(ModelBindingUnavailable):
        fixture.reader().read()


@pytest.mark.parametrize("target,limit", [("catalog.json", CATALOG_MAXIMUM),
    ("config.toml", MAXIMUM)])
def test_native_binding_keeps_bounded_config_and_catalog_reads(fixture, target, limit):
    with (fixture.home / target).open("wb") as stream:
        stream.truncate(limit + 1)
    with pytest.raises(ModelBindingUnavailable):
        fixture.reader().read()


def test_large_descriptor_still_uses_small_private_limit(fixture):
    with fixture.path.open("wb") as stream:
        stream.truncate(MAXIMUM + 1)
    with pytest.raises(ModelBindingUnavailable):
        fixture.reader().read()


@pytest.mark.parametrize("change", ["heartbeat", "expired", "future", "revision",
    "unavailable", "mode", "models", "fingerprint"])
def test_descriptor_refresh_during_sampling_only_allows_valid_heartbeat(fixture, monkeypatch, change):
    from connector.runtimes.codex import osir_binding

    reader = fixture.reader()
    pinned = reader.read()
    original = osir_binding.read_secure
    refreshed = False

    def refresh_after_config(path, **kwargs):
        nonlocal refreshed
        data = original(path, **kwargs)
        if path == fixture.home / "config.toml" and not refreshed:
            refreshed = True
            fixture.data["expiresAtMs"] += 1000
            if change == "expired":
                fixture.data["expiresAtMs"] = 999000
            elif change == "future":
                fixture.data["expiresAtMs"] = 1036000
            elif change == "revision":
                fixture.data["revision"] = "b" * 64
            elif change == "unavailable":
                fixture.data["available"] = False
            elif change == "mode":
                fixture.data["connectionMode"] = "direct"
            elif change == "models":
                fixture.data["models"][0]["title"] = "Changed title"
            elif change == "fingerprint":
                fixture.data["configSha256"] = "b" * 64
            # Model Client's atomic publication; reordering JSON is harmless.
            pending = fixture.path.with_suffix(".pending")
            pending.write_text(json.dumps(fixture.data, sort_keys=True))
            pending.chmod(0o600)
            pending.replace(fixture.path)
        return data

    monkeypatch.setattr(osir_binding, "read_secure", refresh_after_config)
    if change == "heartbeat":
        assert reader.read() == pinned
        assert asyncio.run(BoundCodexClient(Native(), reader, fixture.store).check()) == pinned
    else:
        client = BoundCodexClient(Native(), reader, fixture.store)
        with pytest.raises(ModelBindingUnavailable):
            asyncio.run(client.check())
        assert client.failed
    assert refreshed


def test_model_selection_keeps_namespaced_alias_and_rejects_unpublished_ids(fixture):
    binding = fixture.reader().read()
    assert binding.select(None) == "active/a"
    assert binding.select("active/b") == "active/b"
    for alias in ("a", "other/a", "active/a "):
        with pytest.raises(ModelBindingUnavailable):
            binding.select(alias)


@pytest.mark.skipif(os.name == "nt", reason="POSIX inode race fixture")
def test_atomic_heartbeat_replacing_open_descriptor_resamples_securely(fixture, monkeypatch):
    reader = fixture.reader()
    pinned = reader.read()
    original = os.fdopen
    inode = fixture.path.stat().st_ino
    replaced = False

    class DuringRead:
        def __init__(self, stream):
            self.stream = stream
        def __enter__(self):
            return self
        def __exit__(self, *args):
            self.stream.close()
        def read(self, maximum):
            nonlocal replaced
            data = self.stream.read(maximum)
            fixture.data["expiresAtMs"] += 1000
            pending = fixture.path.with_suffix(".pending")
            pending.write_text(json.dumps(fixture.data))
            pending.chmod(0o600)
            pending.replace(fixture.path)
            replaced = True
            return data

    def open_during_refresh(fd, *args, **kwargs):
        matches = not replaced and os.fstat(fd).st_ino == inode
        stream = original(fd, *args, **kwargs)
        return DuringRead(stream) if matches else stream

    monkeypatch.setattr(os, "fdopen", open_during_refresh)
    assert reader.read() == pinned
    assert replaced


def test_descriptor_resampling_is_bounded_and_never_accepts_unsafe_file(fixture, monkeypatch):
    from connector.runtimes.codex import osir_binding

    reads = 0
    def unavailable(*args, **kwargs):
        nonlocal reads
        reads += 1
        raise ModelBindingUnavailable()

    monkeypatch.setattr(osir_binding, "read_secure", unavailable)
    with pytest.raises(ModelBindingUnavailable):
        fixture.reader().read()
    assert reads == 3


@pytest.mark.parametrize("reason,code", [("open-file", 32), ("open-file", 33),
    ("read-file", 33), ("file-changed", None)])
@pytest.mark.parametrize("sample", [1, 2])
def test_windows_descriptor_race_resamples_both_samples(fixture, monkeypatch, reason, code, sample):
    from connector.runtimes.codex import osir_binding
    from connector.runtimes.codex.osir_binding_windows import WindowsFileReadError

    reader = fixture.reader()
    pinned = reader.read()
    original = osir_binding.read_secure
    reads = 0

    def racing(path, **kwargs):
        nonlocal reads
        if kwargs.get("private"):
            reads += 1
            if sample <= reads < sample + 2:
                raise WindowsFileReadError(reason, code)
        return original(path, **kwargs)

    monkeypatch.setattr(osir_binding, "read_secure", racing)
    assert reader.read() == pinned
    assert reads == 4  # Two valid samples plus two transient failures.


@pytest.mark.parametrize("reason,code", [("open-file", 32), ("open-file", 33),
    ("read-file", 33), ("file-changed", None), ("foreign-owner", 32),
    ("untrusted-writer", 32), ("reparse-or-file-type", 32), ("redirected-path", 32),
    ("security-changed", 32), ("directory-changed", 32), ("token-changed", 32),
    ("links-or-size", 32), ("invalid-read-limit", 32), ("open-file", 5),
    ("open-file", 2), ("open-file", 3), ("read-file", 32), ("file-changed", 32),
    ("generic-oserror", 32)])
def test_windows_descriptor_race_budget_and_unsafe_rejection(fixture, monkeypatch, reason, code):
    from connector.runtimes.codex import osir_binding
    from connector.runtimes.codex.osir_binding_windows import WindowsFileReadError

    reads = 0
    def unavailable(path, **kwargs):
        nonlocal reads
        assert path == fixture.path and kwargs.get("private") is True
        reads += 1
        if reason == "generic-oserror":
            error = OSError("synthetic unavailable file")
            error.reason, error.winerror = "open-file", code
            raise error
        raise WindowsFileReadError(reason, code)

    monkeypatch.setattr(osir_binding, "read_secure", unavailable)
    with pytest.raises(ModelBindingUnavailable):
        fixture.reader().read()
    transient = (reason, code) in {("open-file", 32), ("open-file", 33),
        ("read-file", 33), ("file-changed", None)}
    assert reads == (3 if transient else 1)


@pytest.mark.parametrize("change", ["expired", "elapsed", "future", "revision", "config", "unsafe"])
def test_windows_descriptor_race_never_bypasses_grant_checks(fixture, monkeypatch, change):
    from connector.runtimes.codex import osir_binding
    from connector.runtimes.codex.osir_binding_windows import WindowsFileReadError

    reader = fixture.reader()
    pinned = reader.read()
    original = osir_binding.read_secure
    reads = 0

    def racing(path, **kwargs):
        nonlocal reads
        if kwargs.get("private"):
            reads += 1
            if reads == 1:
                if change == "expired":
                    fixture.data["expiresAtMs"] = 999000
                elif change == "elapsed":
                    reader.clock = lambda: 1031
                elif change == "future":
                    fixture.data["expiresAtMs"] = 1036000
                elif change == "revision":
                    fixture.data["revision"] = "b" * 64
                elif change == "config":
                    config = (fixture.home / "config.toml").read_bytes().replace(b'Synthetic', b'Changed')
                    (fixture.home / "config.toml").write_bytes(config)
                    fixture.data["configSha256"] = hashlib.sha256(config).hexdigest()
                fixture.write()
                raise WindowsFileReadError("open-file", 32)
            if change == "unsafe":
                raise WindowsFileReadError("foreign-owner")
        return original(path, **kwargs)

    monkeypatch.setattr(osir_binding, "read_secure", racing)
    with pytest.raises(ModelBindingUnavailable):
        reader.read()
    assert reader._pinned == pinned
    assert reads == 2


@pytest.mark.parametrize("name", ["config.toml", "catalog.json"])
def test_windows_descriptor_retry_never_retries_native_config_or_catalog(fixture, monkeypatch, name):
    from connector.runtimes.codex import osir_binding
    from connector.runtimes.codex.osir_binding_windows import WindowsFileReadError

    original = osir_binding.read_secure
    reads = 0
    def unavailable(path, **kwargs):
        nonlocal reads
        if path == fixture.home / name:
            reads += 1
            raise WindowsFileReadError("open-file", 32)
        return original(path, **kwargs)

    monkeypatch.setattr(osir_binding, "read_secure", unavailable)
    with pytest.raises(ModelBindingUnavailable):
        fixture.reader().read()
    assert reads == 1


@pytest.mark.parametrize("values", [
    {"codexHome": "/other"}, {"environment": {"OPENAI_API_KEY": "sentinel"}},
    {"modelGateway": {"baseUrl": "https://untrusted.invalid"}},
    {"environment": {"NO_PROXY": "", "no_proxy": "*"}},
    {"customModels": [{"id": "other"}]}, {"ipcEnabled": True},
    {"ipcDeeplinkHandoff": True}, {"codexExecutablePath": "/untrusted"},
    {"useSystemCodex": True}, {"ipcEnabled": 0}, {"bindingPath": "/other"},
])
def test_remote_route_home_environment_and_ipc_overrides_rejected(fixture, values):
    with pytest.raises(RuntimeInvalidRequestError):
        asyncio.run(provider_for(fixture, Native()).validate_config(values))


def test_normal_sdk_models_and_bound_runtime_lists_local_history(fixture, monkeypatch):
    async def run():
        native, host = Native(), FakeHost()
        provider = provider_for(fixture, native)
        config = await provider.validate_config({})
        runtime = await provider.create_runtime(config, host)
        assert runtime.ipc_enabled is False and runtime.ipc_deeplink_handoff is False
        assert runtime._session_reader.native_history_enabled is False
        await runtime.start()
        try:
            models = await runtime.list_model_catalog()
            assert [row.id for row in models.models] == ["active/a", "active/b"]
            assert "secret-sentinel" not in repr(models)
            assert (await runtime.list_sessions()) == ()
            created = await runtime.client.start_thread(CodexStartThreadRequest(cwd=str(fixture.workspace)))
            await runtime.client.start_turn(CodexStartTurnRequest(created.thread_id, "synthetic A"))
            await runtime.client.start_turn(CodexStartTurnRequest(created.thread_id, "synthetic B", model="active/b"))
            assert native.requests[0].model == "active/a"
            assert native.requests[1].model == "active/a"
            assert native.requests[1].effort == "medium"
            assert native.requests[2].model == "active/b"
            native.list_threads.assert_awaited()
            assert [row.id for row in await runtime.list_commands("session", created.thread_id)] == ["compact"]
            for command in ("open-in-codex-app", "kill-chatgpt", "/quit-chatgpt"):
                assert (await runtime.execute_command("session", command)).code == "osir_external_codex_disabled"
            with pytest.raises(ModelBindingUnavailable):
                await runtime.client.start_turn(CodexStartTurnRequest(created.thread_id, "no", model="retired/other"))
        finally:
            await runtime.stop()
        assert native.stopped and runtime.ipc is None and runtime.ipc_owner is None
    asyncio.run(run())


def test_cold_start_preserves_native_model_list_error(fixture):
    async def run():
        native, host = Native(), FakeHost()
        failure = RuntimeInvalidRequestError("native model/list response was invalid")

        async def fail_to_list_models():
            raise failure

        native.list_models = fail_to_list_models
        runtime = await provider_for(fixture, native).create_runtime(
            await provider_for(fixture, native).validate_config({}), host)

        with pytest.raises(RuntimeInvalidRequestError) as raised:
            await runtime.start()

        assert raised.value is failure
        assert native.started and native.stopped
        assert not isinstance(raised.value, ModelBindingUnavailable)

    asyncio.run(run())


def test_stale_cached_reads_and_publication_fail_then_new_runtime_repins(fixture):
    async def run():
        native, host = Native(), FakeHost()
        host.runtime_health_update = AsyncMock()
        host.model_catalog_update = AsyncMock()
        provider = provider_for(fixture, native)
        config = await provider.validate_config({})
        runtime = await provider.create_runtime(config, host)
        await runtime.start()
        first_generation = runtime.config.revision
        fixture.data["revision"] = "b" * 64
        fixture.write()
        try:
            for method, args in [("list_model_catalog", ()), ("get_config", ()),
                    ("get_runtime_capabilities", ()), ("list_sessions", ()),
                    ("get_session_snapshot", ("session",)), ("list_complete_session_inventory", ())]:
                with pytest.raises(ModelBindingUnavailable):
                    await getattr(runtime, method)(*args)
            assert runtime._lifecycle.model_list_result is None
            host.runtime_health_update.assert_awaited_once()
            assert host.model_catalog_update.call_args.args[0].models == ()
            with pytest.raises(ModelBindingUnavailable):
                await runtime.host.timeline_sync("session", "codex", ())
        finally:
            await runtime.stop()
        next_runtime = await provider.create_runtime(config, host)
        assert next_runtime.config.revision > first_generation
        await next_runtime.start()
        try:
            assert len((await next_runtime.list_model_catalog()).models) == 2
        finally:
            await next_runtime.stop()
    asyncio.run(run())


def test_unknown_threads_and_cross_home_paths_never_read_history(fixture):
    async def run():
        native = Native()
        client = BoundCodexClient(native, fixture.reader(), fixture.store)
        await client.start(AsyncMock())
        with pytest.raises(ModelBindingUnavailable):
            await client.read_thread("existing-ungranted")
        created = await client.start_thread(CodexStartThreadRequest(cwd=str(fixture.workspace)))
        native.rows[created.thread_id]["path"] = str(fixture.workspace / "outside.jsonl")
        with pytest.raises(ModelBindingUnavailable):
            await client.read_thread(created.thread_id)
        await client.stop()
    asyncio.run(run())


def test_existing_home_threads_are_discovered_and_registered_on_reconnect(fixture):
    async def run():
        native = Native()
        existing_id = "existing-thread"
        native.rows[existing_id] = {"id": existing_id, "cwd": str(fixture.workspace),
            "path": str(fixture.home / "sessions" / "rollout-existing.jsonl"), "turns": []}
        first = BoundCodexClient(native, fixture.reader(), fixture.store)
        await first.start(AsyncMock())
        created = await first.start_thread(CodexStartThreadRequest(cwd=str(fixture.workspace)))
        await first.stop()
        second = BoundCodexClient(native, fixture.reader(), fixture.store)
        await second.start(AsyncMock())
        first_page = await second.list_threads(limit=1)
        second_page = await second.list_threads(limit=1, cursor=first_page.next_cursor)
        assert {row["id"] for row in (*first_page.threads, *second_page.threads)} == {existing_id, created.thread_id}
        assert (await second.read_thread(existing_id, include_turns=False)).thread["id"] == existing_id
        native.list_threads.assert_awaited()
        await second.stop()
    asyncio.run(run())


def test_history_inventory_rejects_cross_home_rollouts_and_missing_workspaces(fixture):
    async def run():
        native = Native()
        native.rows.update({
            "outside-rollout": {"id": "outside-rollout", "cwd": str(fixture.workspace),
                "path": str(fixture.workspace / "rollout.jsonl")},
            "missing-workspace": {"id": "missing-workspace", "cwd": str(fixture.home / "not-a-workspace"),
                "path": str(fixture.home / "sessions" / "rollout-missing.jsonl")},
            "valid": {"id": "valid", "cwd": str(fixture.workspace),
                "path": str(fixture.home / "sessions" / "rollout-valid.jsonl")},
        })
        client = BoundCodexClient(native, fixture.reader(), fixture.store)
        await client.start(AsyncMock())
        assert [row["id"] for row in (await client.list_threads()).threads] == ["valid"]
        with pytest.raises(ModelBindingUnavailable):
            await client.read_thread("outside-rollout")
        with pytest.raises(ModelBindingUnavailable):
            await client.read_thread("missing-workspace")
        await client.stop()
    asyncio.run(run())


def test_sdk_receives_bound_native_config_and_no_inherited_secret_routing(fixture, monkeypatch):
    import openai_codex
    monkeypatch.setenv("OPENAI_API_KEY", "inherited-secret-sentinel")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://untrusted.invalid")
    binding = fixture.reader().read()
    native = _sdk_config(openai_codex, RuntimeConfig(runtime="codex", revision=9, values={}),
        local_binding=binding)
    assert native.cwd == str(fixture.home)
    assert native.env["CODEX_HOME"] == str(fixture.home)
    assert native.env["OPENAI_API_KEY"] == ""
    assert native.env["OPENAI_BASE_URL"] == ""
    assert native.env["CODEX_INTERNAL_ORIGINATOR_OVERRIDE"] == "osir_anywhere_connector"
    assert native.codex_bin is None and native.launch_args_override is None
    assert 'model_provider="local"' in native.config_overrides
    assert all("base_url" not in row and "sentinel" not in row for row in native.config_overrides)


@pytest.mark.parametrize("inherited", [None, "", "*", "untrusted.invalid"])
def test_bound_sdk_pins_loopback_proxy_bypass_after_environment_scrubbing(fixture, monkeypatch, inherited):
    import openai_codex

    for key in ("NO_PROXY", "no_proxy"):
        if inherited is None:
            monkeypatch.delenv(key, raising=False)
        else:
            monkeypatch.setenv(key, inherited)
    monkeypatch.setenv("HTTPS_PROXY", "http://untrusted.invalid:7897")
    monkeypatch.setenv("OPENAI_API_KEY", "secret-sentinel")
    native = _sdk_config(openai_codex, RuntimeConfig(runtime="codex", revision=1,
        values={"environment": {"NO_PROXY": "", "no_proxy": "*",
                                "HTTPS_PROXY": "http://untrusted.invalid:7897"}}),
        local_binding=fixture.reader().read())
    assert native.env["NO_PROXY"] == native.env["no_proxy"] == "127.0.0.1,localhost,::1"
    assert native.env["HTTPS_PROXY"] == native.env["OPENAI_API_KEY"] == ""
    assert native.env["CODEX_HOME"] == str(fixture.home)


def test_sdk_actual_thread_start_and_resume_stdio_parameters_pin_route(fixture):
    async def run():
        low = SimpleNamespace(thread_start=AsyncMock(return_value=SimpleNamespace(thread=SimpleNamespace(id="native-id"))),
            thread_resume=AsyncMock(return_value=SimpleNamespace(thread=SimpleNamespace(id="resumed-id"))),
            turn_start=AsyncMock())
        native = SimpleNamespace(_client=low, _ensure_initialized=AsyncMock())
        client = CodexSdkClient(native, local_binding_config=fixture.reader().read().native_config())
        await client.start_thread(CodexStartThreadRequest(cwd=str(fixture.workspace), model="active/b"))
        params = low.thread_start.call_args.args[0]
        assert params["model"] == "active/b" and params["modelProvider"] == "local"
        assert params["config"]["model"] == "active/b"
        assert params["config"]["model_providers"]["local"]["base_url"] == "http://127.0.0.1:1/v1"
        await client._resume_thread(low, CodexResumeThreadRequest("resumed-id"))
        params = low.thread_resume.call_args.args[1]
        assert params["model"] == "active/a" and params["modelProvider"] == "local"
    asyncio.run(run())


def test_protocol_and_public_runtime_surfaces_have_explicit_guards():
    for name, method in vars(CodexRuntimeClient).items():
        if callable(method) and not name.startswith("_"):
            assert name in BoundCodexClient.__dict__, name
    for name, method in vars(CodexRuntime).items():
        if inspect.iscoroutinefunction(method) and not name.startswith("_"):
            assert name in BoundCodexRuntime.__dict__, name
    for name, method in vars(RuntimeHostClient).items():
        if inspect.iscoroutinefunction(method) and name != "prepare_runtime_host":
            assert name in GuardedHost.__dict__, name
    assert "__getattr__" not in BoundCodexClient.__dict__


@pytest.mark.skipif(os.name == "nt", reason="POSIX policy fixture; Windows has separate native reader tests")
def test_reader_rejects_writable_file_and_parent_symlink(fixture):
    fixture.path.chmod(0o666)
    with pytest.raises(ModelBindingUnavailable):
        fixture.reader().read()
    fixture.path.chmod(0o600)
    alias = fixture.path.parent / "alias"
    alias.symlink_to(fixture.home, target_is_directory=True)
    with pytest.raises((ModelBindingUnavailable, OSError)):
        read_secure(alias / "config.toml")


def test_binding_invalid_default_duplicate_or_hash_fails_closed(fixture):
    fixture.data["models"].append(fixture.data["models"][0])
    fixture.write()
    with pytest.raises(ModelBindingUnavailable):
        fixture.reader().read()


def test_public_rpc_config_schema_inventory_never_export_native_binding(fixture):
    from connector.server.runtime_rpc import RuntimeRpcHandler
    from connector.server.runtime_rpc_payloads import runtime_config_payload

    async def run():
        provider, host = provider_for(fixture, Native()), FakeHost()
        supervisor = RuntimeSupervisor((provider,), host)
        spec = RuntimeInstanceSpec("rti_owned", "codex", "Owned")
        runtime = await supervisor.start(spec, {})
        rpc = RuntimeRpcHandler(supervisor, host)
        try:
            public = await runtime.get_config()
            native = runtime.native_runtime
            assert native.config.values["codexHome"] == str(fixture.home)
            payloads = [runtime_config_payload(public)]
            for method in ("runtime.config", "runtime.configSchema", "runtime.discover"):
                payloads.append(await rpc.dispatch(method, {} if method == "runtime.discover"
                    else {"runtimeId": spec.runtime_id, "runtime": "codex"}))
            # runtime.config normally uses entry.config; also exercise fallback.
            supervisor._entries[spec.runtime_id] = replace(supervisor.entry(spec.runtime_id), config=None)
            payloads.append(await rpc.dispatch("runtime.config", {"runtimeId": spec.runtime_id,
                "runtime": "codex"}))
            encoded = json.dumps(payloads)
            for secret in (str(fixture.home), str(fixture.path), "codexHome", "bindingRevision",
                    fixture.data["revision"], fixture.data["configSha256"],
                    fixture.data["catalogSha256"], "secret-sentinel", "127.0.0.1", "model_providers"):
                assert secret not in encoded, secret
            assert set(public.values) == {"useSystemCodex", "ipcEnabled", "ipcDeeplinkHandoff",
                "environment", "customModels"}
            # A caller cannot mutate the next public result or SDK config.
            public.values["environment"]["sentinel"] = "no"
            assert (await runtime.get_config()).values["environment"] == {}
            assert native.config.values["environment"] == {}
        finally:
            await supervisor.stop(spec.runtime_id)
    asyncio.run(run())


def test_remote_matching_home_also_rejected_and_caller_metadata_not_echoed(fixture):
    async def run():
        provider = provider_for(fixture, Native())
        with pytest.raises(RuntimeInvalidRequestError):
            await provider.validate_config({"codexHome": str(fixture.home)})
        runtime = await provider.create_runtime(RuntimeConfig(runtime="codex", revision=1,
            values={}, schema={"private": str(fixture.home)},
            metadata={"raw": "secret-sentinel"}), FakeHost())
        encoded = json.dumps(asdict(await runtime.get_config()))
        assert "secret-sentinel" not in encoded and str(fixture.home) not in encoded
    asyncio.run(run())


def test_local_source_identity_never_enters_metadata_or_remote_namespace(fixture):
    from connector.runtime_protocol.instance_binding import _source_key_digest

    provider = provider_for(fixture, Native())
    config = asyncio.run(provider.validate_config({}))
    key = provider.session_source_key(config)
    assert key.local_only
    assert provider.resource_claims(config)[0].key == key.key
    spec = RuntimeInstanceSpec("rti_owned", "codex", "Owned")
    host = RuntimeInstanceHost(FakeHost(), spec, source_key=key)
    assert "runtimeSource" not in host.instance_metadata({})
    assert _source_key_digest(key) not in host.session_namespace
    assert str(fixture.home) not in host.session_namespace
    # Local storage retains source separation; upstream metadata stays unchanged.
    assert _source_key_digest(key) in host.instance_sync_key("codex/synthetic")
    upstream = RuntimeInstanceHost(FakeHost(), spec,
        source_key=RuntimeSourceKey(key.kind, key.key))
    assert upstream.instance_metadata({})["runtimeSource"]["key"] == key.key
    assert _source_key_digest(key) in upstream.session_namespace


def test_invalid_binding_cannot_publish_ready_but_error_and_cleanup_do_not_recurse():
    async def run():
        raw = SimpleNamespace(runtime_health_update=AsyncMock())
        guard = AsyncMock(side_effect=ModelBindingUnavailable())
        host = GuardedHost(raw, guard)
        for status in ("running", "ready", "available", "starting", "unknown"):
            with pytest.raises(ModelBindingUnavailable):
                await host.runtime_health_update(status)
        raw.runtime_health_update.assert_not_awaited()
        for status in ("error", "stopping", "stopped"):
            await host.runtime_health_update(status)
        assert raw.runtime_health_update.await_count == 3
        assert guard.await_count == 5
    asyncio.run(run())


def test_every_host_content_sink_rejects_before_calling_raw_on_invalid_binding():
    async def run():
        guard = AsyncMock(side_effect=ModelBindingUnavailable())
        methods = [name for name, fn in vars(GuardedHost).items()
            if inspect.iscoroutinefunction(fn) and name != "runtime_health_update"]
        raw = SimpleNamespace(**{name: AsyncMock() for name in methods})
        host = GuardedHost(raw, guard)
        for name in methods:
            with pytest.raises(ModelBindingUnavailable):
                await getattr(host, name)()
            getattr(raw, name).assert_not_awaited()
    asyncio.run(run())


def test_every_runtime_cached_read_and_write_rejects_after_expiry(fixture):
    async def run():
        provider = provider_for(fixture, Native())
        runtime = await provider.create_runtime(await provider.validate_config({}), FakeHost())
        await runtime.start()
        fixture.data["expiresAtMs"] = 999000
        fixture.write()
        try:
            for name, fn in vars(BoundCodexRuntime).items():
                if not inspect.iscoroutinefunction(fn) or name.startswith("_") or name in {
                        "start", "stop", "interrupt_session"}:
                    continue
                args = ["owned" for parameter in list(inspect.signature(fn).parameters.values())[1:]
                    if parameter.kind == parameter.POSITIONAL_OR_KEYWORD
                    and parameter.default is parameter.empty]
                with pytest.raises(ModelBindingUnavailable):
                    await getattr(runtime, name)(*args)
        finally:
            await runtime.stop()
    asyncio.run(run())


def test_early_thread_started_released_only_after_created_thread_readback(fixture):
    class Early(Native):
        async def start_thread(self, request):
            result = await super().start_thread(request)
            await self.handler({"method": "thread/started", "params": {"thread": {"id": result.thread_id}}})
            await self.handler({"method": "thread/started", "params": {"thread": {"id": "other"}}})
            await self.handler({"method": "item/started", "params": {"threadId": result.thread_id}})
            return result

    async def run():
        handler = AsyncMock()
        client = BoundCodexClient(Early(), fixture.reader(), fixture.store)
        await client.start(handler)
        created = await client.start_thread(CodexStartThreadRequest(cwd=str(fixture.workspace)))
        handler.assert_awaited_once()
        assert handler.call_args.args[0]["params"]["thread"]["id"] == created.thread_id
        assert client._early_started == []
        await client.stop()
    asyncio.run(run())


@pytest.mark.skipif(os.name == "nt", reason="POSIX inode race fixture")
@pytest.mark.parametrize("mutation", ["write", "replace", "parent"])
def test_reader_rechecks_file_and_ancestor_identity_after_read(tmp_path, monkeypatch, mutation):
    root = tmp_path.resolve() / "owned"
    root.mkdir(mode=0o700)
    target = root / "data"
    target.write_bytes(b"before")
    target.chmod(0o600)
    original = os.fdopen

    class DuringRead:
        def __init__(self, stream):
            self.stream = stream
        def __enter__(self):
            return self
        def __exit__(self, *args):
            self.stream.close()
        def read(self, maximum):
            value = self.stream.read(maximum)
            if mutation == "write":
                target.write_bytes(b"different size")
            elif mutation == "replace":
                other = root / "other"
                other.write_bytes(b"before")
                other.chmod(0o600)
                other.replace(target)
            else:
                root.rename(tmp_path.resolve() / "moved")
                root.mkdir(mode=0o700)
            return value

    monkeypatch.setattr(os, "fdopen", lambda *args, **kwargs: DuringRead(original(*args, **kwargs)))
    with pytest.raises(ModelBindingUnavailable):
        read_secure(target, private=True)
