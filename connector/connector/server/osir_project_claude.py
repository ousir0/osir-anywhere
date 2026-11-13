"""Opt-in Claude provider for NEW sessions in one locally granted project.

Public API: ProjectClaudeProvider(workspace=AUTHORIZED_WORKSPACE,
sdk_loader=None, client_factory=None). Use its normal validate_config(values)
and create_runtime(config, host) interfaces. The public values are exactly
{workspace: <canonical project>, claudeExecutablePath: /opt/homebrew/bin/claude}.
ProjectClaudeRuntime.scope contains this instance's platform/native ID bindings.

This reuses ClaudeRuntime's normal turn execution, stream projector and live
session store. It never calls its history reader/syncer, scheduled reconnect or
CLI model discovery. All list/snapshot/sync paths are in-memory and all host
publications pass a session gate. No default provider or global is patched.
Starting a new instance loses the grant; old IDs cannot be adopted or resumed.
There is deliberately no ~/.claude/projects scan or disk-history import.

The wrapper enforces session authorization, not an OS sandbox. A real launch,
authentication, native settings/tool isolation and cloud transport must be
verified separately by the integrating connection. This module does not read
credentials or run a CLI on import/discover/validate/create_runtime/start/catalog.
Only an explicitly requested new conversation invokes the normal native SDK.
"""

from __future__ import annotations

import copy
import importlib.util
import re
import threading
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path

from connector.runtime_protocol import (
    AgentRuntime,
    PreparedSessionTimelineSync,
    RuntimeConfig,
    RuntimeConfigSchema,
    RuntimeTypeDescriptor,
    RuntimeUnsupportedError,
    SessionState,
)
from connector.runtime_protocol.host import RuntimeHostClient
from connector.runtimes.claude.catalogs.reader import ClaudeCatalogReader
from connector.runtimes.claude.domain.permissions import (
    permission_mode_from_selection_id,
)
from connector.runtimes.claude.provider import ClaudeProvider
from connector.runtimes.claude.runtime import ClaudeRuntime

AUTHORIZED_WORKSPACE = Path("/Users/ouwei/cc-switch-osir-client")
CLAUDE_EXECUTABLE = Path("/opt/homebrew/bin/claude")
PROJECT_CONFIG_REVISION = 1
_ID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_UNSUPPORTED_CAPABILITIES = {"runtime.attachment", "session.steer", "session.command.execute"}


class ProjectClaudeDenied(PermissionError):
    """Fixed public reason; no native diagnostics or private config."""


def _identifier(value):
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ProjectClaudeDenied("Invalid project session ID")
    return value


def _directory(value):
    try:
        path = Path(value)
        if not path.is_absolute() or ".." in path.parts:
            raise ProjectClaudeDenied("Canonical project directory required")
        canonical = path.resolve(strict=True)
        if (path != canonical or not canonical.is_dir()
                or any(part.is_symlink() for part in (path, *path.parents))):
            raise ProjectClaudeDenied("Project directory aliases or symlinks denied")
        return canonical
    except (OSError, RuntimeError, TypeError, ValueError):
        raise ProjectClaudeDenied("Project directory unavailable") from None


@dataclass
class _Binding:
    native_id: str | None = None
    failed: bool = False


class ProjectClaudeScope:
    """Process-local NEW-session ownership; no API for importing an old ID."""

    def __init__(self, workspace: Path = AUTHORIZED_WORKSPACE):
        self.workspace = _directory(workspace)
        self._bindings: dict[str, _Binding] = {}
        self._native_ids: dict[str, str] = {}
        self._lock = threading.RLock()
        self._revoked = False

    def require_workspace(self, cwd):
        self._available()
        if _directory(cwd) != _directory(self.workspace):
            raise ProjectClaudeDenied("Only the exact granted Claude workspace is supported")
        return self.workspace

    def _available(self):
        if self._revoked:
            raise ProjectClaudeDenied("Project Claude grant revoked")

    @property
    def known_ids(self):
        with self._lock:
            self._available()
            return frozenset(key for key, binding in self._bindings.items() if not binding.failed)

    @property
    def native_ids(self):
        with self._lock:
            self._available()
            return frozenset(self._native_ids)

    def reserve(self, session_id, cwd):
        with self._lock:
            self.require_workspace(cwd)
            identifier = _identifier(session_id)
            if identifier in self._bindings:
                raise ProjectClaudeDenied("Project session already reserved")
            self._bindings[identifier] = _Binding()

    def require_session(self, session_id, external_session_id=None):
        with self._lock:
            self.require_workspace(self.workspace)
            binding = self._bindings.get(_identifier(session_id))
            if (binding is None or binding.failed or external_session_id is not None
                    and external_session_id != binding.native_id):
                raise ProjectClaudeDenied("Session is not owned by this project instance")
            return binding.native_id

    def bind_native(self, session_id, native_id, cwd):
        with self._lock:
            self.require_workspace(cwd)
            self.require_session(session_id)
            identifier = _identifier(native_id)
            binding = self._bindings[session_id]
            if (binding.native_id not in (None, identifier)
                    or self._native_ids.get(identifier, session_id) != session_id):
                raise ProjectClaudeDenied("Conflicting project native session identity")
            binding.native_id = identifier
            self._native_ids[identifier] = session_id

    def fail(self, session_id):
        with self._lock:
            binding = self._bindings[session_id]
            binding.failed = True
            if binding.native_id is not None:
                self._native_ids.pop(binding.native_id, None)

    def revoke(self):
        with self._lock:
            self._revoked = True


class _MemoryKV:
    """Keeps client-message and scheduled-state keys off the normal disk KV."""

    def __init__(self):
        self._values = {}

    def get(self, key):
        return copy.deepcopy(self._values.get(key))

    def set(self, key, value):
        self._values[key] = copy.deepcopy(value)

    def delete(self, key):
        self._values.pop(key, None)


def _capabilities(value):
    return replace(value, capabilities=tuple(item for item in value.capabilities
        if item.capability_id not in _UNSUPPORTED_CAPABILITIES))


class _ProjectHost(RuntimeHostClient):
    """Explicit outgoing host surface; no raw notification/snapshot fallback."""

    def __init__(self, delegate, scope):
        self._delegate, self.scope = delegate, scope
        self._kv = _MemoryKV()

    @property
    def connector_id(self):
        return self._delegate.connector_id

    @property
    def session_namespace(self):
        return self._delegate.session_namespace

    @property
    def runtime_kv(self):
        return self._kv

    def _check(self, session_id, runtime="claude", external_session_id=None):
        if runtime != "claude":
            raise ProjectClaudeDenied("Wrong project runtime")
        return self.scope.require_session(session_id, external_session_id)

    def _source(self, session_id, source):
        native_id = self._check(session_id)
        for key in ("sessionId", "externalSessionId", "external_session_id"):
            if source.get(key) not in (None, native_id):
                raise ProjectClaudeDenied("Foreign project timeline source")
        if source.get("runtime", "claude") != "claude":
            raise ProjectClaudeDenied("Foreign project timeline runtime")

    def _item(self, item):
        self._source(item.session_id, item.source)

    async def session_meta_upsert(self, session_id, runtime, external_session_id=None, title=None,
                                  cwd=None, ordering_time=None, metadata=None):
        self._check(session_id, runtime)
        self.scope.require_workspace(cwd)
        if external_session_id is not None:
            self.scope.bind_native(session_id, external_session_id, cwd)
        await self._delegate.session_meta_upsert(session_id=session_id, runtime=runtime,
            external_session_id=external_session_id, title=title, cwd=str(self.scope.workspace),
            ordering_time=ordering_time, metadata=copy.deepcopy(metadata))

    async def session_state_update(self, session_id, runtime, status=None, selections=None,
                                   external_session_id=None, status_reason=None, error=None, metadata=None):
        self._check(session_id, runtime, external_session_id)
        await self._delegate.session_state_update(session_id=session_id, runtime=runtime, status=status,
            selections=copy.deepcopy(selections), external_session_id=external_session_id,
            status_reason=status_reason, error=copy.deepcopy(error), metadata=copy.deepcopy(metadata))

    async def session_source_update(self, observation):
        self._check(observation.session_id, observation.runtime, observation.external_session_id)
        await self._delegate.session_source_update(copy.deepcopy(observation))

    async def session_turn_ended(self, session_id, runtime, external_session_id=None, turn_id=None,
                                outcome="completed", metadata=None):
        self._check(session_id, runtime, external_session_id)
        await self._delegate.session_turn_ended(session_id=session_id, runtime=runtime,
            external_session_id=external_session_id, turn_id=turn_id, outcome=outcome, metadata=copy.deepcopy(metadata))

    async def timeline_item_upsert(self, item):
        self._item(item)
        await self._delegate.timeline_item_upsert(copy.deepcopy(item))

    async def timeline_sync(self, session_id, runtime, items, external_session_id=None,
                            complete=False, metadata=None):
        self._check(session_id, runtime, external_session_id)
        for item in items:
            if item.session_id != session_id:
                raise ProjectClaudeDenied("Mixed project snapshot sessions")
            self._item(item)
        await self._delegate.timeline_sync(session_id=session_id, runtime=runtime, items=copy.deepcopy(items),
            external_session_id=external_session_id, complete=complete, metadata=copy.deepcopy(metadata))

    async def notice_upsert(self, notice):
        self._check(notice.session_id, notice.runtime)
        self._source(notice.session_id, notice.source)
        await self._delegate.notice_upsert(copy.deepcopy(notice))

    async def session_capabilities_update(self, capabilities):
        self._check(capabilities.session_id, capabilities.runtime)
        if any(item.session_id not in (None, capabilities.session_id) or item.runtime != "claude"
               for item in capabilities.capabilities):
            raise ProjectClaudeDenied("Mixed project capability sessions")
        await self._delegate.session_capabilities_update(_capabilities(copy.deepcopy(capabilities)))

    async def runtime_capabilities_update(self, capabilities):
        if capabilities.runtime != "claude" or capabilities.session_id is not None:
            raise ProjectClaudeDenied("Wrong project capabilities")
        if any(item.session_id is not None or item.runtime != "claude" for item in capabilities.capabilities):
            raise ProjectClaudeDenied("Mixed project runtime capabilities")
        self.scope.require_workspace(self.scope.workspace)
        await self._delegate.runtime_capabilities_update(_capabilities(copy.deepcopy(capabilities)))

    async def model_catalog_update(self, catalog):
        self.scope.require_workspace(self.scope.workspace)
        if catalog.runtime != "claude":
            raise ProjectClaudeDenied("Wrong project model catalog")
        await self._delegate.model_catalog_update(copy.deepcopy(catalog))

    async def permission_catalog_update(self, catalog):
        self.scope.require_workspace(self.scope.workspace)
        if catalog.runtime != "claude":
            raise ProjectClaudeDenied("Wrong project permission catalog")
        await self._delegate.permission_catalog_update(copy.deepcopy(catalog))

    async def runtime_error(self, runtime, code, message, session_id=None, external_session_id=None, details=None):
        self._check(session_id, runtime, external_session_id)
        await self._delegate.runtime_error(runtime="claude", code="project_claude_error",
            message="Project Claude execution failed", session_id=session_id, external_session_id=external_session_id)

    async def attachment_download(self, session_id, file_id):
        self._check(session_id)
        raise ProjectClaudeDenied("Project Claude attachments are not enabled")

    async def sync_state_read(self, key):
        self.scope.require_workspace(self.scope.workspace)
        return self._kv.get(key)

    async def sync_state_write(self, key, value):
        self.scope.require_workspace(self.scope.workspace)
        self._kv.set(key, value)

    async def sync_state_delete(self, key):
        self.scope.require_workspace(self.scope.workspace)
        self._kv.delete(key)


class _NoModelDiscovery:
    cached_models = ()

    async def models(self):
        return ()


class _ProjectCatalog(ClaudeCatalogReader):
    def __post_init__(self):
        self.discovery = _NoModelDiscovery()


class ProjectClaudeRuntime(AgentRuntime):
    def __init__(self, config, host, *, workspace, sdk_loader, client_factory=None):
        self.scope = ProjectClaudeScope(workspace)
        self._host = _ProjectHost(host, self.scope)
        self._config = config
        self._started = False

        def guarded_factory(sdk, options):
            read = options.get if isinstance(options, Mapping) else lambda key, default=None: getattr(options, key, default)
            self.scope.require_workspace(read("cwd"))
            if read("cli_path") != str(CLAUDE_EXECUTABLE):
                raise ProjectClaudeDenied("Fixed project Claude executable required")
            resume = read("resume")
            if resume is not None and resume not in self.scope.native_ids:
                raise ProjectClaudeDenied("Unknown Claude native resume ID")
            if read("continue_conversation", False) or read("add_dirs", []):
                raise ProjectClaudeDenied("Project Claude continuation override denied")
            if client_factory is not None:
                return client_factory(sdk, options)
            return sdk.ClaudeSDKClient(options=options)

        self._native = ClaudeRuntime(config=config, host=self._host, sdk_loader=sdk_loader,
            client_factory=guarded_factory, client_message_kv=self._host.runtime_kv)
        # Per-instance dependency injection. Normal providers/classes stay intact.
        catalog = _ProjectCatalog(config=config, sdk_loader=sdk_loader)
        self._native._catalogs = catalog
        self._native._turns.catalogs = catalog
        self._native._turns.selections.catalogs = catalog
        self._native._turns.runner.catalogs = catalog

    @property
    def identity(self):
        return self._native.identity

    def _check(self, session_id, external_session_id=None):
        native_id = self.scope.require_session(session_id, external_session_id)
        session = self._native._sessions.get(session_id)
        if session is not None:
            self.scope.require_workspace(session.cwd)
            if session.external_session_id not in (None, native_id):
                raise ProjectClaudeDenied("Conflicting project cached native identity")
        return native_id

    async def start(self):
        self.scope.require_workspace(self.scope.workspace)
        self._native._turns.runner.stopping = False
        self._started = True
        # Do not call normal start(): it reconnects persisted scheduled sessions.

    async def stop(self):
        self._started = False
        try:
            await self._native.stop()
        finally:
            self.scope.revoke()

    async def get_config(self):
        return copy.deepcopy(self._config)

    async def get_runtime_capabilities(self):
        self.scope.require_workspace(self.scope.workspace)
        return _capabilities(await self._native.get_runtime_capabilities())

    async def list_model_catalog(self, query=None, limit=100):
        self.scope.require_workspace(self.scope.workspace)
        return await self._native.list_model_catalog(query=query, limit=limit)

    async def list_permission_catalog(self, query=None, limit=100):
        self.scope.require_workspace(self.scope.workspace)
        catalog = await self._native.list_permission_catalog(query=query, limit=limit)
        return replace(catalog, permissions=tuple(item for item in catalog.permissions
            if item.id in {"default", "plan", "dontAsk"}))

    async def list_sessions(self, limit=100, cursor=None, force=False):
        self.scope.require_workspace(self.scope.workspace)
        if type(limit) is not int or not 1 <= limit <= 1000 or cursor is not None or type(force) is not bool:
            raise ProjectClaudeDenied("Unsupported project Claude inventory pagination")
        refs = self._native._session_store.list_sessions(limit=limit)
        for ref in refs:
            self._check(ref.session_id, ref.external_session_id)
            self.scope.require_workspace(ref.cwd)
        return copy.deepcopy(refs)

    async def list_complete_session_inventory(self, page_size=100, force=False):
        if len(self.scope.known_ids) > 1000:
            raise ProjectClaudeDenied("Project inventory exceeds supported complete snapshot bound")
        return await self.list_sessions(limit=1000, force=force)

    async def get_session_snapshot(self, session_id, external_session_id=None, limit=None):
        self._check(session_id, external_session_id)
        if limit is not None and (type(limit) is not int or not 0 <= limit <= 10000):
            raise ProjectClaudeDenied("Invalid project snapshot limit")
        snapshot = self._native._session_store.snapshot(session_id=session_id,
            external_session_id=external_session_id, limit=limit)
        self._check(snapshot.session_id, snapshot.external_session_id)
        for item in snapshot.items:
            if item.session_id != session_id:
                raise ProjectClaudeDenied("Mixed project snapshot sessions")
            self._host._item(item)
        return copy.deepcopy(snapshot)

    async def prepare_session_timeline_sync(self, session_id, external_session_id=None):
        snapshot = await self.get_session_snapshot(session_id, external_session_id)

        async def commit():
            self._check(session_id, snapshot.external_session_id)
            self._native._session_store.mark_synced(session_id, snapshot.external_session_id)
        return PreparedSessionTimelineSync(snapshot, commit)

    async def sync_session_timeline(self, session_id, external_session_id=None):
        prepared = await self.prepare_session_timeline_sync(session_id, external_session_id)
        snapshot = prepared.snapshot
        await self._host.timeline_sync(session_id=session_id, runtime="claude", items=snapshot.items,
            external_session_id=snapshot.external_session_id, complete=False, metadata=snapshot.metadata)
        await prepared.commit()
        return True

    async def get_session_state(self, session_id, external_session_id=None):
        native_id = self._check(session_id, external_session_id)
        state = self._native._session_states.get(session_id)
        if state is not None:
            self._check(state.session_id, state.external_session_id)
            return copy.deepcopy(state)
        return SessionState(session_id, native_id, "claude", "idle")

    async def get_session_notices(self, session_id, external_session_id=None):
        self._check(session_id, external_session_id)
        notices = await self._native.get_session_notices(session_id, external_session_id)
        for notice in notices:
            self._check(notice.session_id)
            if notice.session_id != session_id or notice.runtime != "claude":
                raise ProjectClaudeDenied("Mixed project notice sessions")
        return copy.deepcopy(notices)

    async def get_session_capabilities(self, session_id, external_session_id=None):
        self._check(session_id, external_session_id)
        return _capabilities(await self._native.get_session_capabilities(session_id, external_session_id))

    def _input(self, content, selections, attachments, runtime_options=None):
        if not self._started:
            raise ProjectClaudeDenied("Project Claude runtime is not started")
        if not isinstance(content, str) or not content.strip():
            raise ProjectClaudeDenied("Project Claude text required")
        if attachments or runtime_options:
            raise ProjectClaudeDenied("Project Claude attachments/options are not enabled")
        if selections is not None:
            if not isinstance(selections, Mapping) or set(selections) - {"model", "permission"}:
                raise ProjectClaudeDenied("Unsupported project Claude selections")
            mode = permission_mode_from_selection_id(selections.get("permission"))
            if mode not in (None, "default", "plan", "dontAsk"):
                raise ProjectClaudeDenied("Project Claude permission expansion denied")

    async def create_and_start_session(self, session_id, content, title=None, cwd=None,
                                       selections=None, attachments=(), client_message_id=None, *, runtime_options=None):
        self._input(content, selections, attachments, runtime_options)
        self.scope.reserve(session_id, cwd)
        try:
            result = await self._native.create_and_start_session(session_id=session_id, content=content,
                title=title, cwd=str(self.scope.workspace), selections=selections, client_message_id=client_message_id)
            if not result.ok:
                self.scope.fail(session_id)
            return result
        except BaseException:
            self.scope.fail(session_id)
            raise

    async def start_turn(self, session_id, external_session_id, content, selections=None,
                          attachments=(), client_message_id=None, cwd=None):
        native_id = self._check(session_id, external_session_id)
        if native_id is None:
            raise ProjectClaudeDenied("No confirmed project native session exists")
        if cwd is not None:
            self.scope.require_workspace(cwd)
        self._input(content, selections, attachments)
        return await self._native.start_turn(session_id, native_id, content, selections=selections,
            client_message_id=client_message_id, cwd=str(self.scope.workspace))

    async def update_session_selections(self, session_id, external_session_id, selections):
        self._check(session_id, external_session_id)
        self._input("selection update", selections, ())
        return await self._native.update_session_selections(session_id, external_session_id, selections)

    async def interrupt_session(self, session_id, reason=None):
        self._check(session_id)
        return await self._native.interrupt_session(session_id, reason)

    async def respond_interaction(self, session_id, notice_id, action_id, input_data=None):
        self._check(session_id)
        notices = await self.get_session_notices(session_id)
        if notice_id not in {notice.notice_id for notice in notices}:
            raise ProjectClaudeDenied("Unknown project Claude interaction")
        return await self._native.respond_interaction(session_id, notice_id, action_id, input_data)

    async def list_commands(self, session_id, external_session_id=None, query=None, limit=50):
        self._check(session_id, external_session_id)
        return ()

    async def execute_command(self, session_id, command, external_session_id=None, raw=None, args=()):
        self._check(session_id, external_session_id)
        raise RuntimeUnsupportedError("project Claude commands")

    async def steer_turn(self, session_id, external_session_id, content, attachments=(), client_message_id=None):
        self._check(session_id, external_session_id)
        raise RuntimeUnsupportedError("project Claude steering")


class ProjectClaudeProvider(ClaudeProvider):
    """Register only on the dedicated project connection, never default paths."""

    def __init__(self, *, workspace=AUTHORIZED_WORKSPACE, sdk_loader=None, client_factory=None):
        super().__init__(sdk_loader=sdk_loader)
        self.workspace = _directory(workspace)
        self._project_client_factory = client_factory

    def config_values(self):
        return {"workspace": str(self.workspace), "claudeExecutablePath": str(CLAUDE_EXECUTABLE)}

    async def get_config_schema(self):
        values = self.config_values()
        return RuntimeConfigSchema(runtime="claude", revision=PROJECT_CONFIG_REVISION,
            schema={"type": "object", "additionalProperties": False,
                "properties": {key: {"const": value} for key, value in values.items()}, "required": list(values)},
            defaults=values, metadata={"newSessionsOnly": True, "diskHistoryImport": False})

    async def discover(self):
        # No candidate-path search, SDK construction, CLI launch or auth access.
        return RuntimeTypeDescriptor(runtime_type="claude", display_name="Project-scoped Claude",
            description="New conversations in the locally granted project only",
            available=importlib.util.find_spec("claude_agent_sdk") is not None,
            config_schema=await self.get_config_schema(), instance_policy="single", max_instances=1,
            capabilities={"createAndStartSession": True, "modelCatalog": True, "permissionCatalog": True},
            metadata={"newSessionsOnly": True, "nativeVerified": False, "historyImport": False})

    async def validate_config(self, values):
        if not isinstance(values, Mapping) or dict(values) != self.config_values():
            raise ProjectClaudeDenied("Fixed project Claude configuration required")
        _directory(self.workspace)
        schema = await self.get_config_schema()
        return RuntimeConfig(runtime="claude", revision=PROJECT_CONFIG_REVISION, values=self.config_values(),
            schema=schema.schema, metadata={"newSessionsOnly": True, "nativeVerified": False})

    async def create_runtime(self, config, host):
        # configRevision is the server's update generation (often epoch ms),
        # not the fixed local schema version. Values are still pinned below.
        if (config.runtime != "claude" or type(config.revision) is not int
                or not 0 <= config.revision <= 2**53 - 1):
            raise ProjectClaudeDenied("Unsupported project Claude configuration revision")
        await self.validate_config(config.values)
        native_config = replace(config, values={"executablePath": str(CLAUDE_EXECUTABLE),
            "environment": {}, "customModels": [], "idleTimeoutSeconds": 600})
        runtime = ProjectClaudeRuntime(native_config, host, workspace=self.workspace,
            sdk_loader=self._sdk_loader, client_factory=self._project_client_factory)
        runtime._config = config
        return runtime
