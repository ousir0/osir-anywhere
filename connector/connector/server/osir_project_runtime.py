"""Local project grant for the OSIR development bridge.

Only the locally selected project can be indexed, read or operated. This is
separate from the old text-only acceptance mode and never enables an ordinary
unfiltered Connector. Native Codex ownership and IPC routing remain in charge.
"""
from __future__ import annotations

import asyncio
import time
from pathlib import Path

from connector.core.json_kv import JsonKeyValueStore
from connector.runtime_protocol import (
    RuntimeConfig,
    RuntimeConfigSchema,
    RuntimeInvalidRequestError,
)
from connector.runtime_protocol.host import RuntimeHostClient
from connector.runtimes.catalog_revisions import runtime_catalog_revision
from connector.runtimes.codex.catalogs.reader import CodexCatalogReader
from connector.runtimes.codex.domain.catalogs import permission_catalog_from_codex_items
from connector.runtimes.codex.ipc import CodexIpcClient, CodexIpcSessionProjector
from connector.runtimes.codex.ipc.service import CodexIpcService
from connector.runtimes.codex.provider import CodexProvider
from connector.runtimes.codex.runtime import CodexRuntime
from connector.runtimes.codex.sdk.client import sdk_client_from_config
from connector.server.osir_model_binding import (
    BoundProjectCodexClient,
    LocalCodexBinding,
)

PROJECT = Path('/Users/ouwei/cc-switch-osir-client')
CODEX_HOME = Path('/Users/ouwei/.codex')
CODEX_CLI = '/Applications/ChatGPT.app/Contents/Resources/codex-cli/CodexCLI.app/Contents/MacOS/codex'
PROJECT_CONFIG = {'workspace': str(PROJECT)}


class ProjectCatalogReader(CodexCatalogReader):
    async def list_model_catalog(self, query=None, limit=100):
        binding = getattr(self, 'model_binding', None)
        if binding is not None:
            await binding.check()
        return await super().list_model_catalog(query=query, limit=limit)

    async def list_permission_catalog(self, query=None, limit=100):
        revision = runtime_catalog_revision(self.config.revision, 2)
        catalog = permission_catalog_from_codex_items([{
            'id': 'osir_project_readonly',
            'label': 'OSIR project read-only',
            'description': 'Read-only access to the authorized project.',
            'identity': {'permission_mode': 'osir_project_readonly'},
            'runtimeSettings': {'permissionMode': 'osir_project_readonly'},
            'nativeSettings': {
                'approvalPolicy': 'never',
                'sandbox': 'read-only',
                'sandboxPolicy': {'type': 'readOnly', 'networkAccess': False},
            },
        }], revision=revision)
        permissions = catalog.permissions
        if query:
            lowered = query.casefold()
            permissions = tuple(p for p in permissions if lowered in p.id.casefold() or lowered in p.title.casefold())
        return type(catalog)(runtime='codex', revision=revision, permissions=permissions[:limit])


class ProjectIpcService(CodexIpcService):
    """Probe only authorized thread IDs; never enumerate global IPC/history."""

    def __init__(self, *, scope, **kwargs):
        super().__init__(**kwargs)
        self.scope = scope

    async def scan_once(self):
        refs = await asyncio.to_thread(self.scope.inventory)
        ids = {row['id'] for row in refs}
        self._extra_candidates.clear()
        semaphore = asyncio.Semaphore(4)

        async def follow(thread_id):
            async with semaphore:
                current = self.follower.get(thread_id)
                if current is None or current.status != 'following':
                    await self.follower.follow(thread_id, discovery_timeout_ms=1200)
        # Only probe held threads and ones already announced, not all history.
        await asyncio.gather(*(follow(t) for t in ids if self.thread_is_held(t)), return_exceptions=True)
        self._scan_count += 1

    async def _on_following_changed(self, broadcast):
        if self._authorized_broadcast(broadcast):
            await super()._on_following_changed(broadcast)

    async def _on_owner_announced(self, broadcast):
        if self._authorized_broadcast(broadcast):
            await super()._on_owner_announced(broadcast)

    def _authorized_broadcast(self, broadcast):
        params = broadcast.params
        thread_id = params.get('conversationId') if isinstance(params, dict) else None
        if not isinstance(thread_id, str):
            return False
        try:
            self.scope.require_thread(thread_id)
            return True
        except (PermissionError, ValueError, OSError):
            return False


class ProjectCodexRuntime(CodexRuntime):
    def __post_init__(self):
        super().__post_init__()
        catalogs = ProjectCatalogReader(
            config=self.config,
            ensure_started=self.start,
            get_model_list_result=self._get_model_list_result,
        )
        self._catalogs = catalogs
        catalogs.model_binding = getattr(self.client, 'model_binding', None)
        for reader in (self._session_reader, self._turns, self._turns.actions,
                       self._turns.selections, self._turns.session_starter):
            reader.list_permission_catalog = catalogs.list_permission_catalog
            reader.list_model_catalog = catalogs.list_model_catalog

    async def _ipc_route_for_write(self, session_id, external_session_id=None):
        thread_id = external_session_id
        if thread_id is None:
            state = self._session_states.get(session_id)
            thread_id = state.external_session_id if state is not None else None
        service = self.ipc_service
        lock_probe = getattr(service, 'thread_is_held', None)
        if thread_id and (self._ipc_attached_thread(session_id, external_session_id) is not None
                          or callable(lock_probe) and lock_probe(thread_id)):
            owner = self.ipc_owner
            if owner is None or not owner.owns(thread_id):
                return self._ipc_blocked_write_route(
                    thread_id,
                    code='osir_project_external_owner_readonly',
                    status='held_by_external_owner',
                    message='This project connection can follow Codex Desktop sessions, but cannot send to a thread owned by another app.',
                    started_at=asyncio.get_running_loop().time(),
                )
        route = await super()._ipc_route_for_write(session_id, external_session_id)
        # The base route may attach an owner while awaiting discovery. Never
        # let that race bypass the project client's read-only SDK settings.
        if route.thread is not None:
            routed_id = route.thread.thread_id
            if self.ipc_owner is None or not self.ipc_owner.owns(routed_id):
                return self._ipc_blocked_write_route(
                    routed_id, code='osir_project_external_owner_readonly',
                    status='held_by_external_owner',
                    message='Sessions owned by another app are read-only in this project connection.',
                    started_at=asyncio.get_running_loop().time(),
                )
        return route

    async def interrupt_session(self, session_id, reason=None):
        state = self._session_states.get(session_id)
        thread_id = state.external_session_id if state is not None else None
        if thread_id and self._ipc_attached_thread(session_id, thread_id) is not None:
            owner = self.ipc_owner
            if owner is None or not owner.owns(thread_id):
                route = self._ipc_blocked_write_route(
                    thread_id, code='osir_project_external_owner_readonly',
                    status='held_by_external_owner',
                    message='Sessions owned by another app are read-only in this project connection.',
                    started_at=asyncio.get_running_loop().time(),
                )
                return self._ipc_blocked_operation(route, thread_id)
        return await super().interrupt_session(session_id, reason)

    async def get_session_capabilities(self, session_id, external_session_id=None):
        capabilities = await super().get_session_capabilities(session_id, external_session_id)
        if external_session_id and self._ipc_attached_thread(session_id, external_session_id) is not None:
            from dataclasses import replace
            readonly = {'session.interrupt', 'session.steer'}
            return replace(capabilities, capabilities=tuple(
                replace(item, available=False,
                    unavailable_reason='This session is owned by another app and is read-only here.')
                if item.capability_id in readonly else item
                for item in capabilities.capabilities))
        return capabilities

    async def _start_ipc(self):
        if self.ipc_service is None:
            home = Path(self.config.values['codexHome'])
            self.ipc = CodexIpcClient(codex_home=home)
            projector = CodexIpcSessionProjector(
                host=self.host, session_states=self._session_states, notices=self._notices,
                active_turn_ids=self._active_turn_ids, timeline=self._timeline,
                read_model_catalog=self._ipc_model_catalog, read_permission_catalog=self._ipc_permission_catalog,
                async_submissions=self._async_submissions,
            )

            async def project(event):
                try:
                    self.project_scope.require_thread(event.thread.thread_id)
                except (PermissionError, ValueError, OSError):
                    return
                await projector.handle(event)

            self.ipc_service = ProjectIpcService(scope=self.project_scope, client=self.ipc,
                codex_home=home, on_event=project, scan_interval=30)
        await super()._start_ipc()


class ProjectCodexProvider(CodexProvider):
    def __init__(self, scope, state_path: Path, model_binding=None):
        super().__init__()
        self.scope = scope
        self.state_path = state_path
        self.model_binding = model_binding or LocalCodexBinding()

    async def get_config_schema(self):
        return RuntimeConfigSchema(runtime='codex', revision=1, schema={
            'type': 'object', 'additionalProperties': False,
            'properties': {'workspace': {'const': str(PROJECT)}}, 'required': ['workspace'],
        }, defaults=PROJECT_CONFIG)

    async def discover(self):
        # Do not call the normal provider's config validation with cloud values.
        from connector.runtime_protocol import RuntimeTypeDescriptor
        return RuntimeTypeDescriptor(runtime_type='codex', display_name='OSIR Project Codex',
            description='Codex sessions in the locally authorized OSIR client project',
            available=True, implementation_type='cli', recommended=True,
            capabilities={'createAndStartSession': True, 'modelCatalog': True, 'permissionCatalog': True},
            config_schema=await self.get_config_schema(), metadata={'workspace': str(PROJECT), 'projectScoped': True})

    async def validate_config(self, values):
        if dict(values) != PROJECT_CONFIG:
            raise RuntimeInvalidRequestError('The project must be selected locally')
        return RuntimeConfig(runtime='codex', revision=1, values=PROJECT_CONFIG,
            schema=(await self.get_config_schema()).schema)

    async def create_runtime(self, config, host: RuntimeHostClient):
        binding = await self.model_binding.check()
        if binding.home != self.scope.codex_home:
            from connector.server.osir_model_binding import ModelBindingUnavailable
            raise ModelBindingUnavailable()
        # Native configuration is local only. No endpoint, key, binary, Home or
        # IPC setting from the cloud can expand this grant.
        # Server catalogs require an increasing revision when content changes.
        # One startup generation is immutable; a binding change requires a
        # reconnect, whose millisecond generation also invalidates cloud caches.
        native = RuntimeConfig(runtime='codex', revision=int(time.time() * 1000), values={
            'codexHome': str(binding.home), 'codexExecutablePath': CODEX_CLI,
            'useSystemCodex': True, 'ipcEnabled': True, 'ipcDeeplinkHandoff': False,
            'environment': {}, 'customModels': [],
        })
        runtime = ProjectCodexRuntime(config=native, host=host,
            client=BoundProjectCodexClient(sdk_client_from_config(native), self.scope, self.model_binding),
            client_message_kv=JsonKeyValueStore(self.state_path), ipc_enabled=True,
            ipc_deeplink_handoff=False, safe_ipc_write_routing=True)
        runtime.project_scope = self.scope
        return runtime

    def resource_claims(self, config):
        return ()

    def session_source_key(self, config):
        from connector.runtime_protocol import RuntimeSourceKey
        return RuntimeSourceKey(kind='osir_project', key=str(PROJECT))
