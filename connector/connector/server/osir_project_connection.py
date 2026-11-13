"""Desktop-owned connection for one explicitly selected existing project.

Credentials arrive only through Main's private stdin pipe. Local constants pin
scope, Codex Home and executable; cloud RPC cannot select another directory or
provider. Native SDK, history projection and ownership routing are reused.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import sys
import time
from contextlib import nullcontext
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import httpx
import websockets

from connector.core.json_kv import JsonKeyValueStore
from connector.runtime_protocol import RuntimeInstanceSpec, RuntimeSupervisor
from connector.server.osir_cloud_verification import ExistingDesktopDevice
from connector.server.osir_connection_probe import ORIGIN
from connector.server.osir_model_binding import (
    LocalCodexBinding,
    ModelBindingUnavailable,
)
from connector.server.osir_project_claude import ProjectClaudeProvider
from connector.server.osir_project_runtime import (
    PROJECT,
    PROJECT_CONFIG,
    ProjectCodexProvider,
)
from connector.server.osir_project_transport import ProjectTransport
from connector.server.osir_scoped_connection import emit
from connector.server.runtime_host import ConnectorRuntimeHost
from connector.server.runtime_rpc import RuntimeRpcHandler
from connector.server.runtime_session_rpc import sync_session_snapshot
from connector.server.runtime_sync import (
    _session_meta_notification,
    _timeline_sync_notification,
)

STATE_DIR = Path('/Users/ouwei/agents-anywhere/.local-dev/project-coordination-20261114')
_SESSION_ID = re.compile(
    r'(?:(?:sess_|session_)[A-Za-z0-9_-]{1,128}|'
    r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12})\Z'
)


def require_session_id(value):
    if not isinstance(value, str) or not _SESSION_ID.fullmatch(value):
        raise PermissionError('Missing project session identity')
    return value


def local_desktop_proxy(value):
    if value is None:
        return None
    if not isinstance(value, str):
        raise PermissionError('Invalid local desktop proxy')
    parsed = urlsplit(value)
    if (parsed.scheme != 'http' or parsed.hostname not in {'127.0.0.1', 'localhost'}
            or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment
            or parsed.port is None or not 1 <= parsed.port <= 65535):
        raise PermissionError('Only the existing loopback desktop proxy is supported')
    return value


async def stop_project_delivery(supervisor, runtime_ids, transport, delivery_task, *, timeout=15):
    stops = {asyncio.create_task(supervisor.stop(instance_id)) for instance_id in runtime_ids}
    pending = stops
    try:
        if stops:
            # wait() observes a deadline without waiting for cancellation that
            # a native terminal-delivery shield may suppress indefinitely.
            done, pending = await asyncio.wait(stops, timeout=timeout)
            for task in done:
                if not task.cancelled() and task.exception() is not None:
                    emit('project-runtime-stop-failed', errorType=type(task.exception()).__name__)
            if pending:
                emit('project-runtime-stop-deferred', reason='Native shutdown exceeded its deadline')
    finally:
        delivery_task.cancel()
        await asyncio.gather(delivery_task, return_exceptions=True)
        # Closing the queue wakes terminal producers even if their native stop
        # code shields cancellation. Never wait on them before this step.
        await transport.close()
        for task in pending:
            task.cancel()
        if pending:
            done, remaining = await asyncio.wait(pending, timeout=2)
            for task in done:
                if not task.cancelled():
                    task.exception()
            if remaining:
                emit('project-runtime-stop-deferred', reason='Native cleanup remains pending')


class ProjectHost(ConnectorRuntimeHost):
    """One instance's egress gate, also used by RPC snapshot/read helpers."""

    def __init__(self, *args, scope, runtime_type='codex', runtime_id='codex', owners=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._scope = scope
        self.runtime_type, self.runtime_id = runtime_type, runtime_id
        self.owners = owners if owners is not None else {}
        self.bindings: dict[str, str] = {}
        self.pending: set[str] = set()
        self.local_kv = JsonKeyValueStore(STATE_DIR / f'{runtime_id}-project-runtime-kv.json')

    @property
    def scope(self):
        return self._scope() if callable(self._scope) else self._scope

    @property
    def runtime_kv(self):
        return self.local_kv

    def claim(self, session_id):
        require_session_id(session_id)
        if self.owners.get(session_id, self.runtime_id) != self.runtime_id:
            raise PermissionError('Project session belongs to another runtime')
        self.owners[session_id] = self.runtime_id

    def require_session(self, session_id, external_id=None):
        require_session_id(session_id)
        if self.owners.get(session_id, self.runtime_id) != self.runtime_id:
            raise PermissionError('Project session belongs to another runtime')
        bound = self.bindings.get(session_id)
        if external_id is not None and bound not in (None, external_id):
            raise PermissionError('Project session identity cannot change')
        if self.runtime_type == 'claude':
            # A pending RPC alone never authorizes a Claude session. Only the
            # native wrapper can reserve/bind it; a restart invalidates it.
            return self.scope.require_session(session_id, external_id)
        external_id = external_id if external_id is not None else bound
        if external_id is not None:
            self.scope.require_thread(external_id)
        elif session_id not in self.pending:
            raise PermissionError('Unknown project session')
        return external_id

    def _identity(self, value, *, required=False):
        if not isinstance(value, dict):
            raise PermissionError('Invalid project notification envelope')
        for key, expected in (('runtime', self.runtime_type), ('runtimeType', self.runtime_type),
                              ('runtimeId', self.runtime_id)):
            if key in value and value[key] != expected:
                raise PermissionError('Wrong project notification runtime')
        if required and (value.get('runtime') != self.runtime_type or value.get('runtimeId') != self.runtime_id):
            raise PermissionError('Missing project notification runtime')
        if value.get('cwd') is not None:
            self.scope.require_workspace(value['cwd'])

    def _source(self, source, native_id):
        self._identity(source)
        for key in ('sessionId', 'threadId', 'externalSessionId', 'external_session_id'):
            if source.get(key) not in (None, native_id):
                raise PermissionError('Foreign project notification source')

    def validate_notification(self, method, payload):
        allowed = {'session.meta.upsert', 'session.state.updated', 'session.source.updated',
            'session.turnEnded', 'timeline.sync', 'timeline.itemUpsert', 'notice.upsert',
            'runtime.capability.updated', 'runtime.catalog.updated', 'runtime.error'}
        if method not in allowed:
            raise PermissionError('Unsupported project notification')
        self._identity(payload, required=method != 'notice.upsert')
        if method == 'notice.upsert':
            self._identity(payload.get('source'), required=True)
        session_id = payload.get('sessionId')
        native_id = None
        if session_id is not None:
            native_id = self.require_session(session_id, payload.get('externalSessionId'))
        elif method.startswith(('session.', 'timeline.')) or method == 'notice.upsert':
            raise PermissionError('Missing project notification session')
        for key in ('metadata', 'details'):
            if key in payload:
                self._identity(payload[key])
        if 'source' in payload:
            self._source(payload['source'], native_id)
        if 'catalog' in payload:
            self._identity(payload['catalog'])
        for capability in payload.get('capabilities', ()):
            self._identity(capability)
            if capability.get('sessionId') not in (None, session_id):
                raise PermissionError('Mixed project capability sessions')
        items = payload.get('items', ()) if method == 'timeline.sync' else ()
        if method == 'timeline.itemUpsert':
            items = (payload['item'],)
        for item in items:
            if not isinstance(item, dict) or item.get('sessionId') != session_id:
                raise PermissionError('Mixed project snapshot sessions')
            self._identity(item)
            self._source(item.get('source', {}), native_id)
        return session_id, native_id

    async def _notify_server(self, method, payload):
        session_id, native_id = self.validate_notification(method, payload)
        if session_id is not None:
            self.claim(session_id)
            if native_id is not None:
                self.bindings[session_id] = native_id
                self.pending.discard(session_id)
        await super()._notify_server(method, payload)

    async def publish_runtime_notifications(self, *args, **kwargs):
        raise PermissionError('Raw project notification batches are unavailable')

    async def publish_runtime_snapshot(self, *args, **kwargs):
        raise PermissionError('Raw project snapshots are unavailable')


class ProjectHostRouter(ConnectorRuntimeHost):
    """Select a fixed local instance Host before RuntimeInstanceHost binds it."""

    def __init__(self, *args, scope, configs, **kwargs):
        super().__init__(*args, **kwargs)
        self.codex_scope, self.configs = scope, configs
        self.hosts = {}
        self.runtime_ids = {}
        self.owners = {}
        self.supervisor = None

    def claude_scope(self, runtime_id):
        entry = self.supervisor.entry(runtime_id)
        if entry.runtime_type != 'claude' or entry.runtime is None:
            raise PermissionError('Claude project instance is not running')
        # entry remains available during stopping, so native shutdown notices
        # still pass the same scope before the wrapper revokes its grant.
        return entry.runtime.native_runtime.scope

    def bind(self, runtime_type, runtime_id):
        if runtime_type not in self.configs:
            raise PermissionError('Unknown project runtime')
        RuntimeInstanceSpec(runtime_id=runtime_id, runtime_type=runtime_type, name='OSIR Project')
        if self.runtime_ids.get(runtime_type, runtime_id) != runtime_id:
            raise PermissionError('Project runtime is already locally bound')
        previous = self.hosts.get(runtime_id)
        if previous is not None:
            if previous.runtime_type != runtime_type:
                raise PermissionError('Project runtime identity cannot change')
            return previous
        self.runtime_ids[runtime_type] = runtime_id
        scope = self.codex_scope if runtime_type == 'codex' else lambda: self.claude_scope(runtime_id)
        host = ProjectHost(self.connector_id, self._notifier, self._attachment_downloader,
            scope=scope, runtime_type=runtime_type, runtime_id=runtime_id, owners=self.owners)
        self.hosts[runtime_id] = host
        return host

    async def prepare_runtime_host(self, runtime_id):
        if runtime_id not in self.hosts:
            raise PermissionError('Project runtime is not locally bound')
        return self.hosts[runtime_id]

    async def _notify_server(self, method, payload):
        raise PermissionError('Unbound project host notifications are unavailable')


class ProjectDispatch:
    def __init__(self, *, scope, supervisor, host, runtime_id, schedule, runtime_type='codex', config=None,
                 capture_snapshot=nullcontext):
        self._scope, self.supervisor, self.host = scope, supervisor, host
        self.runtime_id, self.runtime_type = runtime_id, runtime_type
        self.config = PROJECT_CONFIG if config is None else config
        self.capture_snapshot = capture_snapshot
        self.rpc = RuntimeRpcHandler(supervisor, host, schedule_background=schedule)

    @property
    def scope(self):
        return self._scope() if callable(self._scope) else self._scope

    async def dispatch(self, method, params):
        if method == 'runtime.discover' and params == {}:
            return await self.rpc.dispatch(method, params)
        if not isinstance(params, dict) or params.get('runtime') != self.runtime_type or params.get('runtimeId') != self.runtime_id:
            raise PermissionError('Unknown project runtime')
        allowed = {'runtime.config', 'runtime.configSchema', 'runtime.validateConfig',
            'runtime.start', 'runtime.stop', 'runtime.capabilities', 'runtime.modelCatalog',
            'runtime.permissionCatalog', 'session.discover', 'session.create', 'session.sync',
            'session.state', 'session.capabilities', 'session.notices', 'session.send_message',
            'session.interrupt', 'interaction.respond', 'session.selections.update'}
        if self.runtime_type == 'codex':
            allowed.add('session.steer')
        if method not in allowed:
            raise PermissionError('This project connection has no filesystem, shell or global commands')
        if method in {'runtime.start', 'runtime.validateConfig'} and params.get('config') != self.config:
            raise PermissionError('Cloud configuration cannot select a project')
        if params.get('attachments') or params.get('runtimeOptions'):
            raise PermissionError('Project verification accepts text only')
        session_id = params.get('sessionId')
        if method == 'session.create':
            self.scope.require_workspace(params.get('cwd'))
            require_session_id(session_id)
            if session_id in self.host.pending or session_id in self.host.bindings:
                raise PermissionError('Project session already exists')
            if isinstance(self.host, ProjectHost):
                if session_id in self.host.owners:
                    raise PermissionError('Project session already reserved')
                self.host.claim(session_id)
            self.host.pending.add(session_id)
        elif method.startswith('session.') and method != 'session.discover' or method == 'interaction.respond':
            require_session_id(session_id)
            external = params.get('externalSessionId')
            if external is None:
                external = self.host.bindings.get(session_id)
            if isinstance(self.host, ProjectHost):
                external = self.host.require_session(session_id, external)
                self.host.claim(session_id)
            elif self.runtime_type == 'claude':
                external = self.scope.require_session(session_id, external)
            else:
                self.scope.require_thread(external)
            if self.host.bindings.get(session_id) not in (None, external):
                raise PermissionError('Project thread binding mismatch')
            if external is not None:
                self.host.bindings[session_id] = external
            if params.get('cwd') is not None:
                self.scope.require_workspace(params['cwd'])
        if method == 'session.sync':
            # Return only after the selected snapshot reaches the cloud.
            runtime = self.supervisor.resolve_runtime(self.runtime_id, self.runtime_type)
            with self.capture_snapshot():
                return {'runtime': self.runtime_type, 'runtimeId': self.runtime_id,
                    **await sync_session_snapshot(runtime, self.host, params)}
        try:
            return await self.rpc.dispatch(method, params)
        finally:
            if method == 'session.create':
                self.host.pending.discard(session_id)


async def connect(data):
    from connector.server.osir_project_scope import ProjectSessionScope
    if data.get('projectWorkspace') != str(PROJECT) or data.get('syncExistingOnConnect') is not False:
        raise PermissionError('An explicit local project grant is required')
    device = ExistingDesktopDevice.parse(data['desktopDevice'])
    desktop_proxy = local_desktop_proxy(data.get('desktopProxy'))
    if desktop_proxy:
        # Native SDK model requests use the same selected local route.
        os.environ['HTTPS_PROXY'] = desktop_proxy
        os.environ['HTTP_PROXY'] = desktop_proxy
        os.environ['NO_PROXY'] = '127.0.0.1,localhost'
    model_binding = LocalCodexBinding()
    binding = await model_binding.check()
    scope = ProjectSessionScope(codex_home=binding.home, workspace=PROJECT)
    # Index is queried only for this directory; no global list/IPC inventory.
    inventory = await asyncio.to_thread(scope.inventory)
    claude_provider = ProjectClaudeProvider(workspace=PROJECT)
    configs = {'codex': PROJECT_CONFIG, 'claude': claude_provider.config_values()}
    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    emit('project-index-ready', sessions=len(inventory), workspace=str(PROJECT))
    stop = asyncio.Event()
    supervisor = None
    async with httpx.AsyncClient(base_url=ORIGIN + '/api/v2', timeout=60, proxy=desktop_proxy,
                                 trust_env=False, follow_redirects=False) as client:
        async def api(method, route, body=None, *, headers=None):
            response = await client.request(method, route, json=body, headers=headers or {
                'Authorization': 'Bearer ' + data['accessToken']})
            if not response.is_success:
                emit('project-cloud-rejected', method=method, status=response.status_code, route=route)
                raise ConnectionError('Project cloud request rejected')
            return response.json()

        existing = await api('GET', f'/connectors/{device.connector_id}')
        if existing['connector']['status'] != 'offline':
            raise PermissionError('The existing device is still connected')
        runtimes = (await api('GET', f'/connectors/{device.connector_id}/runtimes'))['runtimes']
        existing_ids = {}
        for runtime_type in configs:
            matches = [r for r in runtimes if r['runtimeType'] == runtime_type]
            if len(matches) > 1:
                raise PermissionError('Ambiguous project runtime instance')
            if matches:
                existing_ids[runtime_type] = matches[0]['runtimeId']
        # Only locally pinned providers can stay advertised by this process.
        for previous in runtimes:
            if previous['runtimeType'] not in configs and previous.get('active'):
                await api('PUT', f"/connectors/{device.connector_id}/runtimes/{previous['runtimeId']}/active", {'active': False})
        transport = ProjectTransport(client=client, device=device, origin=ORIGIN, emit=emit)
        connector_headers = {'Authorization': 'Bearer ' + await transport.authenticate()}
        live_revisions = {}
        background = set()
        def schedule(coro):
            task = asyncio.create_task(coro)
            background.add(task)
            task.add_done_callback(background.discard)
            task.add_done_callback(lambda done: done.exception() if not done.cancelled() else None)

        async def notify(method, params):
            if method in {'timeline.itemUpsert', 'session.turnEnded', 'session.state.updated'}:
                identity = params.get('externalSessionId') or params.get('sessionId')
                if identity:
                    live_revisions[identity] = live_revisions.get(identity, 0) + 1
            if method == 'timeline.sync':
                # A history checkpoint may advance only after cloud acceptance.
                await transport.snapshot([{'method': method, 'params': dict(params)}])
            else:
                # Live SDK events must not await a network round trip per delta.
                await transport.notify(method, dict(params))

        async def no_download(*args, **kwargs):
            raise PermissionError('Attachment reads are not part of project verification')

        host = ProjectHostRouter(device.connector_id, notify, no_download, scope=scope, configs=configs)
        provider = ProjectCodexProvider(scope, STATE_DIR / 'project-client-messages.json', model_binding)
        supervisor = RuntimeSupervisor((provider, claude_provider), host)
        host.supervisor = supervisor
        dispatchers = {}

        async def bind(runtime_type, runtime_id):
            instance_host = host.bind(runtime_type, runtime_id)
            if runtime_id not in dispatchers:
                await supervisor.ensure_instance(RuntimeInstanceSpec(runtime_id=runtime_id,
                    runtime_type=runtime_type, name=f'OSIR Project {runtime_type.title()}'))
                dispatchers[runtime_id] = ProjectDispatch(scope=instance_host._scope,
                    supervisor=supervisor, host=instance_host, runtime_id=runtime_id,
                    runtime_type=runtime_type, config=configs[runtime_type], schedule=schedule,
                    capture_snapshot=transport.capture_snapshot)
            return dispatchers[runtime_id]

        for runtime_type, instance_id in existing_ids.items():
            await bind(runtime_type, instance_id)

        async with websockets.connect(ORIGIN.replace('https:', 'wss:') + '/api/v2/connector/ws',
                additional_headers={**connector_headers, 'X-Device-OS': 'macos'},
                proxy=desktop_proxy, max_size=1024 * 1024) as ws:
            async def reader():
                async def respond(message):
                    method, params = message.get('method'), message.get('params', {})
                    started_at = time.monotonic()
                    if method in {'session.send_message', 'session.create'}:
                        emit('project-rpc-received', method=method, at=datetime.now(UTC).isoformat())
                    reply = {'id': message.get('id'), 'type': 'response'}
                    try:
                        if not isinstance(params, dict):
                            raise PermissionError('Invalid project request envelope')
                        if method == 'runtime.discover':
                            result = await RuntimeRpcHandler(supervisor, host).dispatch(method, params)
                        else:
                            runtime_type, instance_id = params.get('runtime'), params.get('runtimeId')
                            dispatcher = dispatchers.get(instance_id)
                            if dispatcher is None:
                                if (method != 'runtime.validateConfig' or runtime_type not in configs
                                        or params.get('config') != configs[runtime_type]
                                        or type(params.get('configRevision')) is not int
                                        or params['configRevision'] < 0):
                                    raise PermissionError('Project runtime is not locally bound')
                                dispatcher = await bind(runtime_type, instance_id)
                            result = await dispatcher.dispatch(method, params)
                        reply.update(ok=True, result=result)
                    except Exception as exc:  # noqa: BLE001 - sanitize native/network diagnostics
                        safe_params = params if isinstance(params, dict) else {}
                        runtime_type = safe_params.get('runtime')
                        emit('project-rpc-failed', method=method, errorType=type(exc).__name__,
                             runtimeMatches=runtime_type in configs,
                             runtimeIdMatches=safe_params.get('runtimeId') in dispatchers,
                             configMatches=runtime_type in configs and safe_params.get('config') == configs[runtime_type],
                             cwdMatches=safe_params.get('cwd') == str(PROJECT),
                             cwdPresent=safe_params.get('cwd') is not None,
                             reason=str(exc) if type(exc).__name__ == 'ProjectScopeDenied' else None)
                        reply.update(ok=False, error={'code': 'project_request_denied',
                            'message': 'Project request failed or exceeded the local grant'})
                    await ws.send(json.dumps(reply))
                    if method in {'session.send_message', 'session.create'}:
                        emit('project-rpc-completed', method=method, ok=reply.get('ok'),
                             elapsedMs=round((time.monotonic() - started_at) * 1000),
                             at=datetime.now(UTC).isoformat())
                async for raw in ws:
                    message = json.loads(raw)
                    if message.get('type') == 'request':
                        schedule(respond(message))
                stop.set()

            async def heartbeat():
                while not stop.is_set():
                    await ws.send(json.dumps({'type': 'notification', 'method': 'connector.heartbeat', 'params': {}}))
                    await asyncio.sleep(5)

            async def commands():
                stream = asyncio.StreamReader(limit=1024)
                transport, _ = await asyncio.get_running_loop().connect_read_pipe(
                    lambda: asyncio.StreamReaderProtocol(stream), sys.stdin.buffer)
                try:
                    await stream.readline()
                finally:
                    transport.close()
                    stop.set()

            delivery_task = asyncio.create_task(transport.run())
            tasks = [asyncio.create_task(reader()), asyncio.create_task(heartbeat()),
                     asyncio.create_task(commands()), delivery_task]
            try:
                for _ in range(40):
                    if (await api('GET', f'/connectors/{device.connector_id}'))['connector']['status'] == 'online':
                        break
                    await asyncio.sleep(.25)
                await api('POST', f'/connectors/{device.connector_id}/runtime-types/discover')
                for runtime_type, fixed_config in configs.items():
                    instance_id = host.runtime_ids.get(runtime_type)
                    if instance_id is None:
                        entry = await api('POST', f'/connectors/{device.connector_id}/runtimes', {
                            'runtimeType': runtime_type, 'name': f'OSIR Project {runtime_type.title()}',
                            'config': fixed_config, 'active': False})
                        instance_id = entry['runtimeId']
                        # Creation can synchronously validate through WS before
                        # HTTP returns; bind must agree with that first ID.
                        await bind(runtime_type, instance_id)
                    else:
                        await api('PUT', f'/connectors/{device.connector_id}/runtimes/{instance_id}/active', {'active': False})
                        await api('PUT', f'/connectors/{device.connector_id}/runtimes/{instance_id}/config', {'config': fixed_config})
                        await api('PATCH', f'/connectors/{device.connector_id}/runtimes/{instance_id}',
                            {'name': f'OSIR Project {runtime_type.title()}'})
                    try:
                        await api('PUT', f'/connectors/{device.connector_id}/runtimes/{instance_id}/active', {'active': True})
                    except ConnectionError:
                        if runtime_type != 'claude':
                            raise
                        # A not-yet-verified optional CLI cannot take down the
                        # working Codex device. Authentication failures still
                        # propagate if the deactivation itself is rejected.
                        await api('PUT', f'/connectors/{device.connector_id}/runtimes/{instance_id}/active', {'active': False})
                        emit('project-runtime-unavailable', runtime='claude')
                runtime_id = host.runtime_ids['codex']
                codex_host = host.hosts[runtime_id]
                projects = (await api('GET', '/projects'))['projects']
                project = next((p for p in projects if p.get('connectorId') == device.connector_id
                                and p.get('workspacePath') == str(PROJECT)), None)
                if project is None:
                    project = (await api('POST', '/projects', {'name': 'OSIR Client · 主目录',
                        'connectorId': device.connector_id, 'workspacePath': str(PROJECT),
                        'attachMatchingSessions': True}))['project']
                emit('scoped-connection-ready', connectorId=device.connector_id, runtimeId=runtime_id,
                     runtimeIds=dict(host.runtime_ids),
                     projectId=project['id'], workspace=str(PROJECT), projectScoped=True, textOnly=False)

                async def pull_once():
                    runtime = supervisor.resolve_runtime(runtime_id, 'codex')
                    sessions = await runtime.list_complete_session_inventory(page_size=100, force=False)
                    for session in sessions:
                        notice = _session_meta_notification(session)
                        await codex_host._notify_server(notice['method'], notice['params'])
                    emit('project-meta-synced', sessions=len(sessions))
                    succeeded = failed = 0
                    for session in sessions:
                        try:
                            native = getattr(runtime, 'native_runtime', runtime)
                            # Periodic history imports yield to the live stream.
                            # A capture raced by a new event is retried next scan.
                            identity = session.external_session_id or session.session_id
                            if getattr(native, '_active_turn_ids', {}):
                                continue
                            revision = live_revisions.get(identity, 0)
                            with transport.capture_snapshot():
                                prepared = await runtime.prepare_session_timeline_sync(session.session_id, session.external_session_id)
                                if (getattr(native, '_active_turn_ids', {})
                                        or live_revisions.get(identity, 0) != revision):
                                    continue
                                if prepared and prepared.snapshot:
                                    notice = _timeline_sync_notification(prepared.snapshot, fallback_item_time=session.ordering_time)
                                    await codex_host._notify_server(notice['method'], notice['params'])
                                    if prepared.commit:
                                        await prepared.commit()
                            succeeded += 1
                        except Exception as exc:  # noqa: BLE001 - sanitize native/network diagnostics
                            failed += 1
                            emit('project-history-failed', sessionId=session.session_id, errorType=type(exc).__name__)
                        await asyncio.sleep(.15)
                    emit('project-pull-complete', sessions=len(sessions), succeeded=succeeded, failed=failed)
                async def pull():
                    failures = 0
                    while not stop.is_set():
                        try:
                            await pull_once()
                            failures = 0
                        except Exception as exc:  # noqa: BLE001 - keep transport alive and report recovery
                            failures += 1
                            emit('project-pull-deferred', attempt=failures, errorType=type(exc).__name__)
                        await asyncio.sleep(min(60, 15 * failures) if failures else 30)
                schedule(pull())
                tasks.append(asyncio.create_task(stop.wait()))
                done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                for task in done:
                    if not task.cancelled() and task.exception():
                        raise ConnectionError('Project transport stopped')
            finally:
                for task in tasks:
                    if task is not delivery_task:
                        task.cancel()
                for task in list(background):
                    task.cancel()
                await asyncio.gather(*(task for task in tasks if task is not delivery_task),
                                     *background, return_exceptions=True)
                await stop_project_delivery(supervisor, host.hosts, transport, delivery_task)
                emit('scoped-connection-closed', connectorId=device.connector_id,
                     runtimeId=host.runtime_ids.get('codex'), runtimeIds=dict(host.runtime_ids))


def main():
    try:
        data = json.loads(sys.stdin.buffer.readline(32769))
        asyncio.run(connect(data))
    except Exception as exc:  # noqa: BLE001 - sanitize native/network diagnostics
        emit('scoped-connection-failed', errorType=type(exc).__name__, reason='Local project connection failed',
             code='osir_model_binding_unavailable' if isinstance(exc, ModelBindingUnavailable) else 'project_connection_failed')
        raise SystemExit(1) from None


if __name__ == '__main__':
    main()
