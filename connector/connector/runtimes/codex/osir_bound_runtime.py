"""Normal OSIR runtime guards, including cached reads and publication sinks."""
from __future__ import annotations

import asyncio
from dataclasses import replace

from connector.logging import logger
from connector.runtime_protocol import RuntimeCommandResult, RuntimeModelCatalog
from connector.runtimes.codex.domain.commands import (
    ALIASES,
    KILL_CHATGPT,
    OPEN_IN_CODEX_APP,
)
from connector.runtimes.codex.osir_binding import ModelBindingUnavailable
from connector.runtimes.codex.runtime import CodexRuntime


class BoundCodexRuntime(CodexRuntime):
    def __post_init__(self):
        super().__post_init__()
        self._session_reader.native_history_enabled = False
        self._binding_health_reported = False
        self._binding_watch = None

    async def _guard(self):
        try:
            return await self.client.check()
        except ModelBindingUnavailable:
            self._lifecycle.model_list_result = None
            if not self._binding_health_reported:
                self._binding_health_reported = True
                error = ModelBindingUnavailable()
                # Notification failure must not mask the sticky binding error
                # or prevent the other invalidation notification being tried.
                try:
                    await self.host.raw.runtime_health_update("error",
                        error={"code": error.code, "message": str(error)})
                except Exception as failure:  # noqa: BLE001 - preserve the binding failure
                    logger.warning("OSIR binding health notification failed type={}", type(failure).__name__)
                try:
                    await self.host.raw.model_catalog_update(RuntimeModelCatalog(
                        runtime="codex", revision=self.config.revision + 1, models=()))
                except Exception as failure:  # noqa: BLE001 - preserve the binding failure
                    logger.warning("OSIR binding catalog invalidation failed type={}", type(failure).__name__)
            raise

    async def start(self):
        await self._guard()
        try:
            await self._lifecycle.start()
            # bootstrap traditionally tolerates model/list errors. Binding
            # failure and a missing native model catalog are fatal here.
            await self._guard()
            if self._lifecycle.model_list_result is None:
                raise ModelBindingUnavailable()
        except BaseException:
            await self._lifecycle.stop()
            raise
        if self._binding_watch is None:
            self._binding_watch = asyncio.create_task(self._watch_binding())

    async def _watch_binding(self):
        while True:
            await asyncio.sleep(1)
            try:
                await self._guard()
            except ModelBindingUnavailable:
                return

    async def stop(self):
        if self._binding_watch is not None:
            self._binding_watch.cancel()
            await asyncio.gather(self._binding_watch, return_exceptions=True)
            self._binding_watch = None
        await self._lifecycle.stop()

    async def _start_ipc(self):
        # This variant never discovers/follows/controls an external app.
        return None

    async def list_commands(self, session_id, external_session_id=None, query=None, limit=50):
        await self._guard()
        commands = self._turns.commands.catalog(session_id, external_session_id, query, limit)
        await self._guard()
        return tuple(row for row in commands if row.id not in {OPEN_IN_CODEX_APP, KILL_CHATGPT})

    async def execute_command(self, session_id, command, external_session_id=None, raw=None, args=()):
        await self._guard()
        normalized = command.lstrip("/") if isinstance(command, str) else ""
        if ALIASES.get(normalized, normalized) in {OPEN_IN_CODEX_APP, KILL_CHATGPT}:
            return RuntimeCommandResult(command=command, ok=False,
                code="osir_external_codex_disabled", message="此连接不接管其他 Codex 应用。")
        result = await self._turns.execute_command(session_id=session_id, command=command,
            external_session_id=external_session_id, raw=raw, args=args)
        await self._guard()
        return result

    async def interrupt_session(self, session_id, reason=None):
        # No IPC discovery; the client only interrupts locally owned threads.
        try:
            await self._guard()
        except ModelBindingUnavailable:
            from connector.runtime_protocol import RuntimeOperationResult
            from connector.runtimes.codex.sdk.runtime_client import (
                CodexInterruptTurnRequest,
            )
            state = self._session_states.get(session_id)
            turn = self._active_turn_ids.get(session_id)
            if state is None or state.external_session_id is None or turn is None:
                raise
            await self.client.interrupt_turn(CodexInterruptTurnRequest(state.external_session_id, turn))
            return RuntimeOperationResult(ok=True, result={"interrupted": True})
        return await self._turns.interrupt_session(session_id=session_id, reason=reason)

    async def prepare_session_timeline_sync(self, session_id, external_session_id=None):
        await self._guard()
        prepared = await super().prepare_session_timeline_sync(session_id, external_session_id)
        await self._guard()
        if prepared is None:
            return None
        original = prepared.commit
        if original is None:
            return prepared

        async def commit():
            await self._guard()
            return await original()
        return replace(prepared, commit=commit)

    async def get_config(self, *args, **kwargs):
        await self._guard()
        # Never serialize the SDK's private native RuntimeConfig.
        import copy
        return copy.deepcopy(self.public_config)

    async def get_runtime_capabilities(self, *args, **kwargs):
        await self._guard()
        result = await super().get_runtime_capabilities(*args, **kwargs)
        await self._guard()
        return result

    async def list_model_catalog(self, *args, **kwargs):
        await self._guard()
        result = await super().list_model_catalog(*args, **kwargs)
        await self._guard()
        return result

    async def list_permission_catalog(self, *args, **kwargs):
        await self._guard()
        result = await super().list_permission_catalog(*args, **kwargs)
        await self._guard()
        return result

    async def list_sessions(self, *args, **kwargs):
        await self._guard()
        result = await super().list_sessions(*args, **kwargs)
        await self._guard()
        return result

    async def list_complete_session_inventory(self, *args, **kwargs):
        await self._guard()
        result = await super().list_complete_session_inventory(*args, **kwargs)
        await self._guard()
        return result

    async def get_session_state(self, *args, **kwargs):
        await self._guard()
        result = await super().get_session_state(*args, **kwargs)
        await self._guard()
        return result

    async def get_session_notices(self, *args, **kwargs):
        await self._guard()
        result = await super().get_session_notices(*args, **kwargs)
        await self._guard()
        return result

    async def get_session_capabilities(self, *args, **kwargs):
        await self._guard()
        result = await super().get_session_capabilities(*args, **kwargs)
        await self._guard()
        return result

    async def publish_runtime_capabilities(self, *args, **kwargs):
        await self._guard()
        result = await super().publish_runtime_capabilities(*args, **kwargs)
        await self._guard()
        return result

    async def publish_session_capabilities_for_state(self, *args, **kwargs):
        await self._guard()
        result = await super().publish_session_capabilities_for_state(*args, **kwargs)
        await self._guard()
        return result

    async def get_session_snapshot(self, *args, **kwargs):
        await self._guard()
        result = await super().get_session_snapshot(*args, **kwargs)
        await self._guard()
        return result

    async def create_and_start_session(self, *args, **kwargs):
        await self._guard()
        result = await super().create_and_start_session(*args, **kwargs)
        await self._guard()
        return result

    async def start_turn(self, *args, **kwargs):
        await self._guard()
        result = await super().start_turn(*args, **kwargs)
        await self._guard()
        return result

    async def steer_turn(self, *args, **kwargs):
        await self._guard()
        result = await super().steer_turn(*args, **kwargs)
        await self._guard()
        return result

    async def update_session_selections(self, *args, **kwargs):
        await self._guard()
        result = await super().update_session_selections(*args, **kwargs)
        await self._guard()
        return result

    async def respond_interaction(self, *args, **kwargs):
        await self._guard()
        result = await super().respond_interaction(*args, **kwargs)
        await self._guard()
        return result


class GuardedHost:
    def __init__(self, raw, guard):
        self.raw = raw
        self.guard = guard

    @property
    def connector_id(self):
        return self.raw.connector_id

    @property
    def session_namespace(self):
        return self.raw.session_namespace

    @property
    def runtime_kv(self):
        return self.raw.runtime_kv

    async def runtime_health_update(self, status, error=None, phase=None):
        if status not in {"error", "stopping", "stopped"}:
            await self.guard()
        return await self.raw.runtime_health_update(status, error=error, phase=phase)

    async def publish_runtime_snapshot(self, *args, **kwargs):
        await self.guard()
        result = await self.raw.publish_runtime_snapshot(*args, **kwargs)
        await self.guard()
        return result

    async def publish_runtime_notifications(self, *args, **kwargs):
        await self.guard()
        result = await self.raw.publish_runtime_notifications(*args, **kwargs)
        await self.guard()
        return result

    async def session_meta_upsert(self, *args, **kwargs):
        await self.guard()
        result = await self.raw.session_meta_upsert(*args, **kwargs)
        await self.guard()
        return result

    async def session_state_update(self, *args, **kwargs):
        await self.guard()
        result = await self.raw.session_state_update(*args, **kwargs)
        await self.guard()
        return result

    async def session_source_update(self, *args, **kwargs):
        await self.guard()
        result = await self.raw.session_source_update(*args, **kwargs)
        await self.guard()
        return result

    async def session_turn_ended(self, *args, **kwargs):
        await self.guard()
        result = await self.raw.session_turn_ended(*args, **kwargs)
        await self.guard()
        return result

    async def runtime_capabilities_update(self, *args, **kwargs):
        await self.guard()
        result = await self.raw.runtime_capabilities_update(*args, **kwargs)
        await self.guard()
        return result

    async def session_capabilities_update(self, *args, **kwargs):
        await self.guard()
        result = await self.raw.session_capabilities_update(*args, **kwargs)
        await self.guard()
        return result

    async def model_catalog_update(self, *args, **kwargs):
        await self.guard()
        result = await self.raw.model_catalog_update(*args, **kwargs)
        await self.guard()
        return result

    async def permission_catalog_update(self, *args, **kwargs):
        await self.guard()
        result = await self.raw.permission_catalog_update(*args, **kwargs)
        await self.guard()
        return result

    async def timeline_sync(self, *args, **kwargs):
        await self.guard()
        result = await self.raw.timeline_sync(*args, **kwargs)
        await self.guard()
        return result

    async def timeline_item_upsert(self, *args, **kwargs):
        await self.guard()
        result = await self.raw.timeline_item_upsert(*args, **kwargs)
        await self.guard()
        return result

    async def notice_upsert(self, *args, **kwargs):
        await self.guard()
        result = await self.raw.notice_upsert(*args, **kwargs)
        await self.guard()
        return result

    async def runtime_error(self, *args, **kwargs):
        await self.guard()
        result = await self.raw.runtime_error(*args, **kwargs)
        await self.guard()
        return result

    async def attachment_download(self, *args, **kwargs):
        await self.guard()
        result = await self.raw.attachment_download(*args, **kwargs)
        await self.guard()
        return result

    async def sync_state_read(self, *args, **kwargs):
        await self.guard()
        result = await self.raw.sync_state_read(*args, **kwargs)
        await self.guard()
        return result

    async def sync_state_write(self, *args, **kwargs):
        await self.guard()
        result = await self.raw.sync_state_write(*args, **kwargs)
        await self.guard()
        return result

    async def sync_state_delete(self, *args, **kwargs):
        await self.guard()
        result = await self.raw.sync_state_delete(*args, **kwargs)
        await self.guard()
        return result
