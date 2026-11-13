from __future__ import annotations

from typing import Any

from connector.runtime_protocol import RuntimeHostClient, RuntimeSupervisor
from connector.server.local_rpc import (
    BackgroundScheduler,
    LocalRpcHandler,
    StartTerminalRelay,
    UploadPreparedDownload,
)
from connector.server.osir_m0 import OsirM0Policy
from connector.server.runtime_rpc import RuntimeRpcHandler


class ConnectorRequestSession:
    """Own connection-scoped RPC state while sharing runtime/local services."""

    def __init__(
        self,
        runtime_rpc: RuntimeRpcHandler,
        local_rpc: LocalRpcHandler,
        m0_policy: OsirM0Policy | None = None,
    ) -> None:
        self.runtime_rpc = runtime_rpc
        self.local_rpc = local_rpc
        self._m0_policy = m0_policy

    async def dispatch(self, method: str, params: dict[str, Any]) -> Any:
        if self._m0_policy is not None:
            return await self._m0_policy.dispatch(method, params, self._dispatch_unchecked)
        return await self._dispatch_unchecked(method, params)

    async def _dispatch_unchecked(self, method: str, params: dict[str, Any]) -> Any:
        if self.runtime_rpc.supports(method):
            return await self.runtime_rpc.dispatch(method, params)
        if self.local_rpc.supports(method):
            return await self.local_rpc.dispatch(method, params)
        raise ValueError(f"unsupported connector method: {method}")

    async def discover_runtimes(self) -> dict[str, Any]:
        if self._m0_policy is not None:
            self._m0_policy.require_supported()
        return await self.runtime_rpc.discover_runtimes()


class ConnectorRequestDispatcher:
    """Top-level backend connector RPC router."""

    def __init__(
        self,
        agent_runtime_supervisor: RuntimeSupervisor,
        agent_runtime_host: RuntimeHostClient,
        local_ops: Any,
        upload_prepared_download: UploadPreparedDownload,
        start_terminal_relay: StartTerminalRelay,
        schedule_background: BackgroundScheduler,
        m0_policy: OsirM0Policy | None = None,
    ) -> None:
        self._agent_runtime_supervisor = agent_runtime_supervisor
        self._agent_runtime_host = agent_runtime_host
        self._schedule_background = schedule_background
        self._m0_policy = m0_policy
        self.local_rpc = LocalRpcHandler(
            local_ops=local_ops,
            upload_prepared_download=upload_prepared_download,
            start_terminal_relay=start_terminal_relay,
            schedule_background=schedule_background,
        )
        self._default_session = self.new_session()
        self.runtime_rpc = self._default_session.runtime_rpc

    def new_session(self) -> ConnectorRequestSession:
        return ConnectorRequestSession(
            runtime_rpc=RuntimeRpcHandler(
                agent_runtime_supervisor=self._agent_runtime_supervisor,
                agent_runtime_host=self._agent_runtime_host,
                schedule_background=self._schedule_background,
                m0_policy=self._m0_policy,
            ),
            local_rpc=self.local_rpc,
            m0_policy=self._m0_policy,
        )

    async def dispatch(self, method: str, params: dict[str, Any]) -> Any:
        return await self._default_session.dispatch(method, params)

    async def discover_runtimes(self) -> dict[str, Any]:
        return await self._default_session.discover_runtimes()
