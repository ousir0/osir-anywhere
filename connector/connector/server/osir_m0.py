"""Local-only, fail-closed OSIR acceptance mode.

No audited no-tools adapter exists for the installed Codex SDK. This module
therefore NEVER permits authentication, networking, native startup or egress.
readOnly and approvalPolicy=never do not disable tools or confine file reads.
Do not replace this check with an environment capability flag or SDK attribute
probe. Enabling a future adapter requires a code review and adversarial tests,
including native thread binding and a bounded, text-only outbound allowlist.

Safe preflight (expected exit 2, no connection; run from connector/):
  env -i PATH=/usr/bin:/bin PYTHONDONTWRITEBYTECODE=1 \
    OSIR_CONNECTOR_M0=1 \
    OSIR_ALLOW_ROOTS='["/Users/ouwei/agents-anywhere/.local-dev/acceptance-workspace"]' \
    CODEX_HOME=/Users/ouwei/agents-anywhere/.local-dev/acceptance-codex-home-3c0fc8d0 \
    .venv/bin/python -m connector.server.osir_m0

Cloud preparation only, NOT permission to connect: keep the desktop disconnected
and runtime autostart off; use a fresh acceptance connector identity/storage;
delete no existing data; do not provision Claude/DSH or enable IPC; set
syncExistingOnConnect=false. Cloud runtime values cannot relax these local pins.
Do not start a real M0 until an audited adapter enforces no tools, readOnly,
fixed cwd/home/model/prompt and new native thread/event association. A fresh
CODEX_HOME alone is not a filesystem sandbox. No cloud credentials are needed
or read by this preflight. Passing unit tests does NOT validate a cloud run.
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NoReturn

from connector.runtime_protocol import RuntimeHostClient, RuntimeProvider
from connector.server.osir_m0_scope import M0_PROMPT, OsirM0RpcGuard, OsirM0ScopeError
from connector.server.sync_state import SyncStateStore

M0_WORKSPACE = Path("/Users/ouwei/agents-anywhere/.local-dev/acceptance-workspace")
M0_CODEX_HOME = Path("/Users/ouwei/agents-anywhere/.local-dev/acceptance-codex-home-3c0fc8d0")
M0_RUNTIME_ID = "rti_osir_m0_codex"
M0_MODEL = "ccs-osir-api-5/gpt-6"
M0_BLOCK_REASON = (
    "OSIR M0 blocked: no audited Codex no-tools adapter; readOnly does not "
    "confine reads. No authentication, connection, native Agent or upload permitted."
)


class OsirM0BlockedError(RuntimeError):
    """Required native safety guarantees are unavailable."""


@dataclass(frozen=True)
class OsirM0Settings:
    workspace: Path
    codex_home: Path
    runtime_id: str = M0_RUNTIME_ID
    model: str = M0_MODEL
    prompt: str = M0_PROMPT
    ipc_enabled: bool = False
    sync_existing: bool = False
    tools_enabled: bool = False
    sandbox: str = "readOnly"

    @classmethod
    def from_env(cls) -> OsirM0Settings | None:
        mode = os.environ.get("OSIR_CONNECTOR_M0")
        roots = os.environ.get("OSIR_ALLOW_ROOTS")
        if mode in (None, "0") and roots is None:
            return None
        if mode != "1":
            raise ValueError("OSIR M0 requires explicit OSIR_CONNECTOR_M0=1")
        try:
            allowed = json.loads(roots or "")
        except (TypeError, ValueError) as exc:
            raise ValueError("OSIR M0 requires its single pinned local root") from exc
        if allowed != [str(M0_WORKSPACE)]:
            raise ValueError("OSIR M0 requires its single pinned local root")
        if os.environ.get("CODEX_HOME") != str(M0_CODEX_HOME):
            raise ValueError("OSIR M0 requires its pinned isolated CODEX_HOME")
        # Stat directories only: never read config/auth/history, including the
        # isolated home's files. Reject symlink aliases rather than broadening.
        for path in (M0_WORKSPACE, M0_CODEX_HOME):
            if not path.is_dir() or path.resolve(strict=True) != path:
                raise ValueError("OSIR M0 pinned directories must exist without symlink aliases")
        return cls(workspace=M0_WORKSPACE, codex_home=M0_CODEX_HOME)


class OsirM0Policy:
    def __init__(self, settings: OsirM0Settings) -> None:
        self.settings = settings
        self.scope = OsirM0RpcGuard(
            (settings.workspace,), runtime_id=settings.runtime_id,
            expected_content=settings.prompt,
        )

    def require_supported(self) -> NoReturn:
        # Intentionally unconditional: neither a cloud config nor an env flag
        # can invent the missing native security guarantee.
        raise OsirM0BlockedError(M0_BLOCK_REASON)

    async def dispatch(self, method, params, delegate):
        async def checked_dispatch(checked_method, checked_params):
            self.require_supported()

        return await self.scope.dispatch(method, params, checked_dispatch)

    def deny_egress(self) -> NoReturn:
        # With no safely created/attested native thread, the authorized event
        # set is EMPTY. Block before projecting deferred data, iterating a
        # snapshot, queuing/coalescing, WS sending or HTTP ingest/authentication.
        raise OsirM0ScopeError("OSIR M0 has no attested new session; outbound data denied")


def policy_from_env() -> OsirM0Policy | None:
    settings = OsirM0Settings.from_env()
    return OsirM0Policy(settings) if settings is not None else None


def preflight_from_env() -> None:
    policy = policy_from_env()
    if policy is not None:
        policy.require_supported()


class M0MemoryState(SyncStateStore):
    """No filesystem state: no checkpoint/history restoration or persistence."""

    def get(self, runtime, connector_id, external_session_id):
        return None

    def set(self, *args, **kwargs):
        raise OsirM0ScopeError("OSIR M0 checkpoint writes are disabled")

    def delete(self, *args, **kwargs):
        raise OsirM0ScopeError("OSIR M0 checkpoint deletion is disabled")

    def delete_runtime(self, *args, **kwargs):
        raise OsirM0ScopeError("OSIR M0 checkpoint deletion is disabled")

    def flush(self):
        return False


class M0DisabledLocalOps:
    def __getattr__(self, name):
        raise OsirM0ScopeError("OSIR M0 local filesystem, shell and terminal operations denied")


class M0RuntimeHost(RuntimeHostClient):
    """No disk-backed runtime_kv or event projection can be initialized."""

    def __init__(self, connector_id: str):
        self._connector_id = connector_id

    @property
    def connector_id(self):
        return self._connector_id

    @property
    def runtime_kv(self):
        raise OsirM0ScopeError("OSIR M0 runtime storage is disabled")


class M0BlockedCodexProvider(RuntimeProvider):
    """Only a Codex descriptor is registered; never construct a native client."""

    runtime_type = "codex"
    display_name = "OSIR M0 Codex (blocked)"

    async def discover(self):
        raise OsirM0BlockedError(M0_BLOCK_REASON)

    async def get_config_schema(self):
        raise OsirM0BlockedError(M0_BLOCK_REASON)

    async def validate_config(self, values: Mapping[str, Any]):
        raise OsirM0BlockedError(M0_BLOCK_REASON)

    async def create_runtime(self, config, host):
        raise OsirM0BlockedError(M0_BLOCK_REASON)


def main() -> None:
    try:
        if policy_from_env() is None:
            raise ValueError("OSIR M0 preflight requires OSIR_CONNECTOR_M0=1")
        preflight_from_env()
    except (ValueError, OSError, OsirM0BlockedError) as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
