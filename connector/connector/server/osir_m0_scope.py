"""Opt-in, one-conversation RPC gate for a locally provisioned OSIR M0 runtime.

OSIR_ALLOW_ROOTS is a JSON array of absolute, existing local directory paths.
Read it once in the launcher and share ONE guard across every request session
and reconnect. Cloud configuration must never construct or replace this guard.
Absent means no OSIR opt-in; empty/malformed settings fail closed.

This is the scope-checking primitive, not an authorization to run an Agent.
The OSIR_CONNECTOR_M0 policy in osir_m0 wires it to default/connection dispatch,
blocks every outbound event, and fails before native startup/auth/networking
because no audited no-tools adapter exists. Never install this primitive alone
as the complete isolation boundary.

Only one session.create with a locally pinned test prompt is accepted.
Discovery, old-session reads, runtime
configuration, files, downloads, shell and terminal/relay are all denied. The
reservation survives failed/ambiguous creation, since a thread may already exist.
This does NOT filter outbound events/queued ingest or sandbox Agent tools and
subprocesses. A cwd check is not an OS filesystem boundary. Prevent startup
history and constrain native tools separately before any real cloud M0 run.
"""

from __future__ import annotations

import json
import os
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

RpcDispatch = Callable[[str, dict[str, Any]], Awaitable[Any]]
OSIR_ALLOW_ROOTS_ENV = "OSIR_ALLOW_ROOTS"
M0_PROMPT = "Reply OSIR_M0_OK"
_CREATE_FIELDS = frozenset(
    {"runtime", "runtimeId", "sessionId", "content", "title", "cwd", "clientMessageId"}
)


class OsirM0ScopeError(PermissionError):
    """A request exceeded the local M0 grant."""


class OsirM0RpcGuard:
    def __init__(
        self, roots: tuple[Path, ...], *, runtime_id: str, expected_content: str = M0_PROMPT
    ) -> None:
        if not roots or not isinstance(runtime_id, str) or not runtime_id.strip():
            raise ValueError("OSIR M0 requires local roots and a pinned Codex runtime")
        resolved = []
        for root in roots:
            if not root.is_absolute():
                raise ValueError("OSIR M0 roots must be absolute directories")
            canonical = root.resolve(strict=True)
            if not canonical.is_dir() or canonical == Path(canonical.anchor):
                raise ValueError("OSIR M0 requires bounded existing directories")
            resolved.append(canonical)
        self._roots = tuple(resolved)
        self._runtime_id = runtime_id
        if not isinstance(expected_content, str) or not expected_content.strip():
            raise ValueError("OSIR M0 requires a locally pinned test prompt")
        self._expected_content = expected_content
        self._reserved = False

    @classmethod
    def from_env(
        cls, *, runtime_id: str, expected_content: str = M0_PROMPT
    ) -> OsirM0RpcGuard | None:
        value = os.environ.get(OSIR_ALLOW_ROOTS_ENV)
        if value is None:
            return None
        try:
            roots = json.loads(value)
        except (ValueError, TypeError) as exc:
            raise ValueError("OSIR_ALLOW_ROOTS must be a nonempty JSON path array") from exc
        if not isinstance(roots, list) or not roots or any(
            not isinstance(root, str) or not root.strip() for root in roots
        ):
            raise ValueError("OSIR_ALLOW_ROOTS must be a nonempty JSON path array")
        return cls(
            tuple(Path(root) for root in roots), runtime_id=runtime_id,
            expected_content=expected_content,
        )

    async def dispatch(
        self, method: str, params: dict[str, Any], delegate: RpcDispatch
    ) -> Any:
        if method != "session.create":
            raise OsirM0ScopeError("Only a new M0 test conversation is authorized")
        if not isinstance(params, dict) or set(params) - _CREATE_FIELDS:
            raise OsirM0ScopeError("M0 request contains unauthorized options")
        if params.get("runtime") != "codex" or params.get("runtimeId") != self._runtime_id:
            raise OsirM0ScopeError("M0 request targets an unauthorized runtime")
        for field in ("sessionId", "content", "cwd"):
            if not isinstance(params.get(field), str) or not params[field].strip():
                raise OsirM0ScopeError("M0 request is missing required text")
        for field in ("title", "clientMessageId"):
            if field in params and not isinstance(params[field], str):
                raise OsirM0ScopeError("M0 optional text must be a string")
        if params["content"] != self._expected_content:
            raise OsirM0ScopeError("Only the locally pinned M0 test prompt is authorized")
        requested = Path(params["cwd"])
        if not requested.is_absolute():
            raise OsirM0ScopeError("M0 cwd must be an absolute directory")
        try:
            cwd = requested.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise OsirM0ScopeError("M0 cwd must exist inside the local grant") from exc
        if not cwd.is_dir() or not any(cwd.is_relative_to(root) for root in self._roots):
            raise OsirM0ScopeError("M0 cwd is outside the local grant")
        if self._reserved:
            raise OsirM0ScopeError("The single M0 conversation grant is already reserved")
        # No await between checking and reserving: concurrent RPCs share one grant.
        # Do not release on failure/cancellation; creation may already have happened.
        self._reserved = True
        return await delegate(method, {**params, "cwd": str(cwd)})
