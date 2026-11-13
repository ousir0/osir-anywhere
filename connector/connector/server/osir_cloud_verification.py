"""One new fixed-text session over the real cloud protocol, with no history APIs.

This is an acceptance adapter, not the general Connector. It never imports the
default providers, local ops, SDK, IPC discovery or persisted synchronization.
The separate native runner must attest a new restricted CLI turn before any
assistant text can be uploaded. M0 is deliberately unchanged.
"""
from __future__ import annotations

import asyncio
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import httpx
import websockets

from connector.runtime_protocol.timeline import timeline_content_hash
from connector.server.osir_acceptance_sandbox import (
    MODEL,
    PROMPT,
    WORKSPACE,
    OsirAcceptanceRunner,
)
from connector.server.osir_connection_probe import ORIGIN

REPLY = "OSIR_M0_OK"
CONFIG = {"workspace": str(WORKSPACE), "model": MODEL}
MODEL_SELECTION = "sel_model_osir_acceptance"
PERMISSION_SELECTION = "sel_permission_osir_acceptance_readonly"
SELECTIONS = {"model": MODEL_SELECTION, "permission": PERMISSION_SELECTION}


class VerificationDenied(RuntimeError):
    pass


@dataclass(frozen=True)
class ExistingDesktopDevice:
    connector_id: str
    token: str = field(repr=False)

    @classmethod
    def parse(cls, value: dict) -> ExistingDesktopDevice:
        if (not isinstance(value, dict)
                or set(value) != {"serverUrl", "connectorId", "connectorToken"}
                or value["serverUrl"] != ORIGIN
                or not isinstance(value["connectorId"], str)
                or not re.fullmatch(r"conn_[A-Za-z0-9_-]{1,128}", value["connectorId"])
                or not isinstance(value["connectorToken"], str)
                or not 20 <= len(value["connectorToken"]) <= 16384
                or any(c.isspace() for c in value["connectorToken"])):
            raise VerificationDenied("invalid desktop binding")
        return cls(value["connectorId"], value["connectorToken"])


def descriptor() -> dict:
    return {"runtimeType": "codex", "implementationType": "cli",
            "displayName": "OSIR isolated Codex verification", "description": "Single fixed-text acceptance turn",
            "available": True, "reason": None, "recommended": False, "recommendationRank": None,
            "configSchema": {"revision": 1, "schema": {"type": "object", "additionalProperties": False,
                "properties": {"workspace": {"const": str(WORKSPACE)}, "model": {"const": MODEL}},
                "required": ["workspace", "model"]}, "uiSchema": None, "defaults": CONFIG, "metadata": {}},
            "capabilities": {"createAndStartSession": True, "modelCatalog": True, "permissionCatalog": True},
            "metadata": {"acceptanceOnly": True}, "instancePolicy": "single", "maxInstances": 1}


class SingleSessionAdapter:
    def __init__(self, runner=None):
        self.runtime_id: str | None = None
        self.session_id: str | None = None
        self.thread_id: str | None = None
        self.phase = "discovery"
        self.started = False
        self.spent = False
        self.runner = runner or OsirAcceptanceRunner()
        self.rpc_methods: list[str] = []

    async def dispatch(self, method: str, params: dict) -> dict:
        self.rpc_methods.append(method)
        if method == "runtime.discover" and params == {}:
            return {"runtimeTypes": [descriptor()]}
        if method == "runtime.validateConfig" and self.phase == "creating-runtime":
            if (set(params) - {"runtime", "runtimeId", "name", "config", "configRevision"}
                    or params.get("runtime") != "codex" or params.get("config") != CONFIG
                    or not isinstance(params.get("runtimeId"), str)):
                raise VerificationDenied()
            if self.runtime_id not in (None, params["runtimeId"]):
                raise VerificationDenied()
            self.runtime_id = params["runtimeId"]
            return {"runtime": "codex", "runtimeId": self.runtime_id, "valid": True}
        if params.get("runtime") != "codex" or not self.runtime_id or params.get("runtimeId") != self.runtime_id:
            raise VerificationDenied()
        scope = {"runtime": "codex", "runtimeId": self.runtime_id}
        if self.started and method in {"runtime.capabilities", "runtime.modelCatalog", "runtime.permissionCatalog"}:
            if set(params) - {"runtime", "runtimeId", "query", "limit"}:
                raise VerificationDenied()
            if method == "runtime.capabilities":
                return {**scope, "capabilitySet": {"revision": 1, "capabilities": [
                    {"capabilityId": name, "scope": "runtime", "runtime": "codex",
                     "supported": True, "available": True, "allowed": True}
                    for name in ("catalog.model", "catalog.permission")
                ]}}
            if method == "runtime.modelCatalog":
                return {**scope, "catalog": {"runtime": "codex", "revision": 1, "models": [
                    {"id": MODEL, "displayName": MODEL, "selectionId": MODEL_SELECTION,
                     "default": True, "reasoningItems": [], "metadata": {}}
                ]}}
            return {**scope, "catalog": {"runtime": "codex", "revision": 1, "permissions": [
                {"id": "osir-acceptance-readonly", "displayName": "OSIR isolated read-only verification",
                 "selectionId": PERMISSION_SELECTION, "default": True, "metadata": {}}
            ]}}
        if method == "runtime.start" and self.phase == "starting-runtime" and params.get("config") == CONFIG:
            self.started = True
            return {"runtime": "codex", "runtimeId": self.runtime_id, "status": "running"}
        if method == "runtime.stop" and self.started:
            self.started = False
            return {"runtime": "codex", "runtimeId": self.runtime_id, "status": "stopped"}
        if method == "session.create" and self.phase == "creating-session" and self.started and not self.spent:
            allowed = {"runtime", "runtimeId", "sessionId", "content", "title", "cwd", "clientMessageId", "selections"}
            if (set(params) - allowed or params.get("content") != PROMPT or params.get("cwd") != str(WORKSPACE)
                    or params.get("selections", {}) not in ({}, SELECTIONS)
                    or not isinstance(params.get("sessionId"), str) or not params["sessionId"].startswith("sess_")):
                raise VerificationDenied()
            self.spent = True  # Never replay an ambiguous/failed native launch.
            self.session_id = params["sessionId"]
            result = await asyncio.to_thread(self.runner.run)
            # The runner is responsible for OS isolation, JSON-event allowlisting
            # and new-thread attestation; only its minimal fixed result crosses.
            thread_id = result.thread_id
            if result.text != REPLY or str(UUID(thread_id)) != thread_id:
                raise VerificationDenied()
            self.thread_id = thread_id
            return {"runtime": "codex", "runtimeId": self.runtime_id, "sessionId": self.session_id,
                    "externalSessionId": self.thread_id, "created": True, "messageAccepted": True, "ok": True}
        if (self.session_id and params.get("sessionId") == self.session_id
                and params.get("externalSessionId") in (None, self.thread_id)
                and not set(params) - {"runtime", "runtimeId", "sessionId", "externalSessionId"}):
            session_scope = {**scope, "sessionId": self.session_id, "externalSessionId": self.thread_id}
            if method == "session.capabilities":
                return {**session_scope, "capabilitySet": {"revision": 1, "capabilities": []}}
            if method == "session.notices":
                return {**session_scope, "notices": []}
            if method == "session.state":
                return {**session_scope, "state": {**session_scope,
                    "status": "idle" if self.thread_id else "running", "selections": dict(SELECTIONS), "metadata": {}}}
        raise VerificationDenied()

    def notifications(self) -> list[dict]:
        if not self.spent or not self.thread_id or not self.session_id or not self.runtime_id:
            raise VerificationDenied()
        items = []
        for sequence, role, text in ((1, "user", PROMPT), (2, "assistant", REPLY)):
            content = {"kind": "markdown", "text": text}
            items.append({"id": f"osir-verification-{self.session_id}-{role}", "sessionId": self.session_id,
                          "type": "message", "status": "done", "role": role, "content": content,
                          "source": {"runtime": "codex", "sessionId": self.thread_id},
                          "orderSeq": sequence, "revision": 1,
                          "contentHash": timeline_content_hash(item_type="message", status="done", role=role, content=content)})
        scope = {"runtime": "codex", "runtimeId": self.runtime_id, "sessionId": self.session_id}
        return [{"method": "timeline.sync", "params": {**scope, "complete": True, "items": items}},
                {"method": "session.turnEnded", "params": {**scope, "externalSessionId": self.thread_id, "outcome": "completed"}},
                {"method": "session.state.updated", "params": {**scope, "externalSessionId": self.thread_id, "status": "idle"}}]


async def verify(access_token: str, desktop_device: ExistingDesktopDevice | None = None, *,
                 wait_for_web: bool = False, hold_seconds: int = 0,
                 compatibility_cli: Path | None = None) -> dict:
    if not isinstance(wait_for_web, bool) or type(hold_seconds) is not int or not 0 <= hold_seconds <= 180:
        raise VerificationDenied("invalid verification duration")
    if wait_for_web and desktop_device is None:
        raise VerificationDenied("web verification requires the existing desktop device")
    # Explicit local harness choice only; never accepted from a runtime RPC.
    # The native runner still verifies the pinned compatibility binary hash.
    runner_options = {} if compatibility_cli is None else {"compatibility_cli": compatibility_cli}
    adapter = SingleSessionAdapter(OsirAcceptanceRunner(**runner_options))
    # Native isolation preflight is mandatory even before cloud authentication.
    report = await asyncio.to_thread(adapter.runner.offline_preflight)
    if not report.filesystem_verified or not report.cli_startup_verified:
        raise VerificationDenied()
    # run() uses a fresh runner reservation and repeats its own prerequisites.
    adapter.runner = OsirAcceptanceRunner(**runner_options)
    async with httpx.AsyncClient(base_url=ORIGIN + "/api/v2", timeout=75, trust_env=False,
                                 follow_redirects=False) as client:
        headers = {"Authorization": "Bearer " + access_token}

        async def api(method, route, body=None, *, auth=headers):
            response = await client.request(method, route, headers=auth, json=body)
            if not response.is_success:
                raise VerificationDenied(f"{adapter.phase}: HTTP {response.status_code}")
            return response.json() if response.content else None

        if desktop_device is None:
            created = await api("POST", "/connectors", {"name": "OSIR isolated Codex verification 20261113",
                                "connectorKind": "desktop", "installationId": str(uuid4())})
            connector_id = created["connector"]["id"]
            connector_token = created["connectorToken"]
        else:
            connector_id = desktop_device.connector_id
            # The account-authenticated route verifies ownership. Do not revoke
            # or replace another running Connector to make the check pass.
            existing = await api("GET", f"/connectors/{connector_id}")
            if existing["connector"]["status"] != "offline":
                raise VerificationDenied("desktop device already online")
            connector_token = desktop_device.token
        connector_grant = await api("POST", "/connector/auth", auth={
            "Authorization": f"Connector {connector_id}:{connector_token}"})
        connector_headers = {"Authorization": "Bearer " + connector_grant["accessToken"]}
        tasks = []
        session_created = asyncio.Event()
        deactivated = False
        async with websockets.connect(ORIGIN.replace("https:", "wss:") + "/api/v2/connector/ws",
                                      additional_headers={**connector_headers, "X-Device-OS": "macos"},
                                      proxy=None, max_size=65536) as ws:
            async def reader():
                async for raw in ws:
                    message = json.loads(raw)
                    if message.get("type") != "request":
                        continue
                    reply = {"id": message.get("id"), "type": "response"}
                    try:
                        reply.update(ok=True, result=await adapter.dispatch(message.get("method"), message.get("params", {})))
                    except Exception:  # noqa: BLE001 - no native error content crosses cloud boundary
                        reply.update(ok=False, error={"code": "verification_denied", "message": "Restricted verification failed"})
                    await ws.send(json.dumps(reply))
                    if reply.get("ok") and message.get("method") == "session.create":
                        session_created.set()

            async def heartbeat():
                while True:
                    await ws.send(json.dumps({"type": "notification", "method": "connector.heartbeat", "params": {}}))
                    await asyncio.sleep(5)

            tasks = [asyncio.create_task(reader()), asyncio.create_task(heartbeat())]
            try:
                for _ in range(40):
                    state = await api("GET", f"/connectors/{connector_id}")
                    if state["connector"]["status"] == "online":
                        break
                    await asyncio.sleep(.25)
                else:
                    raise VerificationDenied("online not confirmed")
                # Presence becomes ready before the initial async discovery is
                # persisted. Explicit discovery gives us an acknowledged fence.
                await api("POST", f"/connectors/{connector_id}/runtime-types/discover")
                adapter.phase = "creating-runtime"
                runtime = await api("POST", f"/connectors/{connector_id}/runtimes", {
                    "runtimeType": "codex", "name": "OSIR fixed verification", "config": CONFIG, "active": False})
                if runtime["runtimeId"] != adapter.runtime_id:
                    raise VerificationDenied()
                adapter.phase = "starting-runtime"
                await api("PUT", f"/connectors/{connector_id}/runtimes/{adapter.runtime_id}/active", {"active": True})
                project = await api("POST", "/projects", {"name": "OSIR isolated verification " + uuid4().hex[:8],
                    "connectorId": connector_id, "workspacePath": str(WORKSPACE), "attachMatchingSessions": False})
                adapter.phase = "creating-session"
                if wait_for_web:
                    print(json.dumps({"phase": "web-session-ready", "connectorId": connector_id,
                                      "runtimeId": adapter.runtime_id, "projectId": project["project"]["id"],
                                      "prompt": PROMPT, "workspace": str(WORKSPACE)}), flush=True)
                    async with asyncio.timeout(120):
                        await session_created.wait()
                    session = await api("GET", f"/sessions/{adapter.session_id}/meta")
                    if session["session"].get("projectId") != project["project"]["id"]:
                        raise VerificationDenied("web test project mismatch")
                else:
                    session = await api("POST", "/sessions/create-and-start", {"connectorId": connector_id,
                        "projectId": project["project"]["id"], "runtime": "codex", "runtimeId": adapter.runtime_id,
                        "cwd": str(WORKSPACE), "title": "OSIR local-cloud verification", "content": PROMPT})
                if session["session"]["id"] != adapter.session_id or not adapter.thread_id:
                    raise VerificationDenied()
                adapter.phase = "persisting-test-only"
                ingest = await api("POST", "/connector/ingest", {"notifications": adapter.notifications()}, auth=connector_headers)
                if ingest.get("rejected"):
                    raise VerificationDenied()
                timeline = await api("GET", f"/sessions/{adapter.session_id}/timeline")
                texts = [(item["role"], item["content"].get("text")) for item in timeline["items"]]
                if texts != [("user", PROMPT), ("assistant", REPLY)]:
                    raise VerificationDenied("persisted test reply mismatch")
                if hold_seconds:
                    print(json.dumps({"phase": "test-timeline-persisted", "connectorId": connector_id,
                                      "sessionId": adapter.session_id, "persistedMessages": 2,
                                      "webSubmitReceived": wait_for_web, "holdSeconds": hold_seconds}), flush=True)
                    await asyncio.sleep(hold_seconds)
            finally:
                if adapter.runtime_id is not None:
                    try:
                        async with asyncio.timeout(10):
                            stopped = await api("PUT", f"/connectors/{connector_id}/runtimes/{adapter.runtime_id}/active", {"active": False})
                            deactivated = stopped.get("active") is False
                    except (httpx.HTTPError, TimeoutError, VerificationDenied):
                        # Preserve the original failure; closing WSS stops local
                        # execution regardless. Never start/retry a native turn.
                        pass
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
        if not deactivated:
            raise VerificationDenied("runtime deactivation not confirmed")
        for _ in range(30):
            disconnected = await api("GET", f"/connectors/{connector_id}")
            if disconnected["connector"]["status"] == "offline":
                break
            await asyncio.sleep(.25)
        else:
            raise VerificationDenied("disconnect not confirmed")
        return {"kind": "real-cloud-fixed-codex-session", "checkedAt": datetime.now(UTC).isoformat(),
                "deviceSource": "existing-desktop-binding" if desktop_device else "isolated-test-registration",
                "connectorId": connector_id, "runtimeId": adapter.runtime_id, "sessionId": adapter.session_id,
                "nativeThreadId": adapter.thread_id, "model": MODEL, "workspace": str(WORKSPACE),
                "replyMatched": True, "persistedMessages": 2, "rpcMethods": adapter.rpc_methods,
                "offlineAfterClose": True,
                "runtimeDeactivated": deactivated,
                "webSubmitReceived": wait_for_web,
                "webUiSendVerified": False, "codexDesktopTakeoverVerified": False}


def main():
    try:
        data = json.loads(sys.stdin.buffer.readline(32769))
        device = ExistingDesktopDevice.parse(data["desktopDevice"]) if "desktopDevice" in data else None
        print(json.dumps(asyncio.run(asyncio.wait_for(verify(data["accessToken"], device,
            wait_for_web=data.get("waitForWeb", False), hold_seconds=data.get("holdSeconds", 0),
            compatibility_cli=Path(data["compatibilityCli"]) if "compatibilityCli" in data else None), 420))))
    except Exception as exc:  # noqa: BLE001 - do not log raw network/native failures
        print(json.dumps({"ok": False, "errorType": type(exc).__name__,
                          "stage": str(exc) if isinstance(exc, VerificationDenied) else "local preflight"}))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
