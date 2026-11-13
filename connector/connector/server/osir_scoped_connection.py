"""Desktop-owned development connection for the explicitly granted test directory.

No normal Connector imports or fallthrough. Credentials arrive once on stdin;
stdout contains only fixed lifecycle fields and IDs. A local EOF/stop closes WSS.
This is a bounded text-only test connection, not a released general Agent host.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

import httpx
import websockets

from connector.server.osir_cloud_verification import CONFIG, ExistingDesktopDevice
from connector.server.osir_connection_probe import ORIGIN
from connector.server.osir_scoped_runtime import OsirScopedRuntime, ScopedRuntimeDenied


class ScopedConnection:
    def __init__(self, compatibility_cli: Path):
        self.cli = compatibility_cli
        self.runtime: OsirScopedRuntime | None = None
        self.discovery = OsirScopedRuntime(runtime_id="rti_local_preflight", compatibility_cli=self.cli)
        self.expected_runtime: str | None = None
        self.new_runtime = False
        self.awaiting_first_start = True

    async def dispatch(self, method: str, params: dict) -> dict:
        if method == "runtime.discover" and params == {}:
            descriptor = self.discovery.descriptor()
            # Runtime RPC schemas carry a runtime field; discovery's strict
            # server descriptor wraps it and requires that field to be absent.
            descriptor["configSchema"].pop("runtime", None)
            return {"runtimeTypes": [descriptor]}
        if method == "runtime.validateConfig":
            identifier = params.get("runtimeId")
            if self.runtime is None and self.new_runtime and isinstance(identifier, str):
                candidate = OsirScopedRuntime(runtime_id=identifier, compatibility_cli=self.cli)
                # Validate the fixed config before any native preflight.
                revision = params.get("configRevision")
                if (params.get("config") != CONFIG or type(revision) is not int
                        or not 1 <= revision <= 9007199254740991):
                    raise ScopedRuntimeDenied("Invalid scoped wire configuration revision")
                await candidate.dispatch(method, {**params, "configRevision": 1})
                await candidate.preflight()
                self.runtime = candidate
                self.expected_runtime = identifier
        if self.runtime is None:
            raise ScopedRuntimeDenied("No locally selected scoped runtime")
        if method == "runtime.stop" and self.awaiting_first_start:
            # The server reconciles a saved inactive runtime when WSS connects.
            # Acknowledge that already-stopped state without revoking the new
            # local grant. After its first start, every stop remains final.
            await self.runtime.dispatch("runtime.config", params)
            return {"runtime": "codex", "runtimeId": self.expected_runtime, "status": "stopped"}
        if method in {"runtime.validateConfig", "runtime.start"}:
            # Server configRevision is updatedAt in milliseconds, NOT the
            # provider's schema revision. Accept only the unchanged exact config
            # and a valid wire revision, then select our fixed local schema v1.
            revision = params.get("configRevision")
            if (params.get("config") != CONFIG or type(revision) is not int
                    or not 1 <= revision <= 9007199254740991):
                raise ScopedRuntimeDenied("Invalid scoped wire configuration revision")
            params = {**params, "configRevision": 1}
        result = await self.runtime.dispatch(method, params)
        if method == "runtime.start":
            self.awaiting_first_start = False
        return result


def emit(phase: str, **fields):
    line = json.dumps({"phase": phase, **fields})
    # Dedicated local development receipt; never raw native/network output.
    receipt = Path("/Users/ouwei/agents-anywhere/.local-dev/connection-verification-20261113/scoped-lifecycle.jsonl")
    fd = os.open(receipt, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "a") as stream:
        stream.write(line + "\n")
    print(line, flush=True)


async def connect(data: dict) -> None:
    device = ExistingDesktopDevice.parse(data["desktopDevice"])
    if data.get("syncExistingOnConnect") is not False:
        raise ScopedRuntimeDenied("Existing history synchronization must be disabled")
    connection = ScopedConnection(Path(data["compatibilityCli"]))
    await connection.discovery.preflight()
    stop = asyncio.Event()
    async with httpx.AsyncClient(base_url=ORIGIN + "/api/v2", timeout=65,
                                 trust_env=False, follow_redirects=False) as client:
        async def api(method, route, body=None, *, headers=None):
            emit("scoped-cloud-step", method=method, route=route)
            response = await client.request(method, route, json=body, headers=headers or {
                "Authorization": "Bearer " + data["accessToken"]})
            if not response.is_success:
                raise ScopedRuntimeDenied("Cloud request rejected: " + str(response.status_code))
            return response.json()

        existing = await api("GET", f"/connectors/{device.connector_id}")
        if existing["connector"]["status"] != "offline":
            raise ScopedRuntimeDenied("Device already connected; no takeover")
        inventory = await api("GET", f"/connectors/{device.connector_id}/runtimes")
        candidates = [r for r in inventory["runtimes"] if r.get("config") == CONFIG
                      and r.get("name") in {"OSIR fixed verification", "OSIR scoped test conversations"}]
        if len(candidates) > 1:
            raise ScopedRuntimeDenied("Ambiguous scoped runtime; local review required")
        if candidates:
            connection.expected_runtime = candidates[0]["runtimeId"]
            connection.runtime = OsirScopedRuntime(runtime_id=connection.expected_runtime,
                                                    compatibility_cli=connection.cli)
            await connection.runtime.preflight()
        else:
            connection.new_runtime = True
        grant = await api("POST", "/connector/auth", headers={
            "Authorization": f"Connector {device.connector_id}:{device.token}"})
        connector_headers = {"Authorization": "Bearer " + grant["accessToken"]}
        async with websockets.connect(ORIGIN.replace("https:", "wss:") + "/api/v2/connector/ws",
                additional_headers={**connector_headers, "X-Device-OS": "macos"},
                proxy=None, max_size=65536) as ws:
            async def reader():
                async for raw in ws:
                    message = json.loads(raw)
                    if message.get("type") != "request":
                        continue
                    method, params = message.get("method"), message.get("params", {})
                    reply = {"id": message.get("id"), "type": "response"}
                    try:
                        result = await connection.dispatch(method, params)
                        reply.update(ok=True, result=result)
                    except Exception as exc:  # noqa: BLE001 - never expose native or credential errors
                        emit("scoped-rpc-denied", method=method if isinstance(method, str) else "invalid",
                             errorType=type(exc).__name__,
                             reason=str(exc) if isinstance(exc, ScopedRuntimeDenied) else "Invalid scoped operation")
                        reply.update(ok=False, error={"code": "scoped_request_denied",
                            "message": "Request exceeds the local test grant or execution failed"})
                    await ws.send(json.dumps(reply))
                    if reply.get("ok") and method in {"session.create", "session.send_message", "session.sync"}:
                        notifications = connection.runtime.notifications(params["sessionId"])
                        ingested = await api("POST", "/connector/ingest", {"notifications": notifications},
                                             headers=connector_headers)
                        if ingested.get("rejected"):
                            raise ScopedRuntimeDenied("Scoped timeline rejected")
                        emit("scoped-turn-synced", sessionId=params["sessionId"],
                             messages=len(notifications[0]["params"]["items"]))
                stop.set()

            async def heartbeat():
                while not stop.is_set():
                    await ws.send(json.dumps({"type": "notification", "method": "connector.heartbeat", "params": {}}))
                    await asyncio.sleep(5)

            async def commands():
                # No cloud command can select paths, binaries, models or history.
                reader = asyncio.StreamReader(limit=1024)
                transport, _ = await asyncio.get_running_loop().connect_read_pipe(
                    lambda: asyncio.StreamReaderProtocol(reader), sys.stdin.buffer)
                try:
                    await reader.readline()
                finally:
                    transport.close()
                    stop.set()

            tasks = [asyncio.create_task(reader()), asyncio.create_task(heartbeat()),
                     asyncio.create_task(commands())]
            try:
                for _ in range(40):
                    presence = await api("GET", f"/connectors/{device.connector_id}")
                    if presence["connector"]["status"] == "online":
                        break
                    await asyncio.sleep(.25)
                else:
                    raise ScopedRuntimeDenied("Scoped presence not confirmed")
                await api("POST", f"/connectors/{device.connector_id}/runtime-types/discover")
                if connection.new_runtime:
                    await api("POST", f"/connectors/{device.connector_id}/runtimes", {
                        "runtimeType": "codex", "name": "OSIR scoped test conversations",
                        "config": CONFIG, "active": False})
                    connection.new_runtime = False
                runtime_id = connection.expected_runtime
                await api("PUT", f"/connectors/{device.connector_id}/runtimes/{runtime_id}/active", {"active": True})
                projects = await api("GET", "/projects")
                project = next((p for p in projects["projects"] if p.get("connectorId") == device.connector_id
                                and p.get("workspacePath") == CONFIG["workspace"]), None)
                if project is None:
                    project = (await api("POST", "/projects", {"name": "OSIR 授权测试目录",
                        "connectorId": device.connector_id, "workspacePath": CONFIG["workspace"],
                        "attachMatchingSessions": False}))["project"]
                emit("scoped-connection-ready", connectorId=device.connector_id, runtimeId=runtime_id,
                     projectId=project["id"], workspace=CONFIG["workspace"], textOnly=True)
                tasks.append(asyncio.create_task(stop.wait()))
                done, _ = await asyncio.wait(tasks,
                                             return_when=asyncio.FIRST_COMPLETED)
                for task in done:
                    if not task.cancelled() and task.exception():
                        raise ScopedRuntimeDenied("Scoped transport stopped")
            finally:
                if connection.expected_runtime:
                    try:
                        await api("PUT", f"/connectors/{device.connector_id}/runtimes/{connection.expected_runtime}/active",
                                  {"active": False})
                    except (httpx.HTTPError, ScopedRuntimeDenied):
                        pass  # Main repeats the offline deactivation with a fresh app session.
                if connection.runtime:
                    connection.runtime.stop()
                for task in tasks:
                    task.cancel()
                await ws.close()
                await asyncio.gather(*tasks, return_exceptions=True)
                emit("scoped-connection-closed", connectorId=device.connector_id,
                     runtimeId=connection.expected_runtime)


def main():
    try:
        data = json.loads(sys.stdin.buffer.readline(32769))
        asyncio.run(connect(data))
    except Exception as exc:  # noqa: BLE001 - only fixed lifecycle metadata leaves this process
        emit("scoped-connection-failed", errorType=type(exc).__name__,
             reason=str(exc) if isinstance(exc, ScopedRuntimeDenied) else "Local scoped operation failed")
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
