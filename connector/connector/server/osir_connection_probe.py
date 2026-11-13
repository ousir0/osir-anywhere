"""Bounded real-cloud connection diagnostic; never constructs runtime/local services.

The account access token arrives over stdin from the desktop session manager. It
is never written to disk. This verifies the transport only, not Agent execution.
"""
from __future__ import annotations

import asyncio
import json
import sys
from datetime import UTC, datetime
from uuid import uuid4

import httpx
import websockets

ORIGIN = "https://anywhere.osirclaw.com"


def response_for(message: dict) -> dict | None:
    if message.get("type") != "request" or not isinstance(message.get("id"), str):
        return None
    if message.get("method") == "runtime.discover" and message.get("params") == {}:
        return {"id": message["id"], "type": "response", "ok": True,
                "result": {"runtimeTypes": []}}
    return {"id": message["id"], "type": "response", "ok": False,
            "error": {"code": "probe_denied", "message": "Connection diagnostic only"}}


async def run(access_token: str) -> dict:
    if not isinstance(access_token, str) or not access_token or any(c.isspace() for c in access_token):
        raise ValueError("invalid diagnostic input")
    async with httpx.AsyncClient(base_url=ORIGIN + "/api/v2", timeout=15,
                                 follow_redirects=False, trust_env=False) as client:
        headers = {"Authorization": "Bearer " + access_token}
        created = await client.post("/connectors", headers=headers, json={
            "name": "OSIR isolated connection verification 20261113",
            "connectorKind": "desktop", "installationId": str(uuid4())})
        created.raise_for_status()
        grant = created.json()
        connector_id = grant["connector"]["id"]
        auth = await client.post("/connector/auth", headers={
            "Authorization": f"Connector {connector_id}:{grant['connectorToken']}"})
        auth.raise_for_status()
        request_count = 0
        reader_task = None
        online = False
        roundtrip = False
        try:
            async with websockets.connect(ORIGIN.replace("https:", "wss:") + "/api/v2/connector/ws",
                                          additional_headers={"Authorization": "Bearer " + auth.json()["accessToken"],
                                                              "X-Device-OS": "macos"},
                                          proxy=None, max_size=65536, open_timeout=15) as ws:
                async def reader():
                    nonlocal request_count
                    async for raw in ws:
                        message = json.loads(raw)
                        reply = response_for(message)
                        if reply is not None:
                            if reply.get("ok"):
                                request_count += 1
                            await ws.send(json.dumps(reply))
                reader_task = asyncio.create_task(reader())
                for _ in range(30):
                    if reader_task.done():
                        await reader_task
                        raise RuntimeError("diagnostic socket ended early")
                    await ws.send(json.dumps({"type": "notification", "method": "connector.heartbeat", "params": {}}))
                    state = await client.get(f"/connectors/{connector_id}", headers=headers)
                    state.raise_for_status()
                    if state.json()["connector"]["status"] == "online":
                        online = True
                        break
                    await asyncio.sleep(0.25)
                if not online:
                    raise RuntimeError("cloud did not confirm online status")
                before = request_count
                discover = await client.post(f"/connectors/{connector_id}/runtime-types/discover", headers=headers)
                discover.raise_for_status()
                roundtrip = request_count > before and discover.json()["runtimeTypes"] == []
                if not roundtrip:
                    raise RuntimeError("cloud RPC roundtrip was not confirmed")
        finally:
            if reader_task is not None:
                reader_task.cancel()
                await asyncio.gather(reader_task, return_exceptions=True)
        offline = False
        for _ in range(30):
            state = await client.get(f"/connectors/{connector_id}", headers=headers)
            state.raise_for_status()
            if state.json()["connector"]["status"] == "offline":
                offline = True
                break
            await asyncio.sleep(0.25)
        if not offline:
            raise RuntimeError("cloud did not confirm disconnect")
        return {"kind": "real-cloud-transport-only", "checkedAt": datetime.now(UTC).isoformat(),
                "origin": ORIGIN, "connectorId": connector_id, "onlineConfirmed": online,
                "cloudToLocalRpcConfirmed": roundtrip, "rpcResponses": request_count,
                "offlineAfterClose": offline, "runtimeTypes": [], "agentConversationVerified": False}


def main() -> None:
    try:
        data = json.loads(sys.stdin.buffer.readline(32769))
        result = asyncio.run(asyncio.wait_for(run(data["accessToken"]), timeout=90))
        print(json.dumps(result))
    except Exception as exc:  # noqa: BLE001 - redact every credential-bearing failure
        # Errors may embed credentials/URLs; deliberately omit exception text.
        print(json.dumps({"ok": False, "errorType": type(exc).__name__}))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
