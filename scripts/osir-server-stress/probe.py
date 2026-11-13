#!/usr/bin/env python3
"""Isolated PG18 five-session workload, launched only by reviewed controller.
No local build, inherited production settings, model calls or host connections.
Fixed 5-user/15-WS/1200-event/300-read workload and original correctness gates.
Not historical OOM reproduction, production capacity or a product user limit.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import itertools
import json
import math
import os
import platform
import secrets
import signal
import subprocess
import sys
import time
from pathlib import Path
import re
import socket

ROOT = Path(__file__).resolve().parents[1]
LABEL = "osir-five-active-owner"
REPORT = "OSIR-ANYWHERE-CAPACITY-FIVE-ACTIVE-2026-11-14.md"
PREFIX = os.environ.get("OSIR_ISOLATED_RUN_ID", "invalid")
RUN_ID = os.environ.get("OSIR_ISOLATED_RUN_ID", "")
DB = "osir_pg18_test_" + RUN_ID.rsplit("-", 1)[-1]
# These gates are fixed BEFORE the run and are never relaxed from results.
GATES = {
    "projection_p95_ms_lt": 1000,
    "projection_max_ms_lt": 3000,
    "errors": 0,
    "events": 1200,
    "history_reads": 300,
    "minimum_achieved_events_per_s": 19,
    "drain_timeout_s": 15,
}
ENV = {
    "PYTHONPATH": "/app/server",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONUNBUFFERED": "1",
    "CAPACITY_TEST_ONLY": "1",
    "AGENT_SERVER_DB_URL": f"postgresql+asyncpg://capacity_test@pg:5432/{DB}",
    "AGENT_SERVER_REDIS_URL": "redis://redis:6379/0",
    "AGENT_SERVER_REDIS_PREFIX": PREFIX,
    "AGENT_SERVER_SECRET": "synthetic-capacity-only-not-production",
    "AGENT_SERVER_WORKERS": "1",
    "AGENT_SERVER_EVENT_WORKERS": "1",
    "AGENT_SERVER_EVENT_QUEUE_ITEMS": "8",
    "AGENT_SERVER_EVENT_QUEUE_BYTES": "4194304",
    "AGENT_SERVER_DB_POOL_SIZE": "2",
    "AGENT_SERVER_DB_MAX_OVERFLOW": "2",
    "AGENT_SERVER_DB_POOL_TIMEOUT": "5",
    "AGENT_SERVER_TIMELINE_MAX_LANES": "128",
    "AGENT_SERVER_FILES_BACKEND": "local",
    "AGENT_SERVER_FILES_LOCAL_ROOT": "/tmp/capacity-files",
    "AGENT_SERVER_HOST": "0.0.0.0",
    "AGENT_SERVER_PORT": "8000",
}


def distribution(values):
    v = sorted(values)

    def p(q):
        return round(v[max(0, math.ceil(len(v) * q) - 1)], 3) if v else None

    return {"n": len(v), "p50_ms": p(0.5), "p95_ms": p(0.95), "max_ms": p(1)}


def internal_guard():
    if not re.fullmatch(r"osir-pg18-test-[0-9a-f]{12}", RUN_ID):
        raise RuntimeError("unique isolated run ID required")
    if not (Path("/.dockerenv").exists() or Path("/run/.containerenv").exists()):
        raise RuntimeError("container-only probe")
    if socket.gethostname() not in {RUN_ID + "-api", RUN_ID + "-driver"}:
        raise RuntimeError("isolated hostname mismatch")
    for key, value in ENV.items():
        if os.environ.get(key) != value:
            raise RuntimeError("test environment mismatch: " + key)
    if any(k.startswith("AGENT_SERVER_") and k not in ENV for k in os.environ):
        raise RuntimeError("inherited production settings refused")
    if "test" not in DB or DB != "osir_pg18_test_" + RUN_ID.rsplit("-", 1)[-1]:
        raise RuntimeError("test DB guard failed")


async def serve():
    import uvicorn
    from agent_server.app import create_app
    from agent_server.core.auth import create_user_access_token
    from fastapi import Request
    from loguru import logger

    logger.remove()  # No content/tokens in container logs.
    app = create_app()
    for i in range(5):
        await app.state.store.create_user(
            user_id=f"capacity-user-{i}", password_hash="synthetic-unusable-hash"
        )
    tokens = [create_user_access_token(f"capacity-user-{i}") for i in range(5)]
    counters = {"active_http": 0, "max_active_http": 0, "http_5xx": 0}
    peaks = {}
    samples = []
    loop_lag_ms = []
    monitor_stop = asyncio.Event()

    @app.middleware("http")
    async def inflight(request: Request, call_next):
        counters["active_http"] += 1
        counters["max_active_http"] = max(
            counters["max_active_http"], counters["active_http"]
        )
        try:
            response = await call_next(request)
            counters["http_5xx"] += int(response.status_code >= 500)
            return response
        finally:
            counters["active_http"] -= 1

    def local_metrics():
        pool = app.state.store.engine.pool
        broker = app.state.timeline_broker
        event_pool = broker._event_pool
        # Connector pumps are bound methods on live connections. Read only.
        pumps = [
            c.drain_notifications.__self__
            for c in app.state.rpc._connections.values()
            if c.drain_notifications is not None
        ]
        return {
            "pool_checkedout": pool.checkedout(),
            "pool_size": pool.size(),
            "pool_overflow": max(0, pool.overflow()),
            "event_pending": event_pool.pending,
            "event_pending_bytes": event_pool.pending_bytes,
            "event_worker_processes": len(
                getattr(event_pool._executor, "_processes", {}) or {}
            ),
            "event_worker_pids": sorted(
                (getattr(event_pool._executor, "_processes", {}) or {}).keys()
            ),
            "event_max_pending": event_pool._max_pending,
            "event_max_pending_bytes": event_pool._max_pending_bytes,
            "event_threshold_bytes": event_pool._threshold_bytes,
            "subscriber_queue": sum(
                q.qsize() for v in broker._subs.values() for q in v
            ),
            "subscriber_overflow": sum(
                q.overflowed.is_set() for v in broker._subs.values() for q in v
            ),
            "session_subscribers": sum(len(v) for v in broker._subs.values()),
            "dashboard_subscribers": sum(
                len(v) for v in broker._dashboard_subs.values()
            ),
            "connector_connections": len(pumps),
            "connector_pending": sum(p._pending for p in pumps),
            "connector_pending_bytes": sum(p._pending_bytes for p in pumps),
            "connector_overloaded": sum(p.overloaded for p in pumps),
            "timeline_lanes": len(app.state.timeline_write_buffer._lanes),
        }

    async def monitor():
        last_redis = 0.0
        expected_tick = time.monotonic()
        while not monitor_stop.is_set():
            loop_lag_ms.append(max(0, time.monotonic() - expected_tick) * 1000)
            m = local_metrics()
            for k, v in m.items():
                if isinstance(v, (int, float)):
                    peaks[k] = max(peaks.get(k, 0), v)
            if time.monotonic() - last_redis >= 0.5:
                last_redis = time.monotonic()
                try:
                    r = app.state.redis.client
                    dirty = sorted(await r.smembers(f"{PREFIX}:timeline-buffer:dirty"))
                    sizes = [
                        await r.hlen(
                            f"{PREFIX}:timeline-buffer:{s.decode() if isinstance(s, bytes) else s}:items"
                        )
                        for s in dirty
                    ]
                    m.update(dirty_sessions=len(dirty), pending_items=sum(sizes))
                    for k in ("dirty_sessions", "pending_items"):
                        peaks[k] = max(peaks.get(k, 0), m[k])
                    samples.append({"monotonic": time.monotonic(), **m})
                    del samples[:-120]
                except Exception as exc:  # noqa: BLE001 - aggregate evidence / continue ownership cleanup
                    peaks["monitor_errors"] = peaks.get("monitor_errors", 0) + 1
                    peaks["monitor_error_type"] = type(exc).__name__
            expected_tick = time.monotonic() + 0.05
            await asyncio.sleep(0.05)

    @app.get("/__capacity/fixtures")
    async def fixtures():
        return {"tokens": tokens}

    def task_stacks():
        stacks = []
        for task in asyncio.all_tasks():
            coro, frames = task.get_coro(), []
            for _ in range(24):
                frame = getattr(coro, "cr_frame", None) or getattr(
                    coro, "gi_frame", None
                )
                if frame:
                    frames.append(
                        {
                            "file": frame.f_code.co_filename,
                            "line": frame.f_lineno,
                            "function": frame.f_code.co_name,
                        }
                    )
                coro = getattr(coro, "cr_await", None) or getattr(
                    coro, "gi_yieldfrom", None
                )
                if coro is None:
                    break
            stacks.append({"frames": frames})
        return stacks[:300]

    @app.get("/__capacity/metrics")
    async def metrics():
        return {
            "current": local_metrics(),
            "peaks": dict(peaks),
            "counters": dict(counters),
            "samples": list(samples),
            "api_pid": os.getpid(),
            "loop_lag": distribution(loop_lag_ms),
            "task_stacks": [],
            "redis_lock_stats": __import__("dataclasses").asdict(app.state.redis.stats),
        }

    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host="0.0.0.0",
            port=8000,
            workers=1,
            access_log=False,
            log_level="error",
        )
    )

    async def observed_monitor():
        while not server.started:
            await asyncio.sleep(0.05)
        await monitor()

    task = asyncio.create_task(observed_monitor())
    try:
        await server.serve()
    finally:
        monitor_stop.set()
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


def notification(sid, item_id, revision, text, order, *, status="running"):
    return {
        "method": "timeline.itemUpsert",
        "params": {
            "sessionId": sid,
            "runtime": "codex",
            "item": {
                "id": item_id,
                "sessionId": sid,
                "turnId": "synthetic-turn",
                "type": "message",
                "role": "assistant",
                "status": status,
                "content": {"text": text, "format": "markdown"},
                "source": {
                    "runtime": "codex",
                    "sessionId": "synthetic-native",
                    "turnId": "synthetic-turn",
                    "itemId": item_id,
                    "itemType": "agentMessage",
                },
                "orderSeq": order,
                "revision": revision,
                "contentHash": "sha256:" + hashlib.sha256(text.encode()).hexdigest(),
            },
        },
    }


async def driver():
    import asyncpg
    import httpx
    import websockets
    from redis.asyncio import Redis

    result = {
        "scope": "five-session-streaming-sync-only",
        "send_message_rpc_tested": False,
        "gates_predeclared": GATES,
        "errors": [],
        "phases": [],
        "ws_counts": {},
        "workload": {
            "users": 5,
            "session_ws": 5,
            "connector_ws": 5,
            "dashboard_ws": 5,
            "duration_s": 60,
            "events_per_s": 20,
            "events_each_user": 240,
            "history_items_each": 100,
            "history_item_bytes": 8192,
            "stream_text_bytes": [8192, 65536],
            "history_reads_total": 300,
        },
    }
    errors = result["errors"]
    sessions, sockets, readers, heartbeats = [], [], [], []
    sent, expected, received, ws_items = {}, {}, set(), {}
    http_ms, projection_ms, history_ms, lag_ms = [], [], [], []
    per_user = [{"sent": 0, "received": 0, "history_reads": 0} for _ in range(5)]
    result["per_user"] = per_user
    closing = False
    diagnostics = []
    diagnostic_task = None

    def error(kind, exc=None, **extra):
        errors.append(
            {"kind": kind, "type": type(exc).__name__ if exc else None, **extra}
        )

    async with httpx.AsyncClient(
        base_url="http://api:8000",
        timeout=5,
        trust_env=False,
        limits=httpx.Limits(max_connections=30),
    ) as client:

        async def request(method, path, **kw):
            response = await client.request(method, path, **kw)
            if response.status_code not in (200, 201):
                raise RuntimeError(f"{method} {path}: HTTP {response.status_code}")
            return response.json()

        async def ingest(headers, notifications):
            data = await request(
                "POST",
                "/api/v2/connector/ingest",
                headers=headers,
                json={"notifications": notifications},
            )
            if data["accepted"] != len(notifications) or data["rejected"]:
                raise RuntimeError(
                    "ingest rejected " + json.dumps(data["rejected"])[:500]
                )

        async def ws_open(path, **kw):
            ws = await websockets.connect(
                "ws://api:8000" + path,
                open_timeout=5,
                max_size=2**21,
                max_queue=32,
                proxy=None,
                **kw,
            )
            sockets.append(ws)
            return ws

        async def session_reader(i, ws, sid):
            try:
                async for raw in ws:
                    event = json.loads(raw)
                    if event["type"] not in {"timeline.item_created", "timeline.item_updated"}:
                        continue
                    item = event["payload"]["item"]
                    if item["sessionId"] != sid:
                        error("cross_session_ws", user=i)
                    if not item["id"].startswith("live-"):
                        continue
                    key = (sid, item["id"], item["contentHash"])
                    if key not in sent:
                        error("unexpected_content_hash", user=i)
                        continue
                    if key in received:
                        error("duplicate_revision", user=i)
                        continue
                    received.add(key)
                    projection_ms.append((time.monotonic() - sent[key]) * 1000)
                    per_user[i]["received"] += 1
                    prior = ws_items.get((sid, item["id"]))
                    if prior and (
                        item["revision"] <= prior["revision"]
                        or item["updatedSeq"] <= prior["updatedSeq"]
                    ):
                        error("nonmonotonic_revision", user=i)
                    ws_items[(sid, item["id"])] = item
            except Exception as exc:  # noqa: BLE001 - aggregate evidence / continue ownership cleanup
                if not closing:
                    error(
                        "session_ws", exc, user=i, close_code=getattr(exc, "code", None)
                    )

        async def dashboard_reader(i, ws, sid):
            try:
                async for raw in ws:
                    event = json.loads(raw)
                    result["ws_counts"][f"dashboard_{i}"] = (
                        result["ws_counts"].get(f"dashboard_{i}", 0) + 1
                    )
                    if "sessions" in event and any(
                        s["id"] != sid for s in event["sessions"]
                    ):
                        error("cross_user_dashboard", user=i)
            except Exception as exc:  # noqa: BLE001 - aggregate evidence / continue ownership cleanup
                if not closing:
                    error("dashboard_ws", exc, user=i)

        async def connector_reader(i, ws):
            try:
                async for raw in ws:
                    data = json.loads(raw)
                    if data.get("type") == "request":
                        # Only discovery; no actual runtime executable/model is started.
                        ok = data["method"] == "runtime.discover"
                        reply = {"id": data["id"], "type": "response", "ok": ok}
                        if ok:
                            reply["result"] = {"runtimeTypes": []}
                        else:
                            reply["error"] = {
                                "code": "synthetic_unsupported",
                                "message": "no model runtime",
                            }
                            error("unexpected_connector_rpc", method=data["method"])
                        await ws.send(json.dumps(reply))
            except Exception as exc:  # noqa: BLE001 - aggregate evidence / continue ownership cleanup
                if not closing:
                    error("connector_ws", exc, user=i)

        async def heartbeat(ws):
            while True:
                await ws.send(
                    json.dumps(
                        {
                            "type": "notification",
                            "method": "connector.heartbeat",
                            "params": {},
                        }
                    )
                )
                await asyncio.sleep(5)

        pg = None
        redis = Redis.from_url(ENV["AGENT_SERVER_REDIS_URL"], decode_responses=True)
        try:
            tokens = (await request("GET", "/__capacity/fixtures"))["tokens"]
            for i, token in enumerate(tokens):
                h = {"Authorization": "Bearer " + token}
                me = await request("GET", "/api/v2/auth/me", headers=h)
                assert me["userId"] == f"capacity-user-{i}"
                conn = await request(
                    "POST",
                    "/api/v2/connectors",
                    headers=h,
                    json={"name": f"synthetic-{i}"},
                )
                cid = conn["connector"]["id"]
                access = await request(
                    "POST",
                    "/api/v2/connector/auth",
                    headers={
                        "Authorization": f"Connector {cid}:{conn['connectorToken']}"
                    },
                )
                ch = {"Authorization": "Bearer " + access["accessToken"]}
                project = await request(
                    "POST",
                    "/api/v2/projects",
                    headers=h,
                    json={
                        "name": f"synthetic-{i}",
                        "connectorId": cid,
                        "workspacePath": "/synthetic",
                    },
                )
                session = await request(
                    "POST",
                    "/api/v2/sessions",
                    headers=h,
                    json={
                        "connectorId": cid,
                        "projectId": project["project"]["id"],
                        "runtime": "codex",
                        "externalSessionId": f"synthetic-native-{i}",
                        "title": f"synthetic-{i}",
                        "cwd": "/synthetic",
                    },
                )
                sid = session["session"]["id"]
                sessions.append((sid, h, ch))
                # Real API seeds in batches of 10; no self-created table/direct Timeline writes.
                for batch in range(10):
                    await ingest(
                        ch,
                        [
                            notification(
                                sid,
                                f"history-{j:03}",
                                1,
                                f"synthetic-history-{i}-{j}:".ljust(8192, "h"),
                                j + 1,
                                status="done",
                            )
                            for j in range(batch * 10, batch * 10 + 10)
                        ],
                    )
                await request("GET", f"/api/v2/sessions/{sid}/snapshot", headers=h)
                cw = await ws_open("/api/v2/connector/ws", additional_headers=ch)
                readers.append(asyncio.create_task(connector_reader(i, cw)))
                heartbeats.append(asyncio.create_task(heartbeat(cw)))
                ticket = await request(
                    "POST",
                    "/api/v2/ws-ticket",
                    headers=h,
                    json={
                        "clientId": f"synthetic-session-{i}",
                        "scope": {"sessionId": sid},
                    },
                )
                sw = await ws_open(
                    f"/api/v2/sessions/{sid}/ws?ticket={ticket['ticket']}"
                )
                assert (
                    json.loads(await asyncio.wait_for(sw.recv(), 5))["type"]
                    == "session.subscribed"
                )
                readers.append(asyncio.create_task(session_reader(i, sw, sid)))
                ticket = await request(
                    "POST",
                    "/api/v2/ws-ticket",
                    headers=h,
                    json={
                        "clientId": f"synthetic-dashboard-{i}",
                        "scope": {"dashboard": True},
                    },
                )
                dw = await ws_open(f"/api/v2/dashboard/ws?ticket={ticket['ticket']}")
                initial = json.loads(await asyncio.wait_for(dw.recv(), 5))
                assert initial["type"] == "dashboard.snapshot"
                assert [s["id"] for s in initial["sessions"]] == [sid]
                readers.append(asyncio.create_task(dashboard_reader(i, dw, sid)))
            # Establish ownership isolation via real HTTP. Expected denials are not workload errors.
            denied = await client.get(
                f"/api/v2/sessions/{sessions[1][0]}/timeline", headers=sessions[0][1]
            )
            assert denied.status_code in (403, 404)
            result["cross_user_read_denied"] = denied.status_code
            pg = await asyncpg.connect(
                host="pg", user="capacity_test", database=DB, timeout=5
            )
            result["postgres_version"] = await pg.fetchval("SELECT version()")
            result["schema_revision"] = await pg.fetchval(
                "SELECT version_num FROM alembic_version"
            )
            result["seed_pg_rows"] = await pg.fetchval(
                "SELECT count(*) FROM timeline_items"
            )
            assert result["seed_pg_rows"] == 500
            result["metrics_before"] = await request("GET", "/__capacity/metrics")
            result["phases"].append("15 WS and 500 real Timeline history rows ready")

            async def collect_diagnostics():
                while True:
                    entry = {"monotonic": time.monotonic()}
                    try:
                        entry["pg_activity"] = [
                            dict(row)
                            for row in await pg.fetch(
                                "SELECT state,wait_event_type,wait_event,count(*)::int AS count "
                                "FROM pg_stat_activity WHERE datname=current_database() "
                                "AND pid<>pg_backend_pid() GROUP BY state,wait_event_type,wait_event"
                            )
                        ]
                        entry["metrics"] = await request("GET", "/__capacity/metrics")
                        # Retain frequent counters/lag, full stacks on pool pressure only.
                        if entry["metrics"]["current"]["pool_checkedout"] < 4:
                            entry["metrics"].pop("task_stacks", None)
                        entry["metrics"].pop("samples", None)
                    except Exception as exc:  # noqa: BLE001 - diagnostic error is independent evidence
                        entry["error"] = type(exc).__name__
                    diagnostics.append(entry)
                    del diagnostics[:-90]
                    await asyncio.sleep(1)

            diagnostic_task = asyncio.create_task(collect_diagnostics())
            started = time.monotonic() + 0.2

            async def lane(i, sid, ch):
                for n in range(240):
                    due = started + n * 0.25
                    await asyncio.sleep(max(0, due - time.monotonic()))
                    item_id, revision = f"live-{n // 16:02}", n % 16 + 1
                    size = 8192 if n < 120 else 65536
                    text = f"synthetic-{i}-{n}:".ljust(size, "x")
                    key = (
                        sid,
                        item_id,
                        "sha256:" + hashlib.sha256(text.encode()).hexdigest(),
                    )
                    now = time.monotonic()
                    lag_ms.append(max(0, now - due) * 1000)
                    sent[key] = now
                    expected[(sid, item_id)] = {"revision": revision, "text": text}
                    per_user[i]["sent"] += 1
                    try:
                        await ingest(
                            ch,
                            [
                                notification(
                                    sid,
                                    item_id,
                                    revision,
                                    text,
                                    101 + n // 16,
                                    status="done" if revision == 16 else "running",
                                )
                            ],
                        )
                        http_ms.append((time.monotonic() - now) * 1000)
                    except Exception as exc:  # noqa: BLE001 - aggregate evidence / continue ownership cleanup
                        error("ingest", exc, user=i, n=n, detail=str(exc)[:500])

            async def history(i, sid, h):
                for n in range(60):
                    await asyncio.sleep(max(0, started + n - time.monotonic()))
                    # Alternate current view and genuinely older page, competing with writes.
                    params = (
                        {"mode": "latest", "limit": 100}
                        if n % 2 == 0
                        else {"mode": "history", "beforeOrderSeq": 101, "limit": 100}
                    )
                    t = time.monotonic()
                    try:
                        body = await request(
                            "GET",
                            f"/api/v2/sessions/{sid}/timeline",
                            headers=h,
                            params=params,
                        )
                        assert body["items"] and all(
                            x["sessionId"] == sid for x in body["items"]
                        )
                        history_ms.append((time.monotonic() - t) * 1000)
                        per_user[i]["history_reads"] += 1
                    except Exception as exc:  # noqa: BLE001 - aggregate evidence / continue ownership cleanup
                        error("history", exc, user=i, n=n, detail=str(exc)[:200])

            try:
                await asyncio.wait_for(
                    asyncio.gather(
                        *(lane(i, sid, ch) for i, (sid, h, ch) in enumerate(sessions)),
                        *(
                            history(i, sid, h)
                            for i, (sid, h, ch) in enumerate(sessions)
                        ),
                    ),
                    80,
                )
            except TimeoutError:
                error("load_deadline_80s")
            if diagnostic_task:
                diagnostic_task.cancel()
                await asyncio.gather(diagnostic_task, return_exceptions=True)
                diagnostic_task = None
            result["offered_span_s"] = round(max(sent.values()) - min(sent.values()), 3)
            result["achieved_events_per_s"] = round(
                (len(sent) - 5) / max(0.001, max(sent.values()) - min(sent.values())), 3
            )
            result["metrics_at_stop"] = await request("GET", "/__capacity/metrics")
            result["phases"].append(
                "paced workload stopped (see deadline/error counts; target 60s)"
            )
            # PASSIVE convergence: no flush call or history/snapshot read barrier here.
            drain_started = time.monotonic()
            convergence = False
            checks = []
            while time.monotonic() - drain_started < GATES["drain_timeout_s"]:
                rows = await pg.fetch(
                    "SELECT session_id,id,payload_json,updated_seq FROM timeline_items"
                )
                durable = {
                    (r["session_id"], r["id"]): (
                        json.loads(r["payload_json"]),
                        r["updated_seq"],
                    )
                    for r in rows
                }
                matches = sum(
                    k in durable
                    and durable[k][0]["revision"] >= v["revision"]
                    and durable[k][0]["content"]["text"] == v["text"]
                    for k, v in expected.items()
                )
                dirty = await redis.scard(f"{PREFIX}:timeline-buffer:dirty")
                pending = sum(
                    [
                        await redis.hlen(f"{PREFIX}:timeline-buffer:{sid}:items")
                        for sid, _, _ in sessions
                    ]
                )
                checks.append(
                    {
                        "after_stop_s": round(time.monotonic() - drain_started, 3),
                        "pg_matching_live_items": matches,
                        "pg_total_rows": len(rows),
                        "dirty_sessions": dirty,
                        "pending_items": pending,
                        "ws_received": len(received),
                        "expected_live_items_actually_offered": len(expected),
                    }
                )
                if (
                    matches == 75
                    and len(rows) == 575
                    and len(received) == 1200
                    and dirty == pending == 0
                ):
                    convergence = True
                    break
                await asyncio.sleep(0.25)
            result["passive_convergence"] = {
                "passed": convergence,
                "checks": checks,
                "elapsed_s": round(time.monotonic() - drain_started, 3),
                "queue_drained": bool(
                    checks
                    and checks[-1]["dirty_sessions"] == checks[-1]["pending_items"] == 0
                ),
                "offered_latest_items_matched": bool(
                    checks and checks[-1]["pg_matching_live_items"] == len(expected)
                ),
            }
            if not convergence:
                error("passive_convergence_timeout")
            # Durable HTTP history comparison is checked only AFTER the passive PG/Redis evidence.
            for sid, h, _ in sessions:
                snapshot = await request(
                    "GET",
                    f"/api/v2/sessions/{sid}/timeline",
                    headers=h,
                    params={"mode": "latest", "limit": 500},
                )
                values = {x["id"]: x for x in snapshot["items"]}
                for (s, item_id), value in expected.items():
                    if s != sid:
                        continue
                    item = values.get(item_id)
                    live = ws_items.get((sid, item_id))
                    if (sid, item_id) not in durable:
                        error("pg_missing_offered_item", item=item_id)
                        continue
                    row, seq = durable[(sid, item_id)]
                    if (
                        not item
                        or not live
                        or not (
                            item["revision"] == live["revision"] == row["revision"]
                            and row["revision"] >= value["revision"]
                            and item["content"]["text"]
                            == live["content"]["text"]
                            == row["content"]["text"]
                            == value["text"]
                            and item["contentHash"]
                            == live["contentHash"]
                            == row["contentHash"]
                            and item["updatedSeq"] == live["updatedSeq"] == seq
                            and seq > 0
                        )
                    ):
                        error("durable_http_pg_ws_mismatch", item=item_id)
            result["metrics_final"] = await request("GET", "/__capacity/metrics")
            result["redis_memory"] = {
                k: v
                for k, v in (await redis.info("memory")).items()
                if k
                in ("used_memory", "used_memory_rss", "used_memory_peak", "maxmemory")
            }
            result["phases"].append(
                "passive PG convergence and durable HTTP/WS/hash/sequence comparison completed"
            )
        except Exception as exc:  # noqa: BLE001 - aggregate evidence / continue ownership cleanup
            error("driver_phase", exc, detail=str(exc)[:600])
        finally:
            # Independent of the load/drain outcome: never skip final evidence.
            if diagnostic_task:
                diagnostic_task.cancel()
                await asyncio.gather(diagnostic_task, return_exceptions=True)
            result["diagnostics"] = diagnostics
            try:
                result["metrics_final"] = await request("GET", "/__capacity/metrics")
            except Exception as exc:  # noqa: BLE001 - preserve metrics failure separately
                result["metrics_final_error"] = type(exc).__name__
            if pg:
                try:
                    result["final_pg_inventory"] = [
                        dict(row)
                        for row in await pg.fetch(
                            "SELECT session_id,count(*)::int AS rows,max(updated_seq) AS max_seq "
                            "FROM timeline_items GROUP BY session_id"
                        )
                    ]
                    result["final_pg_activity"] = [
                        dict(row)
                        for row in await pg.fetch(
                            "SELECT state,wait_event_type,wait_event,count(*)::int AS count "
                            "FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() "
                            "GROUP BY state,wait_event_type,wait_event"
                        )
                    ]
                    result["final_dirty"] = await redis.scard(
                        f"{PREFIX}:timeline-buffer:dirty"
                    )
                    result["final_pending"] = sum(
                        [
                            await redis.hlen(f"{PREFIX}:timeline-buffer:{sid}:items")
                            for sid, _, _ in sessions
                        ]
                    )
                except Exception as exc:  # noqa: BLE001 - preserve PG failure separately
                    result["final_pg_error"] = type(exc).__name__
            closing = True
            for t in heartbeats:
                t.cancel()
            await asyncio.gather(*heartbeats, return_exceptions=True)
            await asyncio.gather(*(w.close() for w in sockets), return_exceptions=True)
            for t in readers:
                t.cancel()
            await asyncio.gather(*readers, return_exceptions=True)
            if pg:
                await pg.close()
            await redis.aclose()
    result.update(
        ingest_http=distribution(http_ms),
        projection=distribution(projection_ms),
        history_http=distribution(history_ms),
        schedule_lag=distribution(lag_ms),
        sent=len(sent),
        received=len(received),
        websocket_connections_opened=len(sockets),
    )
    m = result.get("metrics_final", {}).get("peaks", {})
    projection = result["projection"]
    result["passed"] = bool(
        not errors
        and len(sent) == len(received) == 1200
        and len(http_ms) == 1200
        and len(history_ms) == 300
        and len(sockets) == 15
        and projection["p95_ms"] < 1000
        and projection["max_ms"] < 3000
        and result.get("achieved_events_per_s", 0) >= 19
        and result.get("passive_convergence", {}).get("passed")
        and m.get("event_worker_processes") == 1
        and m.get("session_subscribers")
        == m.get("dashboard_subscribers")
        == m.get("connector_connections")
        == 5
        and m.get("subscriber_overflow", 0) == m.get("connector_overloaded", 0) == 0
        and m.get("monitor_errors", 0) == 0
    )
    # Docker log rotation must never be the transport for multi-MiB stacks.
    Path("/tmp/capacity-driver-result.json").write_text(
        json.dumps(result, ensure_ascii=False)
    )
    print(
        json.dumps(
            {"passed": result["passed"], "sent": len(sent), "received": len(received)}
        )
    )


if __name__ == "__main__":
    internal_guard()
    if sys.argv[1:] == ["--serve"]:
        from agent_server.infra.db.migrations import upgrade_database
        upgrade_database()
        asyncio.run(serve())
    elif sys.argv[1:] == ["--driver"]:
        asyncio.run(driver())
        time.sleep(180)  # observer window; workload/result unchanged
    else:
        raise SystemExit("only isolated serve/driver allowed")
