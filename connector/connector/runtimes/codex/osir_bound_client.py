"""Bound SDK surface. No project hard paths, broad history list, or passthrough."""
from __future__ import annotations

import asyncio
import hashlib
import re
from dataclasses import replace
from pathlib import Path

from connector.runtimes.codex.osir_binding import (
    ModelBindingUnavailable,
    canonical_directory,
    plain,
)
from connector.runtimes.codex.sdk.events import CodexSdkEvent
from connector.runtimes.codex.sdk.runtime_client import (
    CodexModelListResult,
    CodexThreadListResult,
)

_ID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_SETTINGS = {"model", "effort", "permissions", "approvalPolicy", "approvalsReviewer"}


class BoundCodexClient:
    def __init__(self, delegate, binding, store):
        self.delegate = delegate
        self.model_binding = binding
        self.store = store
        self.failed = False
        self._threads: dict[str, str] = {}
        self._key: str | None = None
        self._create_lock = asyncio.Lock()
        self._creating = False
        self._early_started = []

    async def check(self):
        if self.failed:
            raise ModelBindingUnavailable()
        try:
            return await self.model_binding.check()
        except ModelBindingUnavailable:
            self.failed = True
            raise

    def _require(self, thread_id):
        if not isinstance(thread_id, str) or thread_id not in self._threads:
            raise ModelBindingUnavailable()
        return self._threads[thread_id]

    async def start(self, handler):
        binding = await self.check()
        self._key = "osir-bound-threads/" + hashlib.sha256(str(binding.home).encode()).hexdigest()
        saved = self.store.get(self._key) or {"threads": {}}
        rows = saved.get("threads")
        if (not isinstance(rows, dict) or len(rows) > 10000 or any(
                not isinstance(key, str) or not _ID.fullmatch(key)
                or not isinstance(cwd, str) or not Path(cwd).is_absolute()
                for key, cwd in rows.items())):
            raise ModelBindingUnavailable()
        self._threads = dict(rows)

        async def guarded(message):
            try:
                await self.check()
            except ModelBindingUnavailable:
                return  # Stale native output is not published as a new valid event.
            if isinstance(message, CodexSdkEvent):
                thread = message.thread_id
                method = message.event_type
            elif isinstance(message, dict):
                method = message.get("method")
                params = message.get("params", {})
                thread = params.get("threadId") if isinstance(params, dict) else None
                if thread is None and isinstance(params, dict) and isinstance(params.get("thread"), dict):
                    thread = params["thread"].get("id")
            else:
                return
            if not isinstance(thread, str):
                return
            if thread in self._threads:
                await handler(message)
            elif self._creating and method == "thread/started" and len(self._early_started) < 32:
                # SDK may deliver thread/started before thread/start returns.
                # Buffer metadata only, and release solely after read-back of
                # the actually created/registered thread. No unknown turn data.
                self._early_started.append((thread, message))

        self._deliver = guarded

        try:
            await self.delegate.start(guarded)
            await self.check()
        except BaseException:
            await self.delegate.stop()
            raise

    async def stop(self):
        # Cleanup is always possible, including after expiry or config changes.
        await self.delegate.stop()

    async def list_models(self):
        binding = await self.check()
        native = await self.delegate.list_models()
        await self.check()
        available = {row.get("id", row.get("model")): row for row in native.models}
        rows = []
        for identifier, title in sorted(binding.models, key=lambda row: row[0] != binding.default_model):
            efforts = available.get(identifier, {}).get("supportedReasoningEfforts", ())
            safe = [{"reasoningEffort": row["reasoningEffort"]} for row in efforts
                if isinstance(row, dict) and plain(row.get("reasoningEffort"), 32)] if isinstance(efforts, (list, tuple)) else []
            rows.append({"id": identifier, "model": identifier, "displayName": title,
                "isDefault": identifier == binding.default_model, "supportedReasoningEfforts": safe})
        return CodexModelListResult(models=tuple(rows))

    async def list_threads(self, limit=100, cursor=None, archived=None):
        await self.check()
        # Only locally recorded, actually created thread IDs. Never delegate a
        # broad SDK history inventory or enumerate the user's Codex Home.
        try:
            offset = 0 if cursor is None else int(cursor)
            if offset < 0 or offset > 10000 or not 1 <= limit <= 1000:
                raise ValueError()
        except (ValueError, TypeError):
            raise ModelBindingUnavailable() from None
        identifiers = sorted(self._threads)
        chosen = identifiers[offset:offset + limit]
        rows = []
        for identifier in chosen:
            result = await self.read_thread(identifier, include_turns=False)
            row = _mapping(result.thread)
            if archived is None or bool(row.get("archived", False)) == archived:
                rows.append(row)
        await self.check()
        following = offset + len(chosen)
        return CodexThreadListResult(tuple(rows), str(following) if following < len(identifiers) else None)

    async def read_thread(self, thread_id, include_turns=True):
        binding = await self.check()
        cwd = self._require(thread_id)
        result = await self.delegate.read_thread(thread_id, include_turns=include_turns)
        row = _mapping(result.thread)
        if row.get("id") != thread_id or row.get("cwd") != cwd:
            raise ModelBindingUnavailable()
        path = row.get("path")
        if path is not None:
            candidate = Path(path)
            if (not candidate.is_absolute() or ".." in candidate.parts
                    or not candidate.is_relative_to(binding.home)
                    or candidate.resolve(strict=False) != candidate):
                raise ModelBindingUnavailable()
        await self.check()
        return result

    async def start_thread(self, request):
        async with self._create_lock:
            self._creating = True
            try:
                result = await self._start_thread(request)
                pending = self._early_started
                self._early_started = []
                self._creating = False
                for thread, message in pending:
                    if thread == result.thread_id:
                        await self._deliver(message)
                return result
            finally:
                self._creating = False
                self._early_started = []

    async def _start_thread(self, request):
        binding = await self.check()
        if request.cwd is None:
            raise ModelBindingUnavailable()  # Workspace must be explicitly chosen.
        cwd = str(canonical_directory(request.cwd))
        if len(self._threads) >= 10000:
            raise ModelBindingUnavailable()
        result = await self.delegate.start_thread(replace(request, cwd=cwd,
            model=binding.select(request.model)))
        await self.check()
        if not isinstance(result.thread_id, str) or not _ID.fullmatch(result.thread_id):
            raise ModelBindingUnavailable()
        self._threads[result.thread_id] = cwd
        try:
            await self.read_thread(result.thread_id, include_turns=False)
        except BaseException:
            self._threads.pop(result.thread_id, None)
            raise
        self.store.set(self._key, {"threads": self._threads})
        return result

    async def start_turn(self, request):
        binding = await self.check()
        await self.read_thread(request.thread_id, include_turns=False)
        result = await self.delegate.start_turn(replace(request, model=binding.select(request.model),
            effort=request.effort if request.effort is not None else binding.default_effort))
        await self.check()
        return result

    async def steer_turn(self, request):
        await self.read_thread(request.thread_id, include_turns=False)
        result = await self.delegate.steer_turn(request)
        await self.check()
        return result

    async def interrupt_turn(self, request):
        # Only this native instance's loaded/owned turn may be interrupted.
        self._require(request.thread_id)
        if not self.delegate.thread_loaded(request.thread_id):
            raise ModelBindingUnavailable()
        return await self.delegate.interrupt_turn(request)

    async def compact_thread(self, thread_id):
        await self.read_thread(thread_id, include_turns=False)
        result = await self.delegate.compact_thread(thread_id)
        await self.check()
        return result

    async def respond(self, request_id, result=None):
        await self.check()
        reply = await self.delegate.respond(request_id, result)
        await self.check()
        return reply

    def thread_loaded(self, thread_id):
        if self.failed:
            raise ModelBindingUnavailable()
        try:
            self.model_binding.read()
        except ModelBindingUnavailable:
            self.failed = True
            raise
        self._require(thread_id)
        return self.delegate.thread_loaded(thread_id)

    async def update_thread_settings(self, thread_id, settings):
        binding = await self.check()
        await self.read_thread(thread_id, include_turns=False)
        if not isinstance(settings, dict) or not set(settings).issubset(_SETTINGS):
            raise ModelBindingUnavailable()
        if "model" in settings:
            binding.select(settings["model"])
        result = await self.delegate.update_thread_settings(thread_id, settings)
        await self.check()
        return result

    async def update_turn_settings(self, thread_id, turn_id, settings):
        await self.read_thread(thread_id, include_turns=False)
        if not isinstance(settings, dict) or not set(settings).issubset({"approvalsReviewer"}):
            raise ModelBindingUnavailable()
        result = await self.delegate.update_turn_settings(thread_id, turn_id, settings)
        await self.check()
        return result

    async def list_thread_turns(self, thread_id):
        await self.read_thread(thread_id, include_turns=False)
        result = await self.delegate.list_thread_turns(thread_id)
        await self.check()
        return result

    async def list_thread_turns_page(self, thread_id, cursor=None, limit=100):
        await self.read_thread(thread_id, include_turns=False)
        result = await self.delegate.list_thread_turns_page(thread_id, cursor, limit)
        await self.check()
        return result


def _mapping(value):
    return dict(value) if isinstance(value, dict) else value.model_dump(mode="json", by_alias=True)
