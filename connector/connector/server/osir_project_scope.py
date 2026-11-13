"""Explicit local grant for one project's Codex sessions; no auto-installation.

ProjectSessionScope(codex_home, workspace) reads ONLY state_5.sqlite rows whose
cwd equals the canonical workspace or begins with workspace + '/'. It never
walks Codex Home. inventory() binds validated refs; require_thread() accepts
only bound IDs and revalidates the selected row and rollout session_meta.
ProjectCodexClient(delegate, scope) implements the runtime-client surface with
local inventory pagination, guarded operations and a filtered notification
handler. Unknown methods are absent: there is no delegate __getattr__ fallback.

Only a dedicated project connection should opt into this wrapper. The delegate
must use this same Codex Home, with global IPC/history synchronization disabled.
This is a session authorization boundary, not an OS/filesystem sandbox: it does
not constrain an independently configured native process or tools. The bridge
must keep its own runtime/transport controls. No credentials are read here.

The SQLite file remains read-only (including WAL-aware reads). Only the first,
bounded session_meta line of a selected rollout is opened, using no-follow
directory descriptors. An indexed thread may live in sessions OR
archived_sessions; all symlinks, mismatched cwd/ID and absent metadata are denied.
New threads are verified against their native read-back before their first turn,
because Codex persists the index/rollout lazily. These short-lived local bindings
are promoted only after the exact index and rollout metadata become available.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import stat
import threading
import time
from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path

from connector.runtimes.codex.sdk.events import CodexSdkEvent
from connector.runtimes.codex.sdk.runtime_client import (
    CodexStartThreadRequest,
    CodexThreadListResult,
    CodexThreadReadResult,
)

AUTHORIZED_WORKSPACE = Path("/Users/ouwei/cc-switch-osir-client")
_ID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_COLUMNS = ("id", "cwd", "rollout_path", "title", "created_at", "updated_at", "archived", "source")
_OPTIONAL_COLUMNS = ("model_provider", "cli_version")
_CWD_SQL = "(cwd = ? OR substr(cwd, 1, length(?)) = ?)"
_MAX_REFS = 10000
_MAX_META = 65536


class ProjectScopeDenied(PermissionError):
    """A fixed local authorization error, without database/SDK details."""


def _id(value) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ProjectScopeDenied("Invalid project thread ID")
    return value


def _canonical(value, *, directory=False) -> Path:
    try:
        path = Path(value)
        if not path.is_absolute() or ".." in path.parts:
            raise ProjectScopeDenied("Canonical absolute project path required")
        resolved = path.resolve(strict=True)
        # Reject aliases and every symlink component, even one pointing inside.
        if path != resolved or any(part.is_symlink() for part in (path, *path.parents)):
            raise ProjectScopeDenied("Project path aliases or symlinks denied")
        if directory and not resolved.is_dir():
            raise ProjectScopeDenied("Project directory required")
        return resolved
    except (OSError, TypeError, ValueError, RuntimeError):
        raise ProjectScopeDenied("Project path unavailable") from None


def _mapping(value) -> dict:
    if isinstance(value, Mapping):
        return dict(value)
    dump = getattr(value, "model_dump", None)
    if callable(dump):
        result = dump(mode="json", by_alias=True, exclude_none=True)
        if isinstance(result, dict):
            return result
    raise ProjectScopeDenied("Invalid project thread response")


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate metadata key")
        result[key] = value
    return result


class ProjectSessionScope:
    def __init__(self, codex_home: Path, workspace: Path = AUTHORIZED_WORKSPACE):
        self.codex_home = _canonical(codex_home, directory=True)
        self.workspace = _canonical(workspace, directory=True)
        self._database = self.codex_home / "state_5.sqlite"
        self._known: set[str] = set()
        self._new: dict[str, tuple[dict, float]] = {}
        self._lock = threading.RLock()

    @property
    def known_ids(self) -> frozenset[str]:
        with self._lock:
            return frozenset(self._known | self._new.keys())

    def require_workspace(self, cwd) -> Path:
        self._check_roots()
        path = _canonical(cwd, directory=True)
        if not path.is_relative_to(self.workspace):
            raise ProjectScopeDenied("Workspace is outside the local project grant")
        return path

    def _check_roots(self):
        _canonical(self.codex_home, directory=True)
        _canonical(self.workspace, directory=True)

    @contextmanager
    def _connect(self):
        self._check_roots()
        database = _canonical(self._database)
        if not stat.S_ISREG(database.stat().st_mode):
            raise ProjectScopeDenied("Project index must be a regular file")
        for suffix in ("-wal", "-shm", "-journal"):
            sidecar = Path(str(database) + suffix)
            if sidecar.is_symlink():
                raise ProjectScopeDenied("Project index symlink denied")
        connection = None
        try:
            connection = sqlite3.connect(database.as_uri() + "?mode=ro", uri=True, timeout=1)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA query_only=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            schema = connection.execute("SELECT type FROM sqlite_master WHERE name='threads'").fetchone()
            if schema is None or schema["type"] != "table":
                raise ProjectScopeDenied("Project thread table unavailable")
            columns = {row["name"] for row in connection.execute("PRAGMA table_info(threads)")}
            if not set(_COLUMNS) <= columns:
                raise ProjectScopeDenied("Unsupported project index schema")
            yield connection, tuple(_COLUMNS) + tuple(c for c in _OPTIONAL_COLUMNS if c in columns)
        except sqlite3.Error:
            raise ProjectScopeDenied("Project index unavailable") from None
        finally:
            if connection is not None:
                connection.close()

    def _rows(self, thread_id: str | None = None) -> list[dict]:
        prefix = str(self.workspace) + "/"
        args = [str(self.workspace), prefix, prefix]
        where = _CWD_SQL
        if thread_id is not None:
            where += " AND id = ?"
            args.append(_id(thread_id))
        with self._connect() as (connection, columns):
            # Column names come only from fixed constants, never remote input.
            query = "SELECT " + ",".join(columns) + " FROM threads WHERE " + where
            query += " ORDER BY updated_at DESC, id ASC LIMIT ?"
            rows = connection.execute(query, (*args, _MAX_REFS + 1)).fetchall()
        if len(rows) > _MAX_REFS:
            raise ProjectScopeDenied("Project inventory exceeds local bound")
        return [dict(row) for row in rows]

    def _rollout(self, value, thread_id: str, cwd: Path) -> Path:
        path = _canonical(value)
        roots = (self.codex_home / "sessions", self.codex_home / "archived_sessions")
        root = next((root for root in roots if path.is_relative_to(root) and path != root), None)
        if root is None:
            raise ProjectScopeDenied("Rollout is outside the authorized Codex session stores")
        _canonical(root, directory=True)
        fd = None
        try:
            # Component-relative no-follow opens also reject replacement with a
            # symlink between validation and opening a selected rollout.
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            parts = path.relative_to(root).parts
            for part in parts[:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
            child = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            try:
                if not stat.S_ISREG(os.fstat(child).st_mode):
                    raise ProjectScopeDenied("Rollout must be a regular file")
                with os.fdopen(child, "rb", closefd=False) as stream:
                    line = stream.readline(_MAX_META + 1)
            finally:
                os.close(child)
            if len(line) > _MAX_META:
                raise ProjectScopeDenied("Rollout metadata exceeds local bound")
            meta = json.loads(line, object_pairs_hook=_unique)
            payload = meta.get("payload") if isinstance(meta, dict) and meta.get("type") == "session_meta" else None
            if (not isinstance(payload, dict) or payload.get("id") != thread_id
                    or self.require_workspace(payload.get("cwd")) != cwd):
                raise ProjectScopeDenied("Rollout thread metadata does not match the project index")
        except (OSError, ValueError, UnicodeError, RecursionError):
            raise ProjectScopeDenied("Invalid selected rollout metadata") from None
        finally:
            if fd is not None:
                os.close(fd)
        return path

    def _ref(self, row: dict) -> dict:
        identifier = _id(row["id"])
        cwd = self.require_workspace(row["cwd"])
        path = self._rollout(row["rollout_path"], identifier, cwd)
        if (type(row["created_at"]) is not int or type(row["updated_at"]) is not int
                or min(row["created_at"], row["updated_at"]) < 0 or row["archived"] not in (0, 1)
                or not isinstance(row["title"], str)):
            raise ProjectScopeDenied("Invalid selected thread metadata")
        # Never copy sub-agent parent IDs or arbitrary JSON from source metadata.
        source = row["source"] if row["source"] in ("cli", "vscode", "exec", "appServer", "unknown") else "unknown"
        ref = {"id": identifier, "cwd": str(cwd), "path": str(path), "title": row["title"],
               "name": row["title"], "preview": row["title"], "createdAt": row["created_at"],
               "updatedAt": row["updated_at"], "archived": bool(row["archived"]), "source": source,
               "ephemeral": False, "status": {"type": "notLoaded"}, "turns": []}
        if isinstance(row.get("model_provider"), str):
            ref["modelProvider"] = row["model_provider"]
        if isinstance(row.get("cli_version"), str):
            ref["cliVersion"] = row["cli_version"]
        return ref

    def inventory(self) -> list[dict]:
        """All valid selected-project refs; invalid selected rows are omitted."""
        with self._lock:
            refs = []
            for row in self._rows():
                try:
                    refs.append(self._ref(row))
                except ProjectScopeDenied:
                    continue
            self._known = {ref["id"] for ref in refs}
            return refs

    def require_thread(self, thread_id: str) -> dict:
        with self._lock:
            identifier = _id(thread_id)
            if identifier in self._new:
                return self._require_new_thread(identifier)
            if identifier not in self._known:
                raise ProjectScopeDenied("Thread is not bound to this local project grant")
            rows = self._rows(identifier)
            if len(rows) != 1:
                self._known.discard(identifier)
                raise ProjectScopeDenied("Bound project thread is no longer available")
            try:
                return self._ref(rows[0])
            except ProjectScopeDenied:
                self._known.discard(identifier)
                raise

    def _require_new_thread(self, identifier):
        ref, deadline = self._new[identifier]
        try:
            self._check_roots()
            if time.monotonic() >= deadline:
                raise ProjectScopeDenied("New project thread persistence timed out")
            # A targeted lookup of our locally minted ID also detects movement
            # outside the project; it never enumerates other project history.
            with self._connect() as (connection, columns):
                row = connection.execute("SELECT " + ",".join(columns) +
                    " FROM threads WHERE id = ?", (identifier,)).fetchone()
            if row is None:
                return dict(ref)
            row = dict(row)
            if row['cwd'] != ref['cwd'] or row['rollout_path'] != ref['path']:
                raise ProjectScopeDenied("New project thread metadata changed")
            path = Path(ref['path'])
            if not path.exists() and not path.is_symlink():
                return dict(ref)
            persisted = self._ref(row)
            self._known.add(identifier)
            del self._new[identifier]
            return persisted
        except ProjectScopeDenied:
            self._new.pop(identifier, None)
            self._known.discard(identifier)
            raise

    def bind_new_thread(self, thread_id: str, *, native_thread=None) -> dict:
        """Bind a freshly returned ID only after authoritative local validation."""
        with self._lock:
            identifier = _id(thread_id)
            if identifier in self._known or identifier in self._new:
                raise ProjectScopeDenied("Native start returned an already bound thread")
            rows = self._rows(identifier)
            if len(rows) != 1:
                if rows or native_thread is None:
                    raise ProjectScopeDenied("New project thread is not yet indexed")
                native = _mapping(native_thread)
                if (native.get('id') != identifier or native.get('ephemeral') is not False
                        or self.require_workspace(native.get('cwd')) != self.workspace):
                    raise ProjectScopeDenied("New native thread does not match the project grant")
                path = Path(native.get('path') or '')
                roots = (self.codex_home / 'sessions', self.codex_home / 'archived_sessions')
                if (not path.is_absolute() or '..' in path.parts
                        or not any(path.is_relative_to(root) and path != root for root in roots)
                        or identifier not in path.name or path.suffix != '.jsonl'
                        or any(part.is_symlink() for part in (path, *path.parents))
                        or path.resolve() != path or len(self._new) >= 4):
                    raise ProjectScopeDenied("New native rollout path is invalid")
                ref = {'id': identifier, 'cwd': str(self.workspace), 'path': str(path),
                    'ephemeral': False, 'turns': []}
                self._new[identifier] = (ref, time.monotonic() + 60)
                return self._require_new_thread(identifier)
            ref = self._ref(rows[0])
            if ref["cwd"] != str(self.workspace):
                raise ProjectScopeDenied("New thread must use the exact granted workspace")
            self._known.add(identifier)
            return ref

    def revoke_thread(self, thread_id: str) -> None:
        """Drop a binding after an inconsistent native response; no disk writes."""
        with self._lock:
            self._known.discard(_id(thread_id))
            self._new.pop(thread_id, None)


class ProjectCodexClient:
    """Explicit client facade; no raw client, RPC or unknown-method fallback."""

    def __init__(self, delegate, scope: ProjectSessionScope):
        self._delegate = delegate
        self.scope = scope
        self._handler = None
        self._secret = secrets.token_bytes(32)
        self._pending: dict[tuple[type, str | int], str | None] = {}

    async def start(self, handler):
        self.scope.inventory()
        if self._handler is not None:
            raise ProjectScopeDenied("Project client already started")
        self._handler = handler
        try:
            await self._delegate.start(self._notification)
        except BaseException:
            self._handler = None
            self._pending.clear()
            raise

    async def stop(self):
        self._handler = None
        self._pending.clear()
        for identifier in tuple(self.scope._new):
            self.scope.revoke_thread(identifier)
        await self._delegate.stop()

    async def list_models(self):
        return await self._delegate.list_models()

    async def list_threads(self, limit=100, cursor=None, archived=None):
        if type(limit) is not int or not 1 <= limit <= 100 or archived is not None and type(archived) is not bool:
            raise ProjectScopeDenied("Invalid project inventory pagination")
        refs = [ref for ref in self.scope.inventory() if archived is None or ref["archived"] == archived]
        fingerprint = hashlib.sha256(json.dumps(refs, sort_keys=True).encode()).hexdigest()
        offset = 0
        if cursor is not None:
            try:
                if not isinstance(cursor, str) or len(cursor) > 1024:
                    raise ValueError
                raw = base64.b64decode(cursor, altchars=b"-_", validate=True)
                signature, payload = raw[:32], raw[32:]
                if not hmac.compare_digest(signature, hmac.digest(self._secret, payload, "sha256")):
                    raise ValueError
                decoded = json.loads(payload)
                offset = decoded["offset"]
                if (decoded["fingerprint"] != fingerprint or decoded["archived"] != archived
                        or type(offset) is not int or not 0 < offset < len(refs)):
                    raise ValueError
            except (ValueError, KeyError, TypeError):
                raise ProjectScopeDenied("Invalid or stale project inventory cursor") from None
        end = offset + limit
        next_cursor = None
        if end < len(refs):
            payload = json.dumps({"offset": end, "fingerprint": fingerprint, "archived": archived},
                                 sort_keys=True).encode()
            next_cursor = base64.urlsafe_b64encode(hmac.digest(self._secret, payload, "sha256") + payload).decode()
        return CodexThreadListResult(threads=tuple(refs[offset:end]), next_cursor=next_cursor)

    def _validate_response(self, value, thread_id):
        """Validate protocol envelopes, never JSON inside messages/tool content.

        Related-thread metadata is not the envelope's own identity. Drop it
        instead of rejecting normal nullable/different parent IDs. Only the
        explicit protocol containers below are traversed; items/content/input/
        output/raw response items remain the authorized conversation's content.
        """
        related = {"parentThreadId", "parent_thread_id", "attachedThreadParentId",
                   "attached_thread_parent_id", "forkedFromId", "forked_from_id"}

        def envelope(node, *, thread=False, depth=0):
            if depth > 8 or not isinstance(node, Mapping):
                raise ProjectScopeDenied("Invalid project protocol envelope")
            result = {key: entry for key, entry in node.items() if key not in related}
            for key in ("threadId", "thread_id", "conversationId"):
                if key in result and result[key] != thread_id:
                    raise ProjectScopeDenied("Conflicting project thread identity")
            if thread and result.get("id") != thread_id:
                raise ProjectScopeDenied("Conflicting project thread identity")
            if result.get("cwd") is not None:
                cwd = self.scope.require_workspace(result["cwd"])
                if thread and str(cwd) != self.scope.require_thread(thread_id)["cwd"]:
                    raise ProjectScopeDenied("Conflicting project thread workspace")
            if thread:
                for key in ("path", "rollout_path"):
                    if result.get(key) is not None and result[key] != self.scope.require_thread(thread_id)["path"]:
                        raise ProjectScopeDenied("Conflicting project rollout path")
                if isinstance(result.get("source"), Mapping):
                    result["source"] = "unknown"
            for key in ("thread", "params", "turn"):
                if key in result and result[key] is not None:
                    result[key] = envelope(result[key], thread=key == "thread", depth=depth + 1)
            for key in ("threads", "turns"):
                if key in result:
                    if not isinstance(result[key], (tuple, list)):
                        raise ProjectScopeDenied("Invalid project protocol collection")
                    result[key] = [envelope(entry, thread=key == "threads", depth=depth + 1) for entry in result[key]]
            return result

        if isinstance(value, (tuple, list)):
            return [envelope(entry) for entry in value]
        return envelope(value)

    async def read_thread(self, thread_id, include_turns=True):
        self.scope.require_thread(thread_id)
        result = await self._delegate.read_thread(thread_id, include_turns=include_turns)
        ref = self.scope.require_thread(thread_id)
        thread = _mapping(result.thread)
        if thread.get("id") != thread_id or self.scope.require_workspace(thread.get("cwd")) != Path(ref["cwd"]):
            raise ProjectScopeDenied("Native thread response does not match project binding")
        checked = self._validate_response({"thread": thread}, thread_id)
        return CodexThreadReadResult(thread=checked["thread"])

    async def _scoped(self, method, thread_id, *args, **kwargs):
        self.scope.require_thread(thread_id)
        result = await getattr(self._delegate, method)(*args, **kwargs)
        self.scope.require_thread(thread_id)
        raw = getattr(result, "payload", None)
        if raw is not None:
            payload = _mapping(raw)
            direct_thread = method == "resume_thread" and "thread" not in payload
            checked = self._validate_response({"thread": payload} if direct_thread else payload, thread_id)
            result = replace(result, payload=checked["thread"] if direct_thread else checked)
        turns = getattr(result, "turns", None)
        if turns is not None:
            result = replace(result, turns=tuple(self._validate_response(turns, thread_id)))
        return result

    def thread_loaded(self, thread_id):
        self.scope.require_thread(thread_id)
        return self._delegate.thread_loaded(thread_id)

    async def list_thread_turns(self, thread_id):
        return await self._scoped("list_thread_turns", thread_id, thread_id)

    async def list_thread_turns_page(self, thread_id, cursor=None, limit=20):
        if type(limit) is not int or not 1 <= limit <= 100 or cursor is not None and not isinstance(cursor, str):
            raise ProjectScopeDenied("Invalid scoped turn pagination")
        return await self._scoped("list_thread_turns_page", thread_id, thread_id, cursor=cursor, limit=limit)

    async def start_thread(self, request):
        if not isinstance(request, CodexStartThreadRequest):
            raise ProjectScopeDenied("Typed project start request required")
        cwd = self.scope.require_workspace(request.cwd)
        if cwd != self.scope.workspace:
            raise ProjectScopeDenied("New thread requires the exact fixed workspace")
        # Do not widen native permissions from the project transport.
        if (request.sandbox not in (None, "read-only") or request.approval_policy not in (None, "never")
                or request.ephemeral):
            raise ProjectScopeDenied("Project permission expansion denied")
        existing = {ref["id"] for ref in self.scope.inventory()}
        result = await self._delegate.start_thread(replace(request, cwd=str(cwd), sandbox="read-only", approval_policy="never"))
        if result.thread_id in existing:
            raise ProjectScopeDenied("Native start reused an existing project thread")
        try:
            payload = _mapping(result.payload)
            nested = "thread" in payload
            thread = _mapping(payload["thread"]) if nested else payload
            if thread.get("id") != result.thread_id:
                raise ProjectScopeDenied("Native start returned conflicting thread identities")
            try:
                self.scope.bind_new_thread(result.thread_id)
            except ProjectScopeDenied as exc:
                if str(exc) != "New project thread is not yet indexed":
                    raise
                native = await self._delegate.read_thread(result.thread_id, include_turns=False)
                self.scope.bind_new_thread(result.thread_id, native_thread=native.thread)
            checked = self._validate_response(payload if nested else {"thread": thread}, result.thread_id)
        except ProjectScopeDenied:
            self.scope.revoke_thread(result.thread_id)
            raise
        return replace(result, payload=checked if nested else checked["thread"])

    async def start_turn(self, request):
        self.scope.require_thread(request.thread_id)
        if request.sandbox not in (None, "read-only") or request.approval_policy not in (None, "never"):
            raise ProjectScopeDenied("Project permission expansion denied")
        for attachment in request.attachments:
            path = _canonical(attachment.path)
            if not path.is_relative_to(self.scope.workspace) or not path.is_file():
                raise ProjectScopeDenied("Attachment is outside the project grant")
        return await self._scoped("start_turn", request.thread_id,
            replace(request, sandbox="read-only", approval_policy="never"))

    async def steer_turn(self, request):
        return await self._scoped("steer_turn", request.thread_id, request)

    async def interrupt_turn(self, request):
        return await self._scoped("interrupt_turn", request.thread_id, request)

    async def compact_thread(self, thread_id):
        return await self._scoped("compact_thread", thread_id, thread_id)

    async def resume_thread(self, request):
        self.scope.require_thread(request.thread_id)
        if request.sandbox not in (None, "read-only") or request.approval_policy not in (None, "never"):
            raise ProjectScopeDenied("Project permission expansion denied")
        return await self._scoped("resume_thread", request.thread_id,
            replace(request, sandbox="read-only", approval_policy="never"))

    async def resume_thread_state(self, thread_id):
        result = await self._scoped("resume_thread_state", thread_id, thread_id)
        payload = _mapping(result)
        direct = "id" in payload and "thread" not in payload
        checked = self._validate_response({"thread": payload} if direct else payload, thread_id)
        return checked["thread"] if direct else checked

    async def update_thread_settings(self, thread_id, settings):
        self.scope.require_thread(thread_id)
        raise ProjectScopeDenied("Project settings mutation is not delegated")

    async def update_turn_settings(self, thread_id, turn_id, settings):
        self.scope.require_thread(thread_id)
        raise ProjectScopeDenied("Project settings mutation is not delegated")

    async def respond(self, request_id, result=None):
        if type(request_id) not in (str, int):
            raise ProjectScopeDenied("Unknown project interaction")
        key = (type(request_id), request_id)
        thread_id = self._pending.pop(key, None)
        if thread_id is None:
            raise ProjectScopeDenied("Unknown project interaction")
        self.scope.require_thread(thread_id)
        # Project grant does not authorize additional file/tool permissions.
        if result not in ({"decision": "decline"}, {"decision": "cancel"}):
            raise ProjectScopeDenied("Only declining a scoped approval is supported")
        await self._delegate.respond(request_id, result)

    async def _notification(self, message):
        if self._handler is None:
            return
        try:
            event = message if isinstance(message, CodexSdkEvent) else CodexSdkEvent.from_value(message)
            identifier = _id(event.thread_id)
            self.scope.require_thread(identifier)
            checked_params = self._validate_response(event.params, identifier)
            checked_raw = self._validate_response(event.raw, identifier)
        except (ProjectScopeDenied, TypeError, ValueError):
            # A filtered event may not leave a pending approval capability.
            request_id = getattr(locals().get("event"), "request_id", None)
            if type(request_id) in (str, int):
                key = (type(request_id), request_id)
                if key in self._pending or len(self._pending) < 1024:
                    self._pending[key] = None
            return
        if event.request_id is not None:
            if type(event.request_id) not in (str, int) or len(self._pending) >= 1024:
                return
            key = (type(event.request_id), event.request_id)
            if key in self._pending:
                self._pending[key] = None
                return
            self._pending[key] = identifier
        safe = replace(message, params=checked_params, raw=checked_raw) if isinstance(message, CodexSdkEvent) else checked_raw
        await self._handler(copy.deepcopy(safe))
