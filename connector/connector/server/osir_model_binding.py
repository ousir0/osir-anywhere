"""Read only the native Client's short-lived, non-secret local descriptor.

No Client database, Keychain, endpoint or key is exported. All errors are fixed
messages. A running runtime pins one revision; changing a provider requires a
safe reconnect rather than mixing the old startup catalog with new routing.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import stat
import time
import tomllib
from dataclasses import dataclass, field, replace
from pathlib import Path

from connector.runtime_protocol import RuntimeUnavailableError
from connector.runtimes.codex.sdk.runtime_client import CodexModelListResult
from connector.server.osir_project_scope import ProjectCodexClient

DEFAULT_BINDING = Path.home() / '.osir_client/anywhere/codex-binding.json'
_SHA = re.compile(r'[a-f0-9]{64}\Z')
_FIELDS = {'schemaVersion', 'source', 'available', 'expiresAtMs', 'errorCode',
    'codexHome', 'connectionMode', 'defaultModel', 'defaultReasoningEffort',
    'models', 'configSha256', 'catalogSha256', 'revision'}


class ModelBindingUnavailable(RuntimeUnavailableError):
    code = 'osir_model_binding_unavailable'

    def __init__(self):
        super().__init__('OSIR 模型配置已变化或不可用，请打开 OSIR 客户端后重新连接。')


def _plain(value, maximum=256):
    return (isinstance(value, str) and 0 < len(value) <= maximum
        and not any(ord(c) < 32 or ord(c) == 127 for c in value))


def _canonical(path: Path):
    if (not path.is_absolute() or '..' in path.parts or path.resolve(strict=True) != path
            or any(p.is_symlink() for p in (path, *path.parents))):
        raise ModelBindingUnavailable()
    return path


def _read(path: Path, *, private=False):
    _canonical(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_size > 2 * 1024 * 1024
                or info.st_uid != os.getuid() or private and stat.S_IMODE(info.st_mode) != 0o600):
            raise ModelBindingUnavailable()
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read(2 * 1024 * 1024 + 1)
        if len(data) > 2 * 1024 * 1024:
            raise ModelBindingUnavailable()
        return data
    finally:
        os.close(fd)


@dataclass(frozen=True)
class ModelBinding:
    home: Path
    revision: str
    default_model: str
    default_effort: str | None
    models: tuple[tuple[str, str], ...]
    config_fingerprint: str = field(repr=False)
    catalog_fingerprint: str = field(repr=False)

    def select(self, model):
        selected = self.default_model if model is None else model
        if selected not in {row[0] for row in self.models}:
            raise ModelBindingUnavailable()
        return selected


class LocalCodexBinding:
    def __init__(self, path=DEFAULT_BINDING, *, clock=time.time):
        self.path = Path(path)
        self.clock = clock
        self._pinned: ModelBinding | None = None

    def read(self):
        try:
            raw = json.loads(_read(self.path, private=True))
            if not isinstance(raw, dict) or not set(raw).issubset(_FIELDS):
                raise ModelBindingUnavailable()
            expiry = raw.get('expiresAtMs')
            now = self.clock() * 1000
            if (raw.get('schemaVersion') != 1 or type(raw.get('schemaVersion')) is not int
                    or raw.get('source') != 'osir-client' or raw.get('available') is not True
                    or type(expiry) is not int or not now < expiry <= now + 35000
                    or raw.get('connectionMode') not in {'direct', 'proxy'}):
                raise ModelBindingUnavailable()
            home = _canonical(Path(raw['codexHome']))
            config = _read(home / 'config.toml')
            if hashlib.sha256(config).hexdigest() != raw['configSha256']:
                raise ModelBindingUnavailable()
            doc = tomllib.loads(config.decode('utf-8'))
            pointer = doc.get('model_catalog_json')
            if pointer:
                catalog = Path(pointer)
                catalog = catalog if catalog.is_absolute() else home / catalog
                if hashlib.sha256(_read(catalog)).hexdigest() != raw['catalogSha256']:
                    raise ModelBindingUnavailable()
            elif raw['catalogSha256'] != '':
                raise ModelBindingUnavailable()
            rows = raw['models']
            if not isinstance(rows, list) or not 1 <= len(rows) <= 2048:
                raise ModelBindingUnavailable()
            if any(not isinstance(row, dict) or set(row) != {'id', 'title'}
                    or not _plain(row['id']) or not _plain(row['title']) for row in rows):
                raise ModelBindingUnavailable()
            models = tuple((row['id'], row['title']) for row in rows)
            default = raw['defaultModel']
            effort = raw.get('defaultReasoningEffort')
            if (not _plain(default) or doc.get('model') != default
                    or default not in {row[0] for row in models}
                    or len({row[0] for row in models}) != len(models)
                    or effort is not None and not _plain(effort, 32)
                    or doc.get('model_reasoning_effort') != effort
                    or not isinstance(raw['revision'], str) or not _SHA.fullmatch(raw['revision'])):
                raise ModelBindingUnavailable()
            binding = ModelBinding(home, raw['revision'], default, effort, models,
                raw['configSha256'], raw['catalogSha256'])
            if self._pinned is not None and binding != self._pinned:
                raise ModelBindingUnavailable()
            self._pinned = binding
            return binding
        except (OSError, ValueError, TypeError, KeyError, RuntimeError):
            raise ModelBindingUnavailable() from None

    async def check(self):
        return await asyncio.to_thread(self.read)


class BoundProjectCodexClient(ProjectCodexClient):
    def __init__(self, delegate, scope, binding: LocalCodexBinding):
        super().__init__(delegate, scope)
        self.model_binding = binding

    async def start(self, handler):
        binding = await self.model_binding.check()
        if binding.home != self.scope.codex_home:
            raise ModelBindingUnavailable()
        await super().start(handler)
        # Catch a Client switch concurrent with native startup.
        try:
            await self.model_binding.check()
        except ModelBindingUnavailable:
            await super().stop()
            raise

    async def list_models(self):
        binding = await self.model_binding.check()
        native = await super().list_models()
        available = {row.get('id', row.get('model')): row for row in native.models}
        models = []
        for identifier, title in sorted(binding.models, key=lambda row: row[0] != binding.default_model):
            row = available.get(identifier, {})
            # Only capability fields used by the picker; never native raw config.
            efforts = row.get('supportedReasoningEfforts', ())
            safe = [{'reasoningEffort': item['reasoningEffort']}
                for item in efforts if isinstance(item, dict)
                and _plain(item.get('reasoningEffort'), 32)] if isinstance(efforts, (list, tuple)) else []
            models.append({'id': identifier, 'model': identifier, 'displayName': title,
                'isDefault': identifier == binding.default_model, 'supportedReasoningEfforts': safe})
        return CodexModelListResult(models=tuple(models))

    async def start_thread(self, request):
        binding = await self.model_binding.check()
        return await super().start_thread(replace(request, model=binding.select(request.model)))

    async def resume_thread(self, request):
        binding = await self.model_binding.check()
        return await super().resume_thread(replace(request, model=binding.select(request.model)))

    async def start_turn(self, request):
        binding = await self.model_binding.check()
        return await super().start_turn(replace(request, model=binding.select(request.model),
            effort=request.effort if request.effort is not None else binding.default_effort))

    async def steer_turn(self, request):
        await self.model_binding.check()
        return await super().steer_turn(request)

    async def compact_thread(self, thread_id):
        await self.model_binding.check()
        return await super().compact_thread(thread_id)

    async def respond(self, request_id, result=None):
        await self.model_binding.check()
        return await super().respond(request_id, result)
