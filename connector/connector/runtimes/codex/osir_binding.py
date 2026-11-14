"""Native Client descriptor reader; independent of project acceptance bridges.

The descriptor is a same-user, short-lived consistency grant, not protection
against arbitrary code running as that user. Never export raw native config.
"""
from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import os
import re
import stat
import time
import tomllib
from contextlib import ExitStack
from dataclasses import dataclass, field
from pathlib import Path

from connector.runtime_protocol import RuntimeUnavailableError

POLICY_ENV = "OSIR_CLIENT_MODEL_BINDING"
POLICY_REQUIRED = "required-v1"
HOME_ENV = "OSIR_CLIENT_BINDING_HOME"
MAXIMUM = 2 * 1024 * 1024
# Native model catalogs include model instructions and exceed the descriptor's
# small limit even when the authorized model list itself is short.
CATALOG_MAXIMUM = 16 * 1024 * 1024
_SHA = re.compile(r"[a-f0-9]{64}\Z")
_FIELDS = {"schemaVersion", "source", "available", "expiresAtMs", "errorCode",
    "codexHome", "connectionMode", "defaultModel", "defaultReasoningEffort",
    "models", "configSha256", "catalogSha256", "revision"}


class ModelBindingUnavailable(RuntimeUnavailableError):
    code = "osir_model_binding_unavailable"

    def __init__(self):
        super().__init__("OSIR 模型配置已变化或不可用，请打开 OSIR 客户端后重新连接。")


def plain(value, maximum=256):
    return (isinstance(value, str) and 0 < len(value) <= maximum
        and not any(ord(c) < 32 or ord(c) == 127 for c in value))


def canonical_directory(value) -> Path:
    path = Path(value)
    if os.name == "nt":
        from .osir_binding_windows import canonical_directory as windows_directory
        return windows_directory(path)
    if (not path.is_absolute() or ".." in path.parts or path.resolve(strict=True) != path
            or not path.is_dir() or any(p.is_symlink() for p in (path, *path.parents))):
        raise ModelBindingUnavailable()
    return path


def read_secure(path: Path, *, private=False, maximum=MAXIMUM) -> bytes:
    if (type(maximum) is not int or type(private) is not bool
            or not 0 <= maximum <= (MAXIMUM if private else CATALOG_MAXIMUM)):
        raise ModelBindingUnavailable()
    if os.name == "nt":
        from .osir_binding_windows import read_secure as windows_read
        return windows_read(path, private=private, maximum=maximum)
    # Pin every directory, not merely lstat() before a following open().
    if not path.is_absolute() or ".." in path.parts:
        raise ModelBindingUnavailable()
    with ExitStack() as handles:
        directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        handles.callback(os.close, directory)
        chain = []
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=directory)
            handles.callback(os.close, child)
            info = os.fstat(child)
            chain.append((directory, part, info.st_dev, info.st_ino, info.st_uid, info.st_mode))
            directory = child
            # Root-owned sticky temporary ancestors are allowed, with pinned
            # protected children. Retain each ancestor handle until recheck.
            if ((info.st_uid not in {0, os.getuid()} or info.st_mode & 0o022)
                    and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX)):
                raise ModelBindingUnavailable()
        parent = os.fstat(directory)
        if private and (parent.st_uid != os.getuid() or stat.S_IMODE(parent.st_mode) != 0o700):
            raise ModelBindingUnavailable()
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=directory)
        handles.callback(os.close, fd)
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_size > maximum
                or info.st_uid != os.getuid() or info.st_mode & 0o022
                or private and stat.S_IMODE(info.st_mode) != 0o600):
            raise ModelBindingUnavailable()
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(maximum + 1)
        after = os.fstat(fd)
        named = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
        identity = lambda row: (row.st_dev, row.st_ino, row.st_size, row.st_mtime_ns,
            row.st_ctime_ns, row.st_uid, row.st_mode, row.st_nlink)
        if (len(data) != info.st_size or len(data) > maximum
                or identity(info) != identity(after) or identity(after) != identity(named)):
            raise ModelBindingUnavailable()
        for parent_fd, part, device, inode, owner, mode in chain:
            current = os.stat(part, dir_fd=parent_fd, follow_symlinks=False)
            if ((current.st_dev, current.st_ino, current.st_uid, current.st_mode)
                    != (device, inode, owner, mode)):
                raise ModelBindingUnavailable()
        # This detects replacement during sampling; it is not a lock against
        # same-user mutations after return. Config/descriptor are sampled again.
        return data


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ModelBindingUnavailable()
        result[key] = value
    return result


@dataclass(frozen=True)
class ModelBinding:
    home: Path
    revision: str
    default_model: str
    default_effort: str | None
    models: tuple[tuple[str, str], ...]
    config_fingerprint: str = field(repr=False)
    catalog_fingerprint: str = field(repr=False)
    route: dict = field(repr=False)

    def select(self, model):
        selected = self.default_model if model is None else model
        if selected not in {row[0] for row in self.models}:
            raise ModelBindingUnavailable()
        return selected

    def native_config(self):
        """Private stdio RPC config, never argv/metadata/logs or cloud values."""
        return copy.deepcopy(self.route)


class LocalCodexBinding:
    def __init__(self, path: Path, *, clock=time.time):
        self.path = Path(path)
        self.clock = clock
        self._pinned: ModelBinding | None = None

    @classmethod
    def for_product(cls):
        # Only Desktop's trusted bootstrap sets this; runtime config has no path.
        home = os.environ.get(HOME_ENV)
        if not home:
            raise ModelBindingUnavailable()
        return cls(canonical_directory(home) / ".osir_client/anywhere/codex-binding.json")

    def fresh(self):
        return type(self)(self.path, clock=self.clock)

    def read(self) -> ModelBinding:
        try:
            descriptor = read_secure(self.path, private=True)
            raw = json.loads(descriptor, object_pairs_hook=_unique)
            if not isinstance(raw, dict) or not set(raw).issubset(_FIELDS):
                raise ModelBindingUnavailable()
            expiry, now = raw.get("expiresAtMs"), self.clock() * 1000
            if (type(raw.get("schemaVersion")) is not int or raw["schemaVersion"] != 1
                    or raw.get("source") != "osir-client" or raw.get("available") is not True
                    or type(expiry) is not int or not now < expiry <= now + 35000
                    or raw.get("connectionMode") not in {"direct", "proxy"}):
                raise ModelBindingUnavailable()
            home = canonical_directory(raw["codexHome"])
            config = read_secure(home / "config.toml")
            if hashlib.sha256(config).hexdigest() != raw["configSha256"]:
                raise ModelBindingUnavailable()
            doc = tomllib.loads(config.decode("utf-8"))
            pointer = doc.get("model_catalog_json")
            catalog_hash = raw["catalogSha256"]
            if pointer:
                catalog = Path(pointer)
                catalog = catalog if catalog.is_absolute() else home / catalog
                if hashlib.sha256(read_secure(catalog, maximum=CATALOG_MAXIMUM)).hexdigest() != catalog_hash:
                    raise ModelBindingUnavailable()
            elif catalog_hash != "":
                raise ModelBindingUnavailable()
            rows = raw["models"]
            if not isinstance(rows, list) or not 1 <= len(rows) <= 2048:
                raise ModelBindingUnavailable()
            if any(not isinstance(row, dict) or set(row) != {"id", "title"}
                    or not plain(row["id"]) or not plain(row["title"]) for row in rows):
                raise ModelBindingUnavailable()
            models = tuple((row["id"], row["title"]) for row in rows)
            default, effort = raw["defaultModel"], raw.get("defaultReasoningEffort")
            if (not plain(default) or doc.get("model") != default
                    or default not in {row[0] for row in models}
                    or len({row[0] for row in models}) != len(models)
                    or effort is not None and not plain(effort, 32)
                    or doc.get("model_reasoning_effort") != effort
                    or not isinstance(raw["revision"], str) or not _SHA.fullmatch(raw["revision"])):
                raise ModelBindingUnavailable()
            provider = doc.get("model_provider", "openai")
            if not plain(provider):
                raise ModelBindingUnavailable()
            definitions = doc.get("model_providers", {})
            definition = definitions.get(provider) if isinstance(definitions, dict) else None
            if (provider != "openai" and not isinstance(definition, dict)
                    or definition is not None and not isinstance(definition, dict)):
                raise ModelBindingUnavailable()
            route = {"model": default, "model_provider": provider}
            if definition is not None:
                route["model_providers"] = {provider: definition}
            if pointer:
                route["model_catalog_json"] = str(catalog)
            if effort is not None:
                route["model_reasoning_effort"] = effort
            binding = ModelBinding(home, raw["revision"], default, effort, models,
                raw["configSha256"], catalog_hash, route)
            if self._pinned is not None and binding != self._pinned:
                raise ModelBindingUnavailable()
            # Detect a concurrent publisher/config write during this sample.
            if hashlib.sha256(read_secure(home / "config.toml")).hexdigest() != binding.config_fingerprint:
                raise ModelBindingUnavailable()
            if pointer and hashlib.sha256(read_secure(catalog, maximum=CATALOG_MAXIMUM)).hexdigest() != catalog_hash:
                raise ModelBindingUnavailable()
            if read_secure(self.path, private=True) != descriptor:
                raise ModelBindingUnavailable()
            self._pinned = binding
            return binding
        except (OSError, ValueError, TypeError, KeyError, RuntimeError, ImportError):
            raise ModelBindingUnavailable() from None

    async def check(self):
        return await asyncio.to_thread(self.read)


def bound_environment(home: Path) -> dict[str, str]:
    # SDK versions merge env over os.environ: explicitly neutralize every
    # inherited variable, then restore only benign local OS necessities.
    allowed = {"PATH", "HOME", "USERPROFILE", "SystemRoot", "SYSTEMROOT", "WINDIR",
        "COMSPEC", "PATHEXT", "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL", "LC_CTYPE",
        "APPDATA", "LOCALAPPDATA", "USER", "LOGNAME"}
    env = {key: "" for key in os.environ}
    env.update({key: os.environ[key] for key in allowed if key in os.environ})
    # Native HTTP clients can discover OS proxies even after env scrubbing.
    # Keep local Client routes direct; inherited bypass lists cannot widen this.
    env["NO_PROXY"] = env["no_proxy"] = "127.0.0.1,localhost,::1"
    env["CODEX_HOME"] = str(home)
    # An empty CLI originator becomes an invalid SDK user-agent prefix.
    env["CODEX_INTERNAL_ORIGINATOR_OVERRIDE"] = "osir_anywhere_connector"
    return env
