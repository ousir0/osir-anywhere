from __future__ import annotations

import os
from pathlib import Path

DATA_DIR_ENV = "AGENT_CONNECTOR_DATA_DIR"
DATA_DIR_NAME = ".agents-anywhere"
LEGACY_DATA_DIR_NAME = ".agent-server"
LEGACY_SQLITE_NAMES = {
    "connector-state.sqlite3",
    "connector-state.sqlite3-shm",
    "connector-state.sqlite3-wal",
}


def connector_data_dir() -> Path:
    configured = configured_data_dir()
    if configured is not None:
        return configured
    home = Path.home()
    canonical = home / DATA_DIR_NAME
    _merge_legacy_data_dir(home / LEGACY_DATA_DIR_NAME, canonical)
    canonical.mkdir(parents=True, exist_ok=True)
    canonical.chmod(0o700)
    return canonical


def configured_data_dir() -> Path | None:
    configured = os.environ.get(DATA_DIR_ENV, "").strip()
    if not configured:
        return None
    directory = Path(configured)
    if not directory.is_absolute():
        raise ValueError(f"{DATA_DIR_ENV} must be an absolute directory (no ~)")
    return directory.resolve(strict=False)


def connector_runtime_root() -> Path:
    configured = configured_data_dir()
    if configured is not None:
        return configured
    # Preserve the upstream OS-account home and its test seam; credentials have
    # separate legacy migration semantics in connector_data_dir().
    from connector.core import runtime_owner

    return runtime_owner.system_home() / DATA_DIR_NAME


def connector_runtime_path() -> Path:
    return connector_runtime_root() / "connector-runtime.json"


def connector_logs_dir() -> Path:
    return connector_runtime_root() / "logs"


def connector_router_dir() -> Path:
    return connector_runtime_root() / "router"


def connector_dsh_bridge_dir() -> Path:
    return connector_runtime_root() / "dsh-bridge"


def _merge_legacy_data_dir(legacy: Path, canonical: Path) -> None:
    if not legacy.is_dir():
        return
    canonical.mkdir(parents=True, exist_ok=True)
    canonical.chmod(0o700)
    for source in legacy.iterdir():
        if source.name in LEGACY_SQLITE_NAMES:
            source.unlink(missing_ok=True)
            continue
        target = _available_target(canonical / source.name)
        source.replace(target)
    legacy.rmdir()


def _available_target(target: Path) -> Path:
    if not target.exists():
        return target
    index = 1
    while True:
        candidate = target.with_name(f"{target.name}.legacy-{index}")
        if not candidate.exists():
            return candidate
        index += 1
