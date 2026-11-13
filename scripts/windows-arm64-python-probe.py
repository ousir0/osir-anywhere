"""Probe installed dependencies only; never log in or start a Connector session."""
import importlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import struct
import subprocess
import sys
import sysconfig

evidence = Path(os.environ["OSIR_PREFLIGHT_ROOT"]) / "evidence"
result = {
    "python": sys.version,
    "executable": sys.executable,
    "machine": platform.machine(),
    "platform": sysconfig.get_platform(),
    "pointerBits": struct.calcsize("P") * 8,
    "imports": [],
    "distributions": [],
    "nativeFiles": [],
    "cli": [],
    "errors": [],
    "scope": "Exact Connector dependency set; Connector application source and its CLI are not copied or exercised.",
}


def observe(name, action):
    try:
        value = action()
        result["imports"].append({"name": name, "status": "passed", "result": value})
    except Exception as exc:
        result["imports"].append({"name": name, "status": "failed", "error": str(exc)})
        result["errors"].append(f"{name}: {exc}")


def pe_machine(path):
    with path.open("rb") as stream:
        header = stream.read(64)
        if header[:2] != b"MZ":
            return None
        offset = struct.unpack_from("<I", header, 60)[0]
        stream.seek(offset)
        signature = stream.read(6)
        if signature[:4] != b"PE\0\0":
            raise ValueError(f"Invalid PE: {path}")
        return hex(struct.unpack_from("<H", signature, 4)[0])


try:
    assert sys.version_info[:3] == (3, 12, 14)
    assert sysconfig.get_platform() == "win-arm64"
    assert result["pointerBits"] == 64
    for name in (
        "asyncer", "claude_agent_sdk", "httpx", "jsonschema", "loguru", "meshcall",
        "openai_codex", "psutil", "pydantic", "pydantic_core", "pyte", "python_socks",
        "winpty", "websockets",
    ):
        observe(name, lambda name=name: {"moduleFile": str(importlib.import_module(name).__file__)})
    observe("psutil.native", lambda: importlib.import_module("psutil").Process().memory_info()._asdict())
    observe("pydantic_core.native", lambda: importlib.import_module("pydantic_core").to_json({"native": "arm64"}).decode())

    def conpty():
        from winpty import PtyProcess
        process = PtyProcess.spawn('cmd.exe /d /c echo OSIR_ARM64_CONPTY')
        try:
            text = process.read(4096)
            assert "OSIR_ARM64_CONPTY" in text, repr(text)
            return text
        finally:
            process.close(force=True)

    observe("winpty.native-spawn", conpty)
    binaries = []
    for distribution in sorted(importlib.metadata.distributions(), key=lambda dist: dist.metadata["Name"].lower()):
        name = distribution.metadata["Name"]
        result["distributions"].append({"name": name, "version": distribution.version})
        for file in distribution.files or []:
            if Path(file).suffix.lower() not in (".pyd", ".dll", ".exe"):
                continue
            path = Path(distribution.locate_file(file)).resolve()
            machine = pe_machine(path)
            if machine is None:
                continue
            item = {"distribution": name, "version": distribution.version, "file": str(file), "machine": machine}
            result["nativeFiles"].append(item)
            if machine != "0xaa64":
                result["errors"].append(f"Non-ARM64 PE in {name}: {file} machine={machine}")
            if path.name.lower() in ("codex.exe", "claude.exe"):
                binaries.append((name, path, ["--version"]))
    meshcall = Path(sys.executable).parent / "meshcall.exe"
    if meshcall.exists():
        binaries.append(("meshcall", meshcall, ["--help"]))
    for distribution, binary, args in binaries:
        completed = subprocess.run([str(binary), *args], capture_output=True, text=True, timeout=60)
        item = {"distribution": distribution, "binary": str(binary), "arguments": args, "exitCode": completed.returncode, "stdout": completed.stdout[-8000:], "stderr": completed.stderr[-8000:]}
        result["cli"].append(item)
        if completed.returncode:
            result["errors"].append(f"CLI failed: {distribution} {binary.name} exit={completed.returncode}")
    for required in ("codex.exe", "claude.exe", "meshcall.exe"):
        if not any(Path(item["binary"]).name.lower() == required for item in result["cli"]):
            result["errors"].append(f"Required dependency CLI not located: {required}")
except Exception as exc:
    result["errors"].append(str(exc))
finally:
    (evidence / "python-native-dependencies.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
sys.exit(1 if result["errors"] else 0)
