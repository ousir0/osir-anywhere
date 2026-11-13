"""Pinned macOS Seatbelt acceptance runner, independent of the old M0 gate.

This is deliberately independent of CodexRuntime, IPC and the M0 gate.
offline_preflight() never connects. run() permits one fixed local proxy turn only
after offline/native endpoint isolation tests and validates JSON events in flight.
Synthetic probe artifacts live in a fresh /private/tmp directory, then disappear.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import selectors
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from contextvars import ContextVar
from dataclasses import asdict, dataclass
from pathlib import Path

WORKSPACE = Path("/Users/ouwei/agents-anywhere/.local-dev/acceptance-workspace")
CODEX_EXECUTABLE = Path(
    "/Applications/ChatGPT.app/Contents/Resources/codex-cli/"
    "CodexCLI.app/Contents/MacOS/codex"
)
CODEX_SHA256 = "a636331ed87605efc4cf84028ac2884a75363f9d10ead63cffb57ea0016d486e"
# Explicit compatibility option, never auto-selected or downloaded by this module.
# Official @openai/codex 0.156.1-darwin-arm64 npm tarball, SHA-512 integrity checked.
COMPATIBILITY_CODEX_SHA256 = "0196e89fe5a7598f816ee54232c3d7c26d75e502ab5cfe2c9240e81d90f7255a"
MODEL = "ccs-osir-api-5/gpt-6"
PROMPT = "Reply OSIR_M0_OK"
EXPECTED_TEXT = "OSIR_M0_OK"
PROXY_URL = "http://127.0.0.1:15721/v1"
MAX_OUTPUT_BYTES = 65536
SANDBOX_EXEC = "/usr/bin/sandbox-exec"
COMPILER = "/Library/Developer/CommandLineTools/usr/bin/clang"
SDK = "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk"
_TOTAL_DEADLINE: ContextVar[float | None] = ContextVar("osir_acceptance_deadline", default=None)
PUBLIC_SYSTEM_READS = (
    Path("/etc/codex/requirements.toml"), Path("/private/etc/codex/requirements.toml"),
)


class AcceptanceIsolationError(RuntimeError):
    """A required isolation or event check failed; no fallback exists."""


@dataclass(frozen=True)
class AcceptanceDiagnostic:
    returncode: int | None
    accepted_events: int
    categories: tuple[str, ...]
    public_paths: tuple[str, ...]
    stderr_bytes: int


def _diagnose(
    stderr: bytes, accepted_events: int, returncode: int | None, rejected_event: bytes = b"",
) -> AcceptanceDiagnostic:
    # Only fixed categories and explicitly public path names may leave memory.
    public = (
        "/etc/passwd", "/private/etc/passwd", "/etc/group", "/private/etc/group",
        "/etc/hosts", "/private/etc/hosts", "/etc/resolv.conf", "/private/etc/resolv.conf",
        "/etc/localtime", "/private/etc/localtime", "/dev/tty", "/dev/fd",
        *(str(path) for path in PUBLIC_SYSTEM_READS),
    )
    category_markers = {
        "permission-denied": (b"operation not permitted", b"permission denied"),
        "user-lookup": (b"getpwuid", b"passwd", b"current user", b"user name", b"username"),
        "home-resolution": (b"home directory", b"home_dir"),
        "isolated-home-canonicalization": (b"canonicalize",),
        "config-loading": (b"config",),
        "sqlite": (b"sqlite", b"database"),
        "process-spawn": (b"spawn", b"exec"),
        "sandbox-initialization": (b"sandbox",),
        "thread-initialization": (b"thread",),
        "terminal": (b"terminal", b"/dev/tty"),
        "git": (b"git",),
        "file-open": (b"open",),
        "argument-or-config": (b"unexpected argument", b"unknown field"),
        "in-process-app-server-stdin-read": (b"reading stdin",),
        "in-process-app-server-initialization": (b"initialize in-process app-server",),
        "managed-preferences-sync": (b"failed to synchronize managed preferences",),
        "model-metadata-fallback": (b"defaulting to fallback metadata",),
    }
    lowered = (stderr + b"\n" + rejected_event).lower()
    return AcceptanceDiagnostic(
        returncode, accepted_events,
        tuple(name for name, markers in category_markers.items() if any(m in lowered for m in markers)),
        tuple(path for path in public if path.encode() in stderr), len(stderr),
    )


@dataclass(frozen=True)
class AcceptanceCounts:
    native_probes: int
    thread_started: int
    turn_started: int
    agent_message: int
    turn_completed: int


@dataclass(frozen=True)
class AcceptanceResult:
    thread_id: str
    text: str
    counts: AcceptanceCounts


@dataclass(frozen=True)
class ProbeResult:
    name: str
    passed: bool
    returncode: int


@dataclass(frozen=True)
class AcceptanceReport:
    filesystem_verified: bool
    cli_startup_verified: bool
    no_tools_verified: bool
    model_execution_allowed: bool
    workspace: str
    model: str
    prompt: str
    executable_sha256: str
    probes: tuple[ProbeResult, ...]
    cli_version: str
    cli_help: str
    exec_help: str
    blocker: str


def _literal(path: Path | str) -> str:
    # JSON string escaping is also valid for the restricted SBPL path strings.
    return json.dumps(str(path), ensure_ascii=True)


def _check_directory(path: Path) -> None:
    if not path.is_absolute():
        raise AcceptanceIsolationError("Absolute directories required")
    try:
        for component in (*reversed(path.parents), path):
            mode = component.lstat().st_mode
            if not stat.S_ISDIR(mode) or stat.S_ISLNK(mode):
                raise AcceptanceIsolationError("Directory contains a symlink or non-directory")
    except OSError as exc:
        raise AcceptanceIsolationError("Required directory unavailable") from exc


def _check_workspace() -> None:
    _check_directory(WORKSPACE)
    if any(WORKSPACE.iterdir()):
        raise AcceptanceIsolationError("Pinned acceptance cwd must remain empty")


def _environment(home: Path, temp: Path) -> dict[str, str]:
    # Never copy os.environ, discover login shells, read auth or use SDK defaults.
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": str(home),
        "CFFIXED_USER_HOME": str(home),
        "CODEX_HOME": str(home),
        "XDG_CONFIG_HOME": str(home),
        "XDG_CACHE_HOME": str(temp),
        "XDG_DATA_HOME": str(home),
        "TMPDIR": str(temp) + "/",
        "LANG": "C",
        "LC_ALL": "C",
        "OPENAI_API_KEY": "PROXY_MANAGED",
        "OTEL_SDK_DISABLED": "true",
    }


def _profile(
    home: Path, temp: Path, executables: tuple[Path, ...], *, managed_proxy: bool = False,
    pinned_cli: Path | None = None,
) -> str:
    """Default deny; optional exact IPv4 proxy endpoint, never Unix/Mach IPC."""
    readable = [
        '(literal "/")',  # dyld needs this even for /usr/bin/true on this macOS.
        '(subpath "/System/Library")',
        '(subpath "/usr/lib")',
        '(literal "/dev/null")',
        '(literal "/dev/urandom")',
        '(literal "/dev/random")',
        f"(literal {_literal(WORKSPACE)})",
        f"(subpath {_literal(home)})",
        f"(subpath {_literal(temp)})",
        *(f"(literal {_literal(path)})" for path in executables),
        *(f"(literal {_literal(path)})" for path in PUBLIC_SYSTEM_READS),
    ]
    # realpath() needs stat of the known path components, not directory data.
    # No child metadata, directory listing or user file reads are granted.
    cli = CODEX_EXECUTABLE if pinned_cli is None else pinned_cli
    metadata = sorted({
        Path("/private"), Path("/private/tmp"), home.parent,
        *WORKSPACE.parents, *cli.parents, cli,
        *(parent for path in PUBLIC_SYSTEM_READS for parent in path.parents),
    })
    return "\n".join([
        "(version 1)",
        "(deny default)",
        "(allow process-fork)",
        "(allow signal (target self))",
        "(allow sysctl-read)",
        "(allow process-exec "
        + " ".join(f"(literal {_literal(path)})" for path in executables) + ")",
        "(allow file-read* " + " ".join(readable) + ")",
        "(allow file-read-metadata "
        + " ".join(f"(literal {_literal(path)})" for path in metadata) + ")",
        f"(allow file-write* (subpath {_literal(home)}) (subpath {_literal(temp)}))",
        '(allow file-write-data (literal "/dev/null"))',
        *(['(allow network-outbound (remote tcp4 "localhost:15721"))'] if managed_proxy else []),
    ])


def _capture(
    argv: list[str], env: dict[str, str], *, timeout: float = 10,
    event_gate: _EventGate | None = None,
) -> tuple[int, bytes, bytes]:
    """Bound output/time and kill the process group, including forked probes."""
    total_deadline = _TOTAL_DEADLINE.get()
    if total_deadline is not None:
        timeout = min(timeout, total_deadline - time.monotonic())
    if timeout <= 0:
        raise AcceptanceIsolationError("Acceptance total deadline exceeded")
    proc = subprocess.Popen(
        argv, cwd=WORKSPACE, env=env, stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True,
        start_new_session=True,
    )
    # The in-process app-server reads stdin through an async reactor. Darwin
    # cannot register /dev/null as a readable kqueue source; give it a real pipe
    # with immediate EOF. No caller input can alter the fixed prompt.
    proc.stdin.close()
    output = {"stdout": bytearray(), "stderr": bytearray()}
    total_bytes = 0
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            for name in output:
                selector.register(getattr(proc, name), selectors.EVENT_READ, name)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise AcceptanceIsolationError("Offline child timed out")
                for key, _ in selector.select(min(remaining, 0.1)):
                    chunk = os.read(key.fileobj.fileno(), 8192)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    total_bytes += len(chunk)
                    if total_bytes > MAX_OUTPUT_BYTES:
                        raise AcceptanceIsolationError("Acceptance child exceeded output limit")
                    if key.data == "stdout" and event_gate is not None:
                        event_gate.feed(chunk)
                    else:
                        output[key.data].extend(chunk)
                        if event_gate is not None and key.data == "stderr":
                            event_gate._stderr.extend(chunk)
            proc.wait(timeout=max(0.001, deadline - time.monotonic()))
        return proc.returncode, bytes(output["stdout"]), bytes(output["stderr"])
    finally:
        # Also kill descendants after their leader has exited and closed pipes.
        with contextlib.suppress(ProcessLookupError):
            os.killpg(proc.pid, signal.SIGKILL)
        proc.wait()
        proc.stdout.close()
        proc.stderr.close()


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise AcceptanceIsolationError("Duplicate event JSON key")
        result[key] = value
    return result


class _EventGate:
    """Exactly one new thread/turn/message/completion, without raw event egress."""

    def __init__(self) -> None:
        self._buffer = bytearray()
        self._stage = 0
        self._thread_id = ""
        self._stderr = bytearray()  # Bounded, private in-memory diagnostics only.
        self._rejected_event = b""

    def feed(self, chunk: bytes) -> None:
        self._buffer.extend(chunk)
        while b"\n" in self._buffer:
            line, _, rest = self._buffer.partition(b"\n")
            self._buffer = bytearray(rest)
            self._event(bytes(line))

    def _event(self, line: bytes) -> None:
        # Retain a rejected error chain privately, without accepting its event.
        self._rejected_event = line
        try:
            event = json.loads(line.decode("utf-8"), object_pairs_hook=_unique_object)
        except (UnicodeError, ValueError) as exc:
            raise AcceptanceIsolationError("Malformed CLI JSON event") from exc
        if not isinstance(event, dict):
            raise AcceptanceIsolationError("CLI event must be an object")
        kind = event.get("type")
        expected = ("thread.started", "turn.started", "item.completed", "turn.completed")
        if self._stage >= len(expected) or kind != expected[self._stage]:
            raise AcceptanceIsolationError("Unexpected CLI event/order")
        if kind == "thread.started":
            if set(event) != {"type", "thread_id"}:
                raise AcceptanceIsolationError("Unexpected thread event fields")
            value = event["thread_id"]
            try:
                parsed = uuid.UUID(value) if isinstance(value, str) else None
            except ValueError as exc:
                raise AcceptanceIsolationError("New thread must have a UUID") from exc
            if parsed is None or not parsed.int or str(parsed) != value:
                raise AcceptanceIsolationError("New thread must have a canonical UUID")
            self._thread_id = value
        elif kind == "turn.started":
            if set(event) != {"type"}:
                raise AcceptanceIsolationError("Unexpected turn event fields")
        elif kind == "item.completed":
            item = event.get("item")
            if set(event) != {"type", "item"} or not isinstance(item, dict):
                raise AcceptanceIsolationError("Unexpected completed event fields")
            if set(item) != {"id", "type", "text"} or item.get("type") != "agent_message":
                raise AcceptanceIsolationError("Only a fixed agent_message is accepted; tools denied")
            if not isinstance(item["id"], str) or not item["id"] or item["text"] != EXPECTED_TEXT:
                raise AcceptanceIsolationError("Agent text differs from the fixed acceptance text")
        else:
            usage = event.get("usage")
            if set(event) != {"type", "usage"} or not isinstance(usage, dict):
                raise AcceptanceIsolationError("Unexpected completion fields")
            required = {"input_tokens", "cached_input_tokens", "output_tokens"}
            extended = required | {"cache_write_input_tokens", "reasoning_output_tokens"}
            if set(usage) not in (required, extended) or any(
                type(value) is not int or value < 0 for value in usage.values()
            ):
                raise AcceptanceIsolationError("Unexpected usage fields")
        self._stage += 1
        self._rejected_event = b""

    def finish(self, native_probes: int) -> AcceptanceResult:
        if self._buffer:
            self._event(bytes(self._buffer))
            self._buffer.clear()
        if self._stage != 4:
            raise AcceptanceIsolationError("Incomplete CLI thread/turn/message/completion")
        return AcceptanceResult(
            thread_id=self._thread_id, text=EXPECTED_TEXT,
            counts=AcceptanceCounts(native_probes, 1, 1, 1, 1),
        )


# Compiled only as a synthetic local probe. It never opens real user paths.
# Exit 0 means the requested assertion passed; ENOENT is NOT a denial success.
_PROBE_SOURCE = r'''
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static int denied(void) { return errno == EACCES || errno == EPERM; }
int main(int argc, char **argv) {
    if (argc < 3) return 80;
    const char *mode = argv[1], *path = argv[2];
    if (!strcmp(mode, "allow-public-read-or-absent")) {
        int fd = open(path, O_RDONLY);
        if (fd >= 0) { close(fd); return 0; }
        return errno == ENOENT ? 0 : 111;
    }
    if (!strcmp(mode, "allow-realpath")) {
        char *resolved = realpath(path, NULL);
        if (!resolved) return 108;
        int ok = !strcmp(resolved, path); free(resolved); return ok ? 0 : 109;
    }
    if (!strcmp(mode, "deny-metadata")) {
        struct stat info;
        return stat(path, &info) == -1 && denied() ? 0 : 110;
    }
    if (!strcmp(mode, "allow-read") || !strcmp(mode, "deny-read")) {
        int fd = open(path, O_RDONLY);
        if (!strcmp(mode, "deny-read")) {
            if (fd >= 0) { close(fd); return 81; }
            return denied() ? 0 : 82;
        }
        if (fd < 0) return 83;
        char value[8]; int n = (int)read(fd, value, sizeof(value)); close(fd);
        return n > 0 ? 0 : 84;
    }
    if (!strcmp(mode, "allow-write") || !strcmp(mode, "deny-write")) {
        int fd = open(path, O_CREAT | O_WRONLY, 0600);
        if (!strcmp(mode, "deny-write")) {
            if (fd >= 0) { close(fd); return 85; }
            return denied() ? 0 : 86;
        }
        if (fd < 0) return 87;
        int n = (int)write(fd, "OK", 2); close(fd); return n == 2 ? 0 : 88;
    }
    if (!strcmp(mode, "shell")) {
        execl("/bin/bash", "bash", "--noprofile", "--norc", "-c",
              "exec /bin/cat \"$1\"", "probe", path, NULL);
        return 89;
    }
    if (!strcmp(mode, "deny-exec")) {
        execl(path, path, NULL); return denied() ? 0 : 90;
    }
    if (!strcmp(mode, "deny-chdir-read")) {
        if (chdir(path) < 0) return denied() ? 0 : 91;
        int fd = open("canary", O_RDONLY);
        if (fd >= 0) { close(fd); return 92; }
        return denied() ? 0 : 93;
    }
    if (!strcmp(mode, "deny-fd")) {
        errno = 0; int flags = fcntl(atoi(path), F_GETFD);
        return flags == -1 && errno == EBADF ? 0 : 94;
    }
    if (!strcmp(mode, "deny-link")) {
        if (argc != 4) return 95;
        return link(path, argv[3]) == -1 && denied() ? 0 : 96;
    }
    if (!strcmp(mode, "deny-unix")) {
        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) return denied() ? 0 : 97;
        struct sockaddr_un addr = {0}; addr.sun_family = AF_UNIX;
        snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);
        int result = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
        int ok = result == -1 && denied(); close(fd); return ok ? 0 : 98;
    }
    if (!strcmp(mode, "deny-tcp") || !strcmp(mode, "allow-proxy") || !strcmp(mode, "deny-alias")) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return denied() ? 0 : 99;
        struct sockaddr_in addr = {0}; addr.sin_family = AF_INET;
        addr.sin_port = htons(atoi(path));
        inet_pton(AF_INET, !strcmp(mode, "deny-alias") ? "127.0.0.2" : "127.0.0.1", &addr.sin_addr);
        int result = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
        if (!strcmp(mode, "allow-proxy")) { close(fd); return result == 0 ? 0 : 103; }
        int ok = result == -1 && denied(); close(fd); return ok ? 0 : 100;
    }
    if (!strcmp(mode, "deny-ipv6")) {
        int fd = socket(AF_INET6, SOCK_STREAM, 0);
        if (fd < 0) return denied() ? 0 : 104;
        struct sockaddr_in6 addr = {0}; addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(atoi(path)); inet_pton(AF_INET6, "::1", &addr.sin6_addr);
        int result = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
        int ok = result == -1 && denied(); close(fd); return ok ? 0 : 105;
    }
    if (!strcmp(mode, "deny-udp")) {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) return denied() ? 0 : 106;
        struct sockaddr_in addr = {0}; addr.sin_family = AF_INET;
        addr.sin_port = htons(atoi(path)); inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
        int result = (int)sendto(fd, "SYNTHETIC", 9, 0, (struct sockaddr *)&addr, sizeof(addr));
        int ok = result == -1 && denied(); close(fd); return ok ? 0 : 107;
    }
    if (!strcmp(mode, "deny-mach")) {
        mach_port_t service = MACH_PORT_NULL;
        kern_return_t result = bootstrap_look_up(bootstrap_port, path, &service);
        if (service != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), service);
        return result == BOOTSTRAP_NOT_PRIVILEGED ? 0 : 101;
    }
    return 102;
}
'''


class OsirAcceptanceRunner:
    """Single-use fixed local turn; no cloud configuration/credentials accepted.

    offline_preflight() launches compiled adversarial probes, then *only*
    --version, --help and exec --help under the same offline Seatbelt policy.
    run() requires those checks plus native proxy-only checks before one turn.
    No generic argv, environment override, resume or IPC API exists.
    compatibility_cli explicitly selects an independently provisioned official
    0.156.1 binary with a fixed content hash; there is no automatic fallback.
    """

    def __init__(self, *, compatibility_cli: Path | None = None) -> None:
        # The caller may provision an official 0.156.1 native binary separately.
        # Content is still pinned, with no generic command/config override API.
        self._executable = CODEX_EXECUTABLE if compatibility_cli is None else Path(compatibility_cli)
        self._expected_sha256 = CODEX_SHA256 if compatibility_cli is None else COMPATIBILITY_CODEX_SHA256
        self._used = False
        self.last_diagnostic: AcceptanceDiagnostic | None = None
        self._last_stderr = b""  # Never serialized or included in exceptions/results.
        self._last_rejected_event = b""

    def run(self) -> AcceptanceResult:
        with self._context() as (root, digest):
            report = self._inspect(root, digest)
            if not report.filesystem_verified or not report.cli_startup_verified:
                failed = ", ".join(f"{p.name}={p.returncode}" for p in report.probes if not p.passed)
                raise AcceptanceIsolationError("Offline isolation failed: " + failed)
            network = self._managed_probe(root)
            if not all(p.passed for p in network):
                failed = ", ".join(f"{p.name}={p.returncode}" for p in network if not p.passed)
                raise AcceptanceIsolationError("Managed proxy isolation failed: " + failed)
            # The actual model gets a second completely fresh Home, with none of
            # the probe files or links. Only our fixed synthetic config is copied.
            home, temp = root / "run-home", root / "run-tmp"
            home.mkdir(mode=0o700)
            temp.mkdir(mode=0o700)
            self._write_config(home)
            _check_workspace()
            gate = _EventGate()
            try:
                code, _, stderr = _capture(
                [SANDBOX_EXEC, "-p", _profile(
                    home, temp, (self._executable,), managed_proxy=True, pinned_cli=self._executable,
                 ), str(self._executable), "--no-daemon", "--strict-config",
                 "--ask-for-approval", "never", "--sandbox", "read-only", "--cd", str(WORKSPACE),
                 "exec", "--skip-git-repo-check", "--ephemeral", "--ignore-rules",
                 "--json", "--color", "never", "--model", MODEL, PROMPT],
                    _environment(home, temp), timeout=40, event_gate=gate,
                )
            except AcceptanceIsolationError:
                self._last_stderr = bytes(gate._stderr)
                self._last_rejected_event = gate._rejected_event
                self.last_diagnostic = _diagnose(
                    self._last_stderr, gate._stage, None, self._last_rejected_event,
                )
                raise
            self._last_stderr = stderr
            self.last_diagnostic = _diagnose(stderr, gate._stage, code)
            if code:
                # Never include raw stderr/events, arbitrary provider text or secrets.
                reason = "native initialization or model execution failed"
                if b"Operation not permitted" in stderr or b"Permission denied" in stderr:
                    reason = "native initialization denied by the unchanged Seatbelt policy"
                if b"unexpected argument" in stderr or b"unknown field" in stderr:
                    reason = "pinned CLI rejected the fixed invocation/config"
                raise AcceptanceIsolationError(f"CLI exit {code}: {reason}; no retry or relaxation")
            result = gate.finish(sum(not p.name.startswith("cli-") for p in report.probes) + len(network))
            _check_workspace()
            return result

    def offline_preflight(self) -> AcceptanceReport:
        with self._context() as (root, digest):
            return self._inspect(root, digest)

    @contextlib.contextmanager
    def _context(self):
        if self._used:
            raise AcceptanceIsolationError("Acceptance runner is single-use")
        self._used = True  # Failure or cancellation never releases this reservation.
        if sys.platform != "darwin" or not Path(SANDBOX_EXEC).is_file():
            raise AcceptanceIsolationError("macOS sandbox-exec unavailable; no fallback")
        _check_workspace()
        _check_directory(self._executable.parent)
        info = self._executable.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise AcceptanceIsolationError("Pinned CLI must be a regular native executable")
        with self._executable.open("rb") as source:
            digest = hashlib.file_digest(source, "sha256").hexdigest()
        if digest != self._expected_sha256:
            raise AcceptanceIsolationError("Installed CLI changed; offline review required")
        fd = os.open(WORKSPACE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        token = _TOTAL_DEADLINE.set(time.monotonic() + 50)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise AcceptanceIsolationError("Another acceptance probe holds the workspace") from exc
            with tempfile.TemporaryDirectory(prefix="osir-acceptance-", dir="/private/tmp") as name:
                yield Path(name), digest
        finally:
            os.close(fd)
            _TOTAL_DEADLINE.reset(token)

    def _inspect(self, root: Path, digest: str) -> AcceptanceReport:
        home, temp = root / "home", root / "tmp"
        home.mkdir(mode=0o700)
        temp.mkdir(mode=0o700)
        env = _environment(home, temp)
        self._write_config(home)
        source, probe = root / "probe.c", root / "probe"
        source.write_text(_PROBE_SOURCE, encoding="utf-8")
        code, _, _ = _capture(
            [COMPILER, "-isysroot", SDK, "-O0", "-Wall", "-Werror", str(source), "-o", str(probe)],
            env, timeout=30,
        )
        if code:
            raise AcceptanceIsolationError("Native probe compilation failed; no fallback")
        results = self._probe(root, home, temp, probe, env)
        # Never launch Codex if even one native probe failed, including IPC.
        if not all(result.passed for result in results):
            return self._report(digest, results, "", "", "", "Adversarial probe failed")
        outputs = []
        profile = _profile(home, temp, (self._executable,), pinned_cli=self._executable)
        for name, args in (
            ("cli-version", ["--version"]),
            ("cli-help", ["--help"]),
            ("cli-exec-help", ["exec", "--help"]),
        ):
            _check_workspace()
            code, stdout, _ = _capture(
                [SANDBOX_EXEC, "-p", profile, str(self._executable), *args], env,
            )
            results += (ProbeResult(name, code == 0 and bool(stdout), code),)
            outputs.append(stdout.decode("utf-8", errors="replace"))
            if not results[-1].passed:
                return self._report(
                    digest, results, *[*(outputs), *("" for _ in range(3 - len(outputs)))],
                    "CLI cannot start under the strict offline policy; no relaxation",
                )
        return self._report(
            digest, results, *outputs,
            "Offline checks passed; run() separately requires native proxy-only checks "
            "and strictly validated fixed-text events. M0 remains unchanged.",
        )

    @staticmethod
    def _write_config(home):
        # Only synthetic values. No real config, credentials or history copied.
        # The proxy's fixed model alias is not in the CLI's built-in catalog.
        # Supply local acceptance metadata so startup does not emit an error
        # item for fallback metadata. This never refreshes a remote catalog.
        catalog = {"models": [{
            "slug": MODEL, "display_name": "Fixed acceptance model",
            "description": None, "base_instructions": PROMPT,
            "supported_reasoning_levels": [], "shell_type": "disabled",
            "visibility": "list", "supported_in_api": True, "priority": 0,
            "availability_nux": None, "upgrade": None,
            "support_verbosity": False, "default_verbosity": None,
            "apply_patch_tool_type": None,
            "truncation_policy": {"mode": "tokens", "limit": 10000},
            "experimental_supported_tools": [], "input_modalities": ["text"],
            "include_apps_usage_instructions": False,
            "node_repl_disabled": True, "supports_reasoning_summary_parameter": False,
        }]}
        (home / "models.json").write_text(json.dumps(catalog), encoding="utf-8")
        (home / "config.toml").write_text(
            f'model = "{MODEL}"\nmodel_provider = "osir_acceptance"\n'
            f'model_catalog_json = {_literal(home / "models.json")}\n'
            'approval_policy = "never"\nsandbox_mode = "read-only"\n'
            'web_search = "disabled"\ncli_auth_credentials_store = "file"\n'
            '[model_providers.osir_acceptance]\nname = "Managed local acceptance proxy"\n'
            f'base_url = "{PROXY_URL}"\nenv_key = "OPENAI_API_KEY"\n'
            'wire_api = "responses"\nrequires_openai_auth = false\n'
            'request_max_retries = 0\nstream_max_retries = 0\n', encoding="utf-8",
        )

    def _managed_probe(self, root):
        home, temp, probe = root / "home", root / "tmp", root / "probe"
        profile = _profile(home, temp, (probe,), managed_proxy=True, pinned_cli=self._executable)
        checks = [
            ("proxy-connect-15721", "allow-proxy", "15721"),
            ("proxy-policy-ipv4-alias-deny", "deny-alias", "15721"),
            ("proxy-policy-ipv6-deny", "deny-ipv6", "15721"),
            ("proxy-policy-udp-deny", "deny-udp", "15721"),
            ("proxy-policy-mach-deny", "deny-mach", "com.apple.cfprefsd.daemon"),
            ("proxy-policy-external-read-deny", "deny-read", str(root / "synthetic-external" / "canary")),
            ("proxy-policy-exec-deny", "deny-exec", "/usr/bin/true"),
        ]
        results = []
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp, \
                socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as unix:
            tcp.bind(("127.0.0.1", 0))
            tcp.listen(1)
            unix.bind(str(home / "managed-probe.sock"))
            unix.listen(1)
            checks.extend([
                ("proxy-policy-other-port-deny", "deny-tcp", str(tcp.getsockname()[1])),
                ("proxy-policy-unix-deny", "deny-unix", str(home / "managed-probe.sock")),
            ])
            for name, mode, argument in checks:
                code, stdout, _ = _capture(
                    [SANDBOX_EXEC, "-p", profile, str(probe), mode, argument],
                    _environment(home, temp),
                )
                results.append(ProbeResult(name, code == 0 and not stdout, code))
        return tuple(results)

    @staticmethod
    def _report(digest, probes, version, help_text, exec_help, blocker):
        return AcceptanceReport(
            filesystem_verified=all(p.passed for p in probes if not p.name.startswith("cli-")),
            cli_startup_verified=(
                sum(p.name.startswith("cli-") and p.passed for p in probes) == 3
            ),
            no_tools_verified=False, model_execution_allowed=False,
            workspace=str(WORKSPACE), model=MODEL, prompt=PROMPT,
            executable_sha256=digest, probes=probes, cli_version=version.strip(),
            cli_help=help_text, exec_help=exec_help, blocker=blocker,
        )

    def _probe(self, root, home, temp, probe, env):
        outside = root / "synthetic-external"
        outside.mkdir()
        canary = outside / "canary"
        canary.write_text("OSIR_SYNTHETIC_EXTERNAL_CANARY_ONLY", encoding="utf-8")
        (home / "allowed").write_text("OSIR_ALLOWED", encoding="utf-8")
        (home / "escape").symlink_to(canary)
        (home / "escape-dir").symlink_to(outside, target_is_directory=True)
        policy = _profile(
            home, temp, (probe, Path("/bin/bash"), Path("/bin/cat")), pinned_cli=self._executable,
        )
        checks = [
            ("allowed-read", "allow-read", str(home / "allowed")),
            ("allowed-write", "allow-write", str(temp / "written")),
            ("isolated-home-realpath", "allow-realpath", str(home)),
            ("fixed-cwd-realpath", "allow-realpath", str(WORKSPACE)),
            ("pinned-cli-realpath", "allow-realpath", str(self._executable)),
            *(("public-requirements-read-or-absent-" + str(index),
               "allow-public-read-or-absent", str(path))
              for index, path in enumerate(PUBLIC_SYSTEM_READS)),
            ("external-canary-metadata", "deny-metadata", str(canary)),
            ("external-canary", "deny-read", str(canary)),
            ("symlink-file", "deny-read", str(home / "escape")),
            ("symlink-directory", "deny-read", str(home / "escape-dir" / "canary")),
            ("parent-traversal", "deny-read", str(home / ".." / "synthetic-external" / "canary")),
            ("chdir-escape", "deny-chdir-read", str(outside)),
            ("external-write", "deny-write", str(outside / "written")),
            ("workspace-write", "deny-write", str(WORKSPACE / "must-not-exist")),
            ("other-executable", "deny-exec", "/usr/bin/true"),
            ("hardlink-escape", "deny-link", str(canary), str(home / "hardlink")),
            ("mach-ipc", "deny-mach", "com.apple.cfprefsd.daemon"),
        ]
        results = []
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp, \
                socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as unix, \
                canary.open("rb") as inherited:
            tcp.bind(("127.0.0.1", 0))
            tcp.listen(1)
            unix.bind(str(home / "ipc.sock"))
            unix.listen(1)
            os.set_inheritable(inherited.fileno(), True)
            checks += [
                ("inherited-descriptor", "deny-fd", str(inherited.fileno())),
                ("tcp-egress", "deny-tcp", str(tcp.getsockname()[1])),
                ("unix-ipc", "deny-unix", str(home / "ipc.sock")),
            ]
            for name, mode, *args in checks:
                _check_workspace()
                code, stdout, _ = _capture(
                    [SANDBOX_EXEC, "-p", policy, str(probe), mode, *args], env,
                )
                results.append(ProbeResult(name, code == 0 and not stdout, code))
            for name, path in (("shell-escape", canary), ("shell-symlink", home / "escape")):
                code, stdout, stderr = _capture(
                    [SANDBOX_EXEC, "-p", policy, str(probe), "shell", str(path)], env,
                )
                # Positive shell control below prevents a missing loader/shell
                # from being mistaken for an enforced read denial.
                results.append(ProbeResult(
                    name, code == 1 and not stdout and b"Operation not permitted" in stderr, code,
                ))
            code, stdout, _ = _capture(
                [SANDBOX_EXEC, "-p", policy, str(probe), "shell", str(home / "allowed")], env,
            )
            results.append(ProbeResult("shell-positive-control", code == 0 and stdout == b"OSIR_ALLOWED", code))
        return tuple(results)


def main() -> None:
    try:
        report = OsirAcceptanceRunner().offline_preflight()
    except (OSError, subprocess.SubprocessError, AcceptanceIsolationError) as exc:
        print(json.dumps({"model_execution_allowed": False, "blocker": str(exc)}))
        raise SystemExit(2) from None
    print(json.dumps(asdict(report), ensure_ascii=False, indent=2))
    # Successful filesystem inspection does not turn the M0 gate green.
    raise SystemExit(2)


if __name__ == "__main__":
    main()
