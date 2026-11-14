"""Inspect an inherited connected socket (fd 3); never read/write its payload.

Main owns connect(), so the Client sees Main's kernel PID, not this helper's PID.
Keep fd 3 until stdin closes; one optional `inspect` line requests a fresh check.
Launch only with a trusted bundled Python: python -I -S -B <this-file>.
stdout contains at most two bounded identity objects or a fixed error; stderr is empty.
No CLI/path/PID input is accepted. All identity data comes from socket/libproc.
"""
import ctypes
import json
import os
import socket
import struct
import sys


class BsdInfo(ctypes.Structure):
    _fields_ = [
        *[(name, ctypes.c_uint32) for name in (
            "flags", "status", "xstatus", "pid", "ppid", "uid", "gid", "ruid",
            "rgid", "svuid", "svgid", "reserved")],
        ("comm", ctypes.c_char * 16), ("name", ctypes.c_char * 32),
        *[(name, ctypes.c_uint32) for name in (
            "nfiles", "pgid", "pjobc", "tdev", "tpgid")],
        ("nice", ctypes.c_int32), ("start_sec", ctypes.c_uint64),
        ("start_usec", ctypes.c_uint64),
    ]


def inspect_peer():
    if sys.platform != "darwin" or len(sys.argv) != 1:
        raise ValueError("unsupported")
    libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    libc.getpeereid.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_uint32),
                               ctypes.POINTER(ctypes.c_uint32)]
    libc.getpeereid.restype = ctypes.c_int
    libproc.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64,
                                    ctypes.c_void_p, ctypes.c_int]
    libproc.proc_pidinfo.restype = ctypes.c_int
    libproc.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    libproc.proc_pidpath.restype = ctypes.c_int
    peer_socket = socket.socket(fileno=os.dup(3))
    try:
        if peer_socket.family != socket.AF_UNIX or peer_socket.type != socket.SOCK_STREAM:
            raise ValueError("socket")
        uid, gid = ctypes.c_uint32(), ctypes.c_uint32()
        if libc.getpeereid(peer_socket.fileno(), ctypes.byref(uid), ctypes.byref(gid)) != 0:
            raise ValueError("uid")
        # Darwin sys/un.h: SOL_LOCAL=0, LOCAL_PEERPID=2. Never lsof/argv PID.
        pid = struct.unpack("=i", peer_socket.getsockopt(0, 2, 4))[0]
        if uid.value != os.geteuid() or pid <= 0:
            raise ValueError("peer")

        def info_for(process_pid):
            info = BsdInfo()
            if libproc.proc_pidinfo(process_pid, 3, 0, ctypes.byref(info), ctypes.sizeof(info)) != ctypes.sizeof(info):
                raise ValueError("process")
            if info.pid != process_pid or info.uid != uid.value or info.ppid <= 0:
                raise ValueError("process")
            return info

        def path_for(process_pid):
            value = ctypes.create_string_buffer(4096)
            if libproc.proc_pidpath(process_pid, value, len(value)) <= 0:
                raise ValueError("path")
            path = value.value.decode("utf-8", "strict")
            if not os.path.isabs(path):
                raise ValueError("path")
            return path

        info = info_for(pid)
        identity = {"uid": uid.value, "pid": pid, "executablePath": path_for(pid),
                    "parentPid": info.ppid, "parentExecutablePath": path_for(info.ppid),
                    "startedAt": [info.start_sec, info.start_usec]}
        again = info_for(pid)
        if (info.ppid, info.start_sec, info.start_usec) != (again.ppid, again.start_sec, again.start_usec):
            raise ValueError("changed")
        return identity
    finally:
        peer_socket.close()


def emit_identity():
    try:
        output = json.dumps(inspect_peer(), separators=(",", ":"))
        if len(output.encode("utf-8")) > 12288:
            raise ValueError("size")
    except Exception:
        sys.stdout.write('{"error":"peer_untrusted"}\n')
        sys.exit(1)
    sys.stdout.write(output + "\n")
    sys.stdout.flush()


if __name__ == "__main__":
    emit_identity()
    command = sys.stdin.buffer.readline(9)
    if command:
        if command != b"inspect\n":
            sys.stdout.write('{"error":"peer_untrusted"}\n')
            sys.exit(1)
        emit_identity()
