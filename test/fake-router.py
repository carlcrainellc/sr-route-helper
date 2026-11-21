#!/usr/bin/env python3
"""A stand-in for Session Router's RPC, just enough for the helper's tests.

Answers llarp.list_exits and llarp.first_hops over ZMTP 3 (NULL mechanism) from a JSON
state file that the test rewrites: {"mapped": ["0.0.0.0/0"], "first_hops": ["9.9.9.9"]}.
Listens on tcp://HOST:PORT or ipc:///path. With a third argument it also opens a UDP
socket on 127.0.0.1 (random port, like the router's DNS listener on systemd builds) and
writes the port to that file.

    fake-router.py ADDR STATE [DNS_PORT_FILE]
"""
import json, os, socket, struct, sys, threading

addr, state_path = sys.argv[1], sys.argv[2]
if len(sys.argv) > 3:
    dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dns.bind(("127.0.0.1", 0))
    open(sys.argv[3], "w").write(str(dns.getsockname()[1]))


def read_exact(c, n):
    b = b""
    while len(b) < n:
        x = c.recv(n - len(b))
        if not x:
            raise EOFError
        b += x
    return b


def read_frame(c):
    flags = read_exact(c, 1)[0]
    n = struct.unpack(">Q", read_exact(c, 8))[0] if flags & 2 else read_exact(c, 1)[0]
    return flags, read_exact(c, n)


def frame(body, more=False, cmd=False):
    f = (1 if more else 0) | (4 if cmd else 0)
    if len(body) > 255:
        return bytes([f | 2]) + struct.pack(">Q", len(body)) + body
    return bytes([f, len(body)]) + body


def serve(c):
    try:
        g = bytearray(64)
        g[0], g[9], g[10] = 0xFF, 0x7F, 3
        g[12:16] = b"NULL"
        g[32] = 1
        c.sendall(bytes(g))
        read_exact(c, 64)
        read_frame(c)  # peer READY
        st = b"ROUTER"
        c.sendall(frame(b"\x05READY" + b"\x0bSocket-Type" + struct.pack(">I", len(st)) + st, cmd=True))
        while True:
            parts = []
            while True:
                flags, body = read_frame(c)
                if flags & 4:
                    continue
                parts.append(body)
                if not flags & 1:
                    break
            cmd, tag = parts[0].decode(), parts[1]
            try:
                state = json.load(open(state_path))
            except Exception:
                state = {}
            if cmd == "llarp.list_exits":
                res = [{"address": "test.sesh", "ranges": state.get("mapped", [])}] if state.get("mapped") else []
                reply = [b"REPLY", tag, json.dumps({"result": res}).encode()]
            elif cmd == "llarp.first_hops" and not state.get("old_router"):
                reply = [b"REPLY", tag, json.dumps({"result": {"first_hops": state.get("first_hops", [])}}).encode()]
            else:
                reply = [b"UNKNOWNCOMMAND", parts[0]]
            c.sendall(b"".join(frame(p, more=i + 1 < len(reply)) for i, p in enumerate(reply)))
    except (EOFError, ConnectionError, OSError):
        pass
    finally:
        c.close()


if addr.startswith("ipc://"):
    path = addr[len("ipc://"):]
    if os.path.exists(path):
        os.unlink(path)
    s = socket.socket(socket.AF_UNIX)
    s.bind(path)
else:
    host, port = addr.replace("tcp://", "").rsplit(":", 1)
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, int(port)))
s.listen()
while True:
    conn, _ = s.accept()
    threading.Thread(target=serve, args=(conn,), daemon=True).start()
