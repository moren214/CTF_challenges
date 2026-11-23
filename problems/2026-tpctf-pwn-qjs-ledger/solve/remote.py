#!/usr/bin/env python3
"""Send one JS source file to the QJS Ledger service and print the reply."""
import json
import socket
import sys
import time


def run(path: str, host: str = "172.16.142.2", port: int = 8000,
        timeout: float = 10.0):
    src = open(path, "r", encoding="utf-8").read()
    req = json.dumps({"code": src}, ensure_ascii=False).encode("utf-8") + b"\n"
    s = socket.create_connection((host, port), timeout=5.0)
    s.settimeout(timeout)
    t0 = time.time()
    s.sendall(req)
    buf = b""
    while b"\n" not in buf:
        chunk = s.recv(65536)
        if not chunk:
            break
        buf += chunk
    s.close()
    line = buf.split(b"\n", 1)[0]
    print(f"[{time.time() - t0:.3f}s] {line.decode('utf-8', 'replace')}")
    return line


if __name__ == "__main__":
    run(sys.argv[1])
