#!/usr/bin/env python3
"""Minimal JSON-lines client for the QJS worker (172.16.32.2:8000)."""
import argparse, json, socket, sys

HOST = "172.16.32.2"
PORT = 8000


class Client:
    def __init__(self, host=HOST, port=PORT, timeout=8.0):
        self.s = socket.create_connection((host, port), timeout=timeout)
        self.f = self.s.makefile("rb")

    def eval(self, code):
        self.s.sendall((json.dumps({"code": code}) + "\n").encode())
        line = self.f.readline()
        if not line:
            raise RuntimeError("connection closed")
        return json.loads(line)

    def close(self):
        try:
            self.f.close()
            self.s.close()
        except Exception:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("code", nargs="?")
    ap.add_argument("--file")
    ap.add_argument("--host", default=HOST)
    ap.add_argument("--port", type=int, default=PORT)
    a = ap.parse_args()
    code = open(a.file, encoding="utf-8").read() if a.file else a.code
    if code is None:
        code = sys.stdin.read()
    c = Client(a.host, a.port)
    try:
        r = c.eval(code)
        print(json.dumps(r, ensure_ascii=False)[:4000])
    finally:
        c.close()


if __name__ == "__main__":
    main()
