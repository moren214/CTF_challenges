import json
import os
import socket

HOST = os.environ.get("QJS_HOST", "172.16.53.2")
PORT = int(os.environ.get("QJS_PORT", "1337"))
BASE = os.path.dirname(os.path.abspath(__file__))
code = open(os.path.join(BASE, "exploit.js"), encoding="utf-8").read()

s = socket.create_connection((HOST, PORT), timeout=5)
s.settimeout(8)
s.sendall((json.dumps({"code": code}) + "\n").encode())
line = s.makefile("rb").readline()
print(line.decode("utf-8", "replace"))
s.close()
