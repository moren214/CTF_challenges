import json
import socket
import sys

HOST = "172.16.177.2"
PORT = 1337

code = open("exploit2.js", "r", encoding="utf-8").read()
s = socket.create_connection((HOST, PORT), timeout=5)
s.settimeout(6)
s.sendall((json.dumps({"code": code}) + "\n").encode())
f = s.makefile("rb")
line = f.readline()
print(line.decode("utf-8", "replace"))
s.close()
