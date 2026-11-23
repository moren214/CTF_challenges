import http.client
import os
import re
import secrets
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

UPSTREAM_HOST = os.environ.get("UPSTREAM_HOST", "app")
UPSTREAM_PORT = int(os.environ.get("UPSTREAM_PORT", "80"))
MAX_BODY = 16 * 1024 * 1024
MAX_PARTS = 1200
PANEL = os.environ.get("PANEL_TOKEN", "pixelboard")
HANDSHAKE = secrets.token_hex(16)
BANNED_BOUNDARIES = {b"BBBBBBBBBB", b"BNDRY12345", b"S" * 17}
BOUNDARY_RE = re.compile(r'boundary="?([^";,]+)"?', re.I)


def _gate_secret():
    import time
    for _ in range(60):
        try:
            with open("/run/gate-secret/value", "r") as fh:
                value = fh.read().strip()
            if value:
                return value
        except OSError:
            pass
        time.sleep(1)
    return ""


GATE_SECRET = _gate_secret()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "gate"

    def log_message(self, *args):
        pass

    def _deny(self, code, reason):
        body = (reason + "\n").encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:
            pass

    def _read_body(self):
        if self.headers.get("Transfer-Encoding"):
            self._deny(411, "declared length required")
            return None
        raw_len = self.headers.get("Content-Length")
        if raw_len is None:
            self._deny(411, "declared length required")
            return None
        try:
            length = int(raw_len)
        except ValueError:
            self._deny(411, "declared length required")
            return None
        if length < 0 or length > MAX_BODY:
            self._deny(413, "body too large")
            return None
        if length == 0:
            return b""
        data = b""
        while len(data) < length:
            chunk = self.rfile.read(min(1 << 20, length - len(data)))
            if not chunk:
                return None
            data += chunk
        return data

    def _check_multipart(self, body):
        ctype = self.headers.get("Content-Type", "")
        if not ctype.lower().startswith("multipart/form-data"):
            return True
        m = BOUNDARY_RE.search(ctype)
        if not m:
            self._deny(400, "multipart boundary missing")
            return False
        boundary = m.group(1).strip().encode("latin-1", "replace")
        if boundary in BANNED_BOUNDARIES:
            self._deny(403, "request shape refused")
            return False
        if body.count(b"--" + boundary) > MAX_PARTS:
            self._deny(413, "too many parts")
            return False
        return True

    def _forward(self, body):
        conn = http.client.HTTPConnection(UPSTREAM_HOST, UPSTREAM_PORT, timeout=120)
        headers = {}
        for k, v in self.headers.items():
            if k.lower() in ("host", "connection", "transfer-encoding"):
                continue
            headers[k] = v
        headers["X-Forwarded-For"] = self.client_address[0]
        if GATE_SECRET:
            headers["X-Gate"] = GATE_SECRET
        try:
            conn.request(self.command, self.path, body=body if body else None, headers=headers)
            resp = conn.getresponse()
        except OSError:
            self._deny(502, "upstream unavailable")
            return
        data = resp.read()
        self.send_response(resp.status, resp.reason)
        for k, v in resp.getheaders():
            if k.lower() in ("connection", "transfer-encoding", "content-length", "x-powered-by"):
                continue
            self.send_header(k, v)
        self.send_header("X-Powered-By", "PHP/8.4.26")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(data)
        except OSError:
            pass
        conn.close()

    def _handle(self):
        if self.path.split("?")[0] == "/handshake":
            payload = (HANDSHAKE + "\n").encode()
            self.send_response(200)
            self.send_header("X-Handshake", HANDSHAKE)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "close")
            self.end_headers()
            try:
                self.wfile.write(payload)
            except OSError:
                pass
            return
        if self.command in ("POST", "PUT", "PATCH", "DELETE"):
            if self.headers.get("X-Panel", "") != PANEL:
                self._deny(403, "request contract not met")
                return
            if self.headers.get("X-Handshake", "") != HANDSHAKE:
                self._deny(409, "handshake required")
                return
        body = b""
        if self.command in ("POST", "PUT", "PATCH"):
            body = self._read_body()
            if body is None:
                return
            if not self._check_multipart(body):
                return
        self._forward(body)

    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle
    do_PATCH = _handle
    do_DELETE = _handle
    do_HEAD = _handle
    do_OPTIONS = _handle


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
