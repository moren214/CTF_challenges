#!/usr/bin/env python3
"""MemTrace 请求规范化网关（零依赖，仅标准库）。

观测台前置网关：对外接收任意 HTTP 客户端的请求，对内以**固定的规范化
形状**（HTTP/1.1，按 Host、Content-Type、Content-Length、Connection 的
固定顺序，固定取值）转发给 Apache + mod_php 上游，保证观测台对请求
解析行为可复现。网关同时执行蓝队请求过滤（固定串黑名单）。
"""

import http.client
import http.server
import socketserver

UPSTREAM_HOST = "apache"
UPSTREAM_PORT = 80
BOUNDARY_BLACKLIST = (
    "boundary=SSSSSSSSSSSSSSSSS",
    "boundary=BBBBBBBBBB",
    "boundary=BNDRY12345",
)
NINEBIE_COOKIE = "PHPSESSID=" + "a" * 32


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = 180

    def log_message(self, fmt, *args):  # 安静模式
        pass

    # ---- 蓝队请求过滤 --------------------------------------------------
    def _filtered(self) -> bool:
        ct = self.headers.get("Content-Type") or ""
        for marker in BOUNDARY_BLACKLIST:
            if marker in ct:
                return True
        cookie = self.headers.get("Cookie") or ""
        if cookie.strip() == NINEBIE_COOKIE:
            return True
        ua = self.headers.get("User-Agent") or ""
        if ua.startswith("php2shell"):
            return True
        return False

    def _read_chunked(self) -> bytes:
        out = bytearray()
        while True:
            line = self.rfile.readline(1024).strip()
            if b";" in line:
                line = line.split(b";", 1)[0]
            try:
                size = int(line, 16)
            except ValueError:
                break
            if size == 0:
                self.rfile.readline(1024)  # trailer
                break
            out += self.rfile.read(size)
            self.rfile.readline(1024)      # CRLF
            if len(out) > (1 << 30):
                break
        return bytes(out)

    def _reply(self, status: int, body: bytes, content_type: str):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
        self.close_connection = True

    # ---- 通用转发 ------------------------------------------------------
    def _relay(self):
        if self._filtered():
            self._reply(403, b"blocked by memtrace gateway filter\n",
                        "text/plain")
            return

        length = int(self.headers.get("Content-Length") or 0)
        if length > 0:
            body = self.rfile.read(length)
        elif (self.headers.get("Transfer-Encoding") or "").lower() == "chunked":
            body = self._read_chunked()
        else:
            body = None

        conn = http.client.HTTPConnection(UPSTREAM_HOST, UPSTREAM_PORT,
                                          timeout=150)
        try:
            conn.putrequest(self.command, self.path, skip_host=True,
                            skip_accept_encoding=True)
            # 规范化头部：固定顺序、固定集合，其余客户端头部一律不透传
            conn.putheader("Host", f"{UPSTREAM_HOST}:{UPSTREAM_PORT}")
            ct = self.headers.get("Content-Type")
            if ct:
                conn.putheader("Content-Type", ct)
            if body is not None:
                conn.putheader("Content-Length", str(len(body)))
            conn.putheader("Connection", "close")
            conn.endheaders(message_body=body)
            resp = conn.getresponse()
            data = resp.read()
            self.send_response(resp.status, resp.reason)
            skip = {"transfer-encoding", "content-length", "connection",
                    "keep-alive"}
            for k, v in resp.msg.items():
                if k.lower() in skip:
                    continue
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)
        except Exception:
            try:
                self._reply(502, b"memtrace gateway: upstream aborted\n",
                            "text/plain")
            except Exception:
                pass
        finally:
            conn.close()
        self.close_connection = True

    def do_GET(self):
        self._relay()

    def do_POST(self):
        self._relay()

    def do_HEAD(self):
        self._relay()

    def do_PUT(self):
        self._relay()

    def do_DELETE(self):
        self._relay()


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


if __name__ == "__main__":
    srv = Server(("0.0.0.0", 80), Handler)
    srv.serve_forever()
