import json, os, struct, subprocess, sys

RUNNER = os.environ.get("RUNNER", "/root/qjs/build/qjs_runner")

class Runner:
    def __init__(self, flag=None, argv=None):
        env = {"LC_ALL": "C", "LANG": "C"}
        if flag is not None:
            env["QJS_CTF_FLAG"] = flag
        self.p = subprocess.Popen(argv or [RUNNER], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  env=env, bufsize=0)
        line = self.p.stderr.readline()
        print("startup:", line.decode(errors="replace").strip(), file=sys.stderr)

    def eval(self, code):
        src = code.encode()
        self.p.stdin.write(struct.pack(">I", len(src)) + src)
        self.p.stdin.flush()
        hdr = self._read_exact(5)
        status = hdr[:1].decode()
        n = struct.unpack(">I", hdr[1:])[0]
        payload = self._read_exact(n)
        return status, payload

    def _read_exact(self, n):
        b = b""
        while len(b) < n:
            c = self.p.stdout.read(n - len(b))
            if not c:
                raise EOFError
            b += c
        return b

if __name__ == "__main__":
    r = Runner(flag=os.environ.get("LOCALFLAG", "TP{{FLAG}}"))
    if len(sys.argv) >= 3 and sys.argv[1] == "--file":
        code = open(sys.argv[2], encoding="utf-8").read()
    elif len(sys.argv) >= 2:
        code = sys.argv[1]
    else:
        code = sys.stdin.read()
    st, payload = r.eval(code)
    print(st, payload.decode(errors="replace"))
