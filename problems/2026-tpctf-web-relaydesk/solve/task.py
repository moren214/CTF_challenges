import json, sys, time, urllib.request, urllib.error

BASE = "http://172.16.212.2:8080"

def task(text, timeout=300):
    body = json.dumps({"text": text}).encode()
    req = urllib.request.Request(BASE + "/api/task", data=body, method="POST",
                                 headers={"Content-Type": "application/json"})
    t0 = time.time()
    try:
        r = urllib.request.urlopen(req, timeout=timeout)
        st, data = r.status, r.read()
    except urllib.error.HTTPError as e:
        st, data = e.code, e.read()
    dt = time.time() - t0
    return st, data, dt

if __name__ == "__main__":
    text = sys.argv[1] if len(sys.argv) > 1 else open(sys.argv[0]).read()
    st, data, dt = task(text)
    print(f"STATUS {st} {dt:.1f}s {len(data)}B")
    try:
        print(json.dumps(json.loads(data), ensure_ascii=False, indent=1))
    except Exception:
        print(data.decode("utf-8", "replace"))
