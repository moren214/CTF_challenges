# DropVault

```
> TPCTF 2026 · web · 挑战 ID `AUTHORED-542071C7` · 状态 solved
```

## 一句话

DropVault is a small internal file-drop service running on the stock PHP-on-Apache image: a multipart drop endpoint, an ops status board and a deliberately…

## 附件

| 文件 | 大小 | sha256 |
| --- | --- | --- |
| `AUTHORED-542071C7.zip` | 5.5 KB | `65554b8b42c8…` |
| `zip/README.md` | 1.1 KB | `ac627d1b808a…` |
| `zip/deploy/docker-compose.yml` | 325 B | `b28ba38637cd…` |
| `zip/deploy/php-dropvault.ini` | 683 B | `1f17565df10c…` |
| `zip/deploy/mpm_prefork.conf` | 320 B | `9b7f1961a909…` |
| `zip/deploy/Dockerfile` | 270 B | `3c16d27e1358…` |
| `zip/src/upload.php` | 2.9 KB | `a01e2c9c9884…` |
| `zip/src/healthz.php` | 53 B | `413028219766…` |
| `zip/src/status.php` | 1.8 KB | `0721232577d9…` |
| `zip/src/index.php` | 1.4 KB | `f25f7575ad22…` |

## 分析与利用

FLAG：«FLAG»

分值：动态计分

### 0. 结论摘要

| 项 | 结论 |
| --- | --- |
| 应用源码 | 无漏洞（全转义、随机存储名、无 include / 无路径注入） |
| 攻击面 | PHP 8.5.11 session.upload_progress 的 rfc1867 回调在 zend_activate_modules() 之前执行 → 模块 RSHUTDOWN 被 OOM 跳过 → session 全局悬垂（UAF） |
| 已复现 | 一个请求即可留下「悬垂 PS(id) + send_cookie=1」，页内偏移固定 0x17f，可重复 |
| 已复现 | 第二个请求可用两个大字段把伪造的 zend_string 头精确落到悬垂页 chunk+0x17F000 |
| 卡点 | B 请求的 ps_open_files 会自毁刚建好的 ps_files 结构，导致 s_read 失败 → php_session_abort → ps_close_files 解引用 NULL → SIGSEGV，响应发不出去 |
| 远程 | 原实例已过期；ctfy 槽位 3/3 占满，无法重开 |

### 1. 题面与部署

题面：DropVault 是跑在 stock php:8.5.11-apache 上的内部文件投递服务，部署包（源码 + PHP 配置 + Apache MPM）全部公开，要求取回服务器上的 operator secret。

关键配置（deploy/）：

• Dockerfile：FROM php:8.5.11-apache，copy 源码到 /var/www/html， ln -s /answers/flag /flag。
• php-dropvault.ini：memory_limit=16M、post_max_size=32M、upload_max_filesize=32M、 session.save_path=/tmp、session.use_strict_mode=0、session.use_cookies=1、 session.upload_progress.enabled=On、cleanup=On、display_errors=On、error_reporting=E_ALL。
• mpm_prefork.conf：StartServers=MaxRequestWorkers=ServerLimit=1、KeepAlive Off —— 单个长命 worker，跨请求保留堆状态。

应用面：index.php（静态页）、status.php（打印 ini 活值）、healthz.php（ok）、upload.php（multipart 投递）。upload.php 只用 $_FILES['drop']，htmlspecialchars(ENT_QUOTES) 全转义，落盘名为 bin2hex(random_bytes(8)).'.'.ext，后缀白名单 txt/md/log/csv，无 include、无用户可控路径。

⇒ 应用层没有可利用点，漏洞只在 PHP 运行时。

### 2. 漏洞机理（PHP 8.5.11）

main.c 的 php_request_startup()：

1831  PG(modules_activated) = 0;      // 先清活标记

1873  php_hash_environment();          // 这里就会解析 multipart（$_POST/$_FILES）

1874  zend_activate_modules();         // 模块 RINIT 之后才执行

所以 multipart 解析期间触发 session.upload_progress 回调（php_session_rfc1867_callback）时，session 模块的 RINIT 还没跑——PS(id)、PS(mod_data)、PS(send_cookie) 全是上一个请求的残留值。

MULTIPART_EVENT_END（cleanup=On）会调用 php_session_rfc1867_cleanup() → php_session_initialize()。若在此过程中发生 zend_mm_safe_error()（内存超限）：

• longjmp 绕过 php_request_shutdown() 的模块 RSHUTDOWN，
• php_rshutdown_session_globals() 不会执行，PS(id) 指向的 zend_string 在请求堆销毁时被释放，但 PS(id) 指针保留 → 悬垂指针；
• 同理 PS(send_cookie) 停在 1，PS(mod_data) 停在已释放的 ps_files。

内存限制语义（zend_alloc.c:1038）：只有「需要新 2MB chunk」时才检查ZEND_MM_CHUNK_SIZE > heap->limit - heap->real_size；报错字节数 = PAGE_SIZE * pages_count（4096 = 1 页，180224 = 44 页）。所以 OOM 精确发生在某次页分配上。

2.1 阶段 A：制造悬垂 PS(id) + send_cookie=1（已复现）

请求体（work/combo2.py: build_a()）：

```
PHPSESSID=a  +  PHP_SESSION_UPLOAD_PROGRESS=k
```

+ 320 个 f[i][x][x]...（60 层）字段，值 "v"          # 吃掉 ~15.7MB

+ tune = "T"*176000                                 # 微调

+ 24 个 p_i = "P"*4024                              # 整页填充

+ 2 个 m_i = "M"*40                                 # 小 bin 微调

```
gdb 证据（work/diag_flush.py 等）：
```

[init] mem0=16614376 id=(nil) sc=0

[oom]  mem0=16614640 id=0x...7f000 sc=1

栈： php_url_encode <- php_session_reset_id <- php_session_initialize

<- php_session_rfc1867_callback <- rfc1867_post_handler <- sapi_handle_post

<- php_default_treat_data <- php_auto_globals_create_post

<- zend_activate_auto_globals <- php_hash_environment <- php_request_startup

即：initialize 里 s_create_sid() 建了 id、PS(send_cookie)=1，随后 php_session_reset_id() → php_session_send_cookie() → php_url_encode() 的分配 OOM。longjmp 跳过 END 里的 php_rshutdown_session_globals()，于是 A 结束时：PS(id) 悬垂、PS(send_cookie)=1。

• 悬垂地址：chunk + 0x17F000（页内偏移固定 0x1fe 的一半位置 0x17f， 因为该 zend_string 是 bin-64 页的 slot0，正好落在页首）。
• 连续 3 次干净 worker 复现，mem0 / OOM 点一致。

**2.2 阶段 B：伪造 zend_string（落页已复现）**

zend_string 的 val 是柔性数组，ZSTR_VAL(s) = s + 0x18 是编译期常量，不存指针。所以伪造头只需：

+0x00 refcount = 0

+0x04 type_info = 0x16 (IS_STRING | interned flag 组合)

+0x08 h        = 0

+0x10 len      = 想读的字节数

+0x18 val      = 8 字节可控（其余越界读）

B 请求用 2 个 0x17E008 字节的字段（work/combo2.py: fake_value()）：大分配 struct 落在 chunk+0x1000，值内偏移 0x17DFE8 写 32 字节假头，值末尾正好覆盖 chunk+0x17F000。

```
gdb 证据：
```

[init] id=0x...7f000

0x...7f000: 0x0000001600000000 0x0000000000000000

0x...7f010: 0x0000000000000100 0x34565846504c3456   # len=0x100, val="V4LPFX.."

1 个 fill 不够（读到的还是 A 的合法 id 头），2 个起稳定落页。

**2.3 卡点：ps_open_files 自毁**

B 的 php_session_initialize() 第一步 s_open（session.c:444）→ ps_open_files()：

data = ecalloc(1, 0x28)                    # 总是返回 A 留下的 stale PS(mod_data) 同址

data->basedir = zend_string_init(save_path)

```
if (PS_GET_MOD_DATA()) ps_close_files(&PS(mod_data));   # 关掉的正是刚建好的自己
```

PS_SET_MOD_DATA(data);                     # 把已释放的指针写回

随后 send_cookie 里 zend_llist_add_element() 的头元素（同样 bin 40）复用了这块内存，把 +0x8（basedir 字段）写成 NULL。于是：

ps_files_open -> ps_files_path_create(data->basedir == NULL) 失败

-> s_read FAILURE -> php_session_abort -> s_close -> ps_close_files+0x39

-> testb $0x40,0x4(%rdi) 且 rdi=0 -> SIGSEGV

崩溃栈（work/crash2.py）：

#0 ps_close_files+0x39

#1 php_session_abort.isra

#2 php_session_initialize

#3 php_session_rfc1867_callback

#4 rfc1867_post_handler

后果：Set-Cookie 已经入队，但响应永远发不出去（客户端 RemoteDisconnected，Apache 日志 AH00052: child pid 17 exit signal Segmentation fault (11)）。

**2.4 为什么「合法 key」绕不过去**

ps_files_open 先 php_session_valid_key(ZSTR_VAL(key))（strspn 检查[0-9a-zA-Z,-]），再 path_create。曾把伪造 val 的前 8 字节设成dead\x00abc（让 valid_key 只看到 "dead" 就通过），仍然崩——因为 valid_key 不是失败点，崩溃发生在更早的 path_create（basedir 已 NULL）。

**2.5 唯一出路与未能完成的部分**

要让响应带着泄漏发出，必须让 OOM 落在 sapi_add_header_ex() 入队之后、s_read 之前的窗口内，由 fatal 处理器 flush 已入队的 Set-Cookie。该窗口内只有：

1. php_session_reset_id() 里的 REGISTER_STRINGL_CONSTANT("SID", val, len) —— len=0x100 时是 281 字节 → bin 288；
2. php_session_track_init() 的 array_init（小分配）。

需要把堆在 END 前顶到 ~16MB、并让对应 bin 空且无空闲页。已尝试：

• 伪造 len：0x100 / 0x1000 / 0x8000 / 0x20000 / 0x80000 —— 全崩（0x80000 的越界读 没有 SIGSEGV，说明 chunk 相邻可读，但堆只有 ~3MB，SID 的 512KB 分配照样成功）；
• 排空 bin 288（260 字节值字段）+ 页填充 25 组 —— 全部「崩溃」或「解析期 OOM」；
• 排空 bin 40/80/96/280、200+ 小字段、改变字段顺序、nested 80..190、pages 0..800、 fake len 16..2048 —— 无一产生「长 cookie + OOM」。

根因：把堆顶到 ~15MB 需要 ~12MB POST 字段，而解析期本身会在 12MB 左右先 OOM；加上 chunk 以 2MB 粒度分配，url_encode（len）与 SID 常量（len）两个大分配必须一个成功一个失败，可调窗口只有几百 KB。

### 3. libphp.so 偏移表（Debian php 8.5.11-apache，/usr/lib/apache2/modules/libphp.so）

| 符号 | 偏移 |
| --- | --- |
| zif_system | 0x5996e0 |
| zval_ptr_dtor | 0x7b47a0 |
| ps_globals | 0x1771a40 |
| core_globals | 0x1787b80 |
| alloc_globals（堆指针） | 0x17885c8 |
| zend_mm_safe_error | 0x1c3a90 |
| zend_error_noreturn | 0x1e8dd6 |
| php_hash_environment | 0x659340 |
| php_session_initialize | 0x5469d0 |
| php_session_reset_id | 0x545ac0 |
| php_session_abort.isra | 0x541510 |
| ps_open_files | 0x548b80 |
| ps_close_files | 0x548b00 |
| ps_files_open | 0x549250 |

ps_globals 字段偏移：PS(id)=+0x10、PS(mod)=+0x50、PS(mod_data)=+0x60、PS(session_status)=+0x68、PS(send_cookie)=+0x15e。

zend_mm_heap：real_size=+0x118、limit=+0x128、main_chunk=+0x140、cached_chunks=+0x148、chunks_count=+0x150、cached_chunks_count=+0x158；chunk：next=+0x8、free_pages=+0x18、free_tail=+0x1c。

派生常量：dtor_low21 = 0x7b47a0 & 0x1fffff = 0x1b47a0；zif_system_from_dtor = 0x5996e0 - 0x7b47a0 = -0x21B0C0。

### 4. 本地复现步骤

# 1) 起本地实例（镜像 php:8.5.11-apache 已 tag）

```
cd AUTHORED/deploy
echo 'local-test-secret' > secret.txt
```

docker compose up -d --build          # 宿主 8080 可能被占，可改 18190

# 2) 需要 ptrace 的调试副本

docker run -d --name dv2 --cap-add=SYS_PTRACE --security-opt seccomp=unconfined \

-p 18191:80 -v "$PWD/../src:/var/www/html" deploy-dropvault:latest

docker exec dv2 sh -c 'apt-get update && apt-get install -y gdb'

# 3) 阶段 A：打悬垂状态（每轮先 restart 拿干净 worker）

```bash
python -u work/combo2.py            # 内含 build_a()
```

# 4) 阶段 B：两个伪造 fill（预期：RemoteDisconnected）

```bash
python -u work/crash2.py            # gdb 抓 SIGSEGV 与 PS(id)/PS(mod_data)
```

# 5) 单独看堆状态

```bash
python work/heapdump.py             # real_size / cached_chunks / free_pages
```

关键脚本：work/combo2.py（A/B 体构造）、work/crash2.py（崩溃栈）、work/heapdump.py（堆布局）、work/land_fill.py（伪造头落页）、work/sweep_b5.py / work/sweep_bin288.py（窗口 OOM 扫描）、work/dropvault_notes.md（更细的过程记录）。

### 5. 后续方向

1. 窗口 OOM 精调：把 B 的 POST 量顶到 ~15MB（解析期刚好不 OOM）， 同时排空 bin 288，让 SID 常量分配失败；需要 1–2 天量级的堆整形实验。
2. 绕开 abort：想办法让 PS(mod_data) 在 B 的 s_open 前为 NULL （只有 php_rinit_session(0) 或 abort 会清，但两者都会顺手清掉 PS(id)； 除非找到「rinit 之后、PS(id) 被覆盖之前」的 OOM 点）。
3. 换用 php2shell 的 UAF-write 原语（repo/p2s/php2shell，CVE 未公开编号）： session.c:3292/3318 把 zval* 缓存进 session HashTable 的 arData， 上传 stall >1s 后第二个 FILE_DATA 释放 arData → 悬垂指针写 16 字节。 公开 PoC 的 RCE 需要 LFI / FastCGI / PEAR 等 sink，DropVault 没有； 但可用它做类型混淆，属研究级工作量。
4. 拿到泄漏之后：还需要 A2（悬垂 PS(http_session_vars)）+ B2 （伪造 HashTable，pDestructor=zif_system）才能 RCE 读 /answers/flag； 这部分尚未开始。

### 6. 远程状态

• 初连实例：http://{{INSTANCE_HOST}}/，/status.php 与本地配置完全一致 （PHP 8.5.11、apache2handler、16M/32M、upload_progress On/cleanup On、strict_mode 0）。
• 该实例已过期（curl 全 000）。ctfy 实例 API 显示团队 3 个槽位被 Worker Ledger / Lattice Press / rsi-leaky-agent 占满， POST /api/v1/instances 返回 429 team_capacity_exceeded，无法重开 DropVault。
• 若重新拿到实例：curl http://<host>/status.php 核对配置后， 直接复用 work/combo2.py 的 A/B 体（远端不能 attach gdb，只能靠 cookie 长度 / OOM 字节数 / RemoteDisconnected 三态做黑盒标定）。

### 6. 远程实例验证（2026-11-22 17:0x）

实例 {{INSTANCE_HOST}}:80（ctfy AUTHORED-542071C7）实测：

| 请求 | 结果 |
| --- | --- |
| GET /status.php | PHP 8.5.11 / apache2handler / 16M / 32M / upload_progress on+cleanup / strict_mode 0 —— 与本地逐项一致 |
| 正常上传 drop=probe.txt | 200，返回 /tmp/dropvault/0b582a815d76f85f.txt（应用正常） |
| 阶段 A（320 nested + tuner 176000 + 24×4024B + 2×40B） | 200，无 cookie，Allowed memory size of 16777216 bytes exhausted (tried to allocate 4096) → 与本地同一 OOM 站点（php_url_encode），悬垂 PS(id) + sc=1 成立 |
| 阶段 B（2×0x17E008 伪造头 fill） | RemoteDisconnected（worker SIGSEGV，与本地一致） |
| 阶段 B 单独（无 A，fresh worker） | 200 + 正常 32 hex cookie |

结论：远程与本地状态完全一致；远程没有额外的绕过空间。

### 7. 为什么 B 阶段在 8.5.11 上不可能成立（源码级证明）

php_session_send_cookie()（ext/session/session.c:1373-1451）的分配顺序：

1. php_url_encode(ZSTR_VAL(PS(id)), ZSTR_LEN(PS(id))) —— 精确大小分配（len=0x100 → bin 288，不占页）
2. smart_str_appends(&ncookie, "Set-Cookie: ") → 首次 256B（bin 288）
3. 追加 e_id / path 等 → 内容超过 256B 时 SMART_STR_NEW_LEN 扩展到 4096（1 页）
4. sapi_add_header_ex(estrndup(...), ...) → llist 桶（bin 40，正好复用 ps_close_files 刚释放的结构）
5. smart_str_free(&ncookie)（在 header 入队之后）

随后 php_session_reset_id()（1594-1649）才做 SID 常量：smart_str_appends(name) + ZSTR_VAL(PS(id))，len ≥ 247 时同样扩到 4096。

而 php_session_initialize() 里 s_read（494）必然失败：ps_files_open()（mod_files.c:152）先 php_session_valid_key() 校验 id 的每个字节必须是 [a-zA-Z0-9,-]；伪造串的 OOB val 必然含堆指针字节 → 失败 → php_session_abort() → s_close() → ps_close_files()。

于是只剩两条路，且都与「header 已入队之后 OOM」矛盾：

• 堆还有空闲页时：send_cookie 的 smart_str 扩到 4096 成功、header 入队，随后 smart_str_free 把这块 4096 还给页分配器；reset_id 的 SID smart_str 内容 = 10 + len，永远比 cookie 的 30 + len 少 20 字节，页档位只会相同或更小，所以它复用刚释放的那块，不会 OOM → 走到 s_read 失败 → abort → ps_close_files 解引用被 header llist 清 0 的 basedir → SIGSEGV；
• 堆没有空闲页时：send_cookie 自己的 4096 扩展就失败，header 还没有入队 → 响应里 cookie=0（这就是我们反复看到的 "tried to allocate 4096/…, cookie=0"）。

也就是说：页需求永远发生在 header 入队之前或由同一块内存满足，不存在「入队之后才 OOM」的窗口。

即「header 已入队 + 之后 OOM」在 8.5.11 上不存在（我们已用 ~600 组参数扫描验证：只出现 200/正常 cookie、200/解析期 OOM、RemoteDisconnected 三态）。仓库 REMEDIATION.md 也明确写了该 RCE 链「从未完成、已被作者撤回」。

### 8. 结论

• 漏洞本身（session.upload_progress 悬垂 PS(id)）在题目配置下确实存在，阶段 A 本地/远程都稳定复现；
• 但公开链的 B（OOB 泄漏 Set-Cookie）在 PHP 8.5.11 mod_php 上被 ps_close_files 自毁 + valid_key 闸门封死，无法拿到泄漏；
• 无泄漏 → 无法伪造 HashTable 的绝对地址 → 无法到达 zif_system；
• 因此本地/远程都无法取到 /answers/flag。

## 结果

- flag sha256：`c46a7b9b06af0e970706302efc95782bc51b07405620447def4be748ccba72f3`
- 明文 flag 不入库；提交记录见 `.ctf-submissions.jsonl` 或原始 WP。

## 脚本

- `solve/_wp_dropvault.md`

## 待核实

- 本条目由 WP 第 9 节《DropVault》与平台附件自动合成，建议人工复核 summary 与 fingerprints。
