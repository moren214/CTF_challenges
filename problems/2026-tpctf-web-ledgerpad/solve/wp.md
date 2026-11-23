# LedgerPad — Writeup

> 题目：AUTHORED-E69EE20C（web / hard，23 solves）
> 目标：取出部署的 pinned secret（`/flag`，仅 worker 账号可读）
> 结果：`{{FLAG}}`

---

## 1. 题目给了什么

附件只有配置和一行源码：

```
README.md
config/php.ini      -> zz-harden.ini
config/prefork.conf
config/zz-body.conf
config/zz-w.conf
app/index.php       -> <?php echo "OK\n";
```

`README.md` 的关键信息：

- 镜像 `php:8.5.11-apache`（PHP 8.5.11 / Apache 2.4.69 / Debian trixie）；
- docroot `/var/www/html`，`www-data` 可写，`/x` 是指向它的短符号链接；
- **单 prefork worker、KeepAlive Off、`MaxConnectionsPerChild 0`**，worker 跨请求常驻；
- `memory_limit=16M`、`post_max_size=8M`、`upload_max_filesize=8M`、Apache `LimitRequestBody 8 MiB`；
- session upload progress 开启，但应用**从不** `session_start()`；
- `/flag` 只有 worker 账号可读；
- 作者明说题围绕 **CVE-2026-109618 / CVE-2026-109619（"PHP2Shell"）**，公开 PoC
  <https://github.com/alvarodh5/php2shell> **不能原样用**，因为 body 上限堵死了 PoC 的 OOM 策略。

应用本身没有任何读文件/包含/上传处理的 sink，所以这是一道纯 PHP 内存破坏题：
要在 8 MiB 的请求体预算内，把 worker 拖进可利用的堆状态。

## 2. 公开 PoC 与本部署的差异

| 项 | 公开 PoC（docker/php.ini） | LedgerPad |
| --- | --- | --- |
| `memory_limit` | 8M | **16M** |
| `post_max_size` | 64M | **8M** |
| `upload_max_filesize` | 64M | **8M** |
| Apache body 上限 | 无 | **8 MiB** |
| OOM 大字段 | 12 MiB | **必须 ≤ 8 MiB（用 6 MiB）** |

PoC 的设计是"用 12 MiB 字段把 8M 上限顶爆"，而这里 body 根本进不来 12 MiB。
但 OOM 只是手段，真正的状态是 **session 初始化途中 bailout 留下的悬空指针**；
只要能让 `php_session_initialize()` 在"已新建 id、还没写回 PS(id)"之间 OOM，
6 MiB 同样够用——`memory_limit=16M`，而 multipart 解析阶段本身就要吃掉几 MiB。

## 3. 漏洞原理（PHP2Shell 三阶段）

### 3.1 stage 1：泄漏 zend_mm chunk 基址

请求 A：

- 1001 个单字节字段 `p0000..p1000` —— 超过 `max_input_vars=1000`，PHP 抛
  `Input variables exceeded 1000` 警告；`display_errors=On` 让警告立刻写进响应 →
  **headers 已发送**（`headers_sent=1`）；
- `PHPSESSID=\x00` —— `php_session_initialize()` 认为要新建 session id
  （`use_strict_mode=0`），`send_cookie=1`；
- `PHP_SESSION_UPLOAD_PROGRESS` + 一个 file part —— 让 `php_session_rfc1867_callback`
  走 `php_session_initialize()`，其中 `php_session_reset_id()` 要发 `Set-Cookie`；
- 末尾 6 MiB 字段 —— OOM bailout 打断在 `reset_id` 发 cookie 之前，
  于是 `PS(id)` 是一个 32 字节 `zend_string`（64 字节 bin），但已不在 session 的引用里，
  **悬空**。

请求 B（不带 file part）：

- `php_session_rfc1867_cleanup()` → `php_session_initialize()` → `reset_id()`；
- `reset_id` 用悬空 `PS(id)` 拼 `Set-Cookie`，`url_encode()` 按 `ZSTR_LEN()` 越界读，
  把堆上的 0x1000 字节塞进响应头 → 解出 `zend_mm` chunk 基址。

stage 2 同法，用 56 字节的 HashTable 页覆盖悬空 `zend_string`，让 `ZSTR_LEN` 变成大数，
越界读带出 `libphp.so` 里的指针 → 得到 libphp 基址。

### 3.2 stage 3：劫持 `pDestructor`

请求 A（第二次 OOM）：

- 6 个 31 字节 pad + upload file part + 6 MiB 字段，并带 `Cookie: PHPSESSID=aaaa…`
  让 `send_cookie=0`；
- OOM 后 `PS(http_session_vars)` 变成指向堆上 `zend_reference` 的悬空指针
  （实测 `rc=2`、`type=0x30a`、`val.type_info=0x307`）。

请求 B：

- `PHPSESSID` 先发；
- **899 个 39 字节值**，每个在偏移 8 处写入 24 字节 fake reference：
  `struct.pack('<IIQQ', 1, 0x1A, htdata, 0x307)`
  → `gc.rc=1`、`gc.type=IS_REFERENCE`、`val.value=fake HashTable`、`val.type=0x307`；
- **15 份 167 字节 fake HashTable**，`pDestructor = libphp + zif_system`，
  内含 fake `execute_data`、fake `zend_string` 和命令串；
- 最后才发 `PHP_SESSION_UPLOAD_PROGRESS` —— 保证所有 carrier 在 session init 之前解析完。

B 结束时 multipart END 触发 `php_session_rfc1867_cleanup → php_session_initialize`：

```
zval_ptr_dtor(PS(http_session_vars))      # rc 2 -> 1 -> 0
  └─ zend_reference_destroy(R0)
       └─ zval_ptr_dtor(&ref->val)        # IS_ARRAY_EX
            └─ zend_array_destroy(fake HT)
                 └─ zend_hash_destroy(fake HT)
                      └─ pDestructor(&bucket->val)   # = zif_system
                           └─ system("cat</flag")     # 输出直接进响应体
```

命令串在 167 字节 carrier 里，上限 14 字节；`cat</flag`（9 字节）把 flag 直接写进 B 的响应。

## 4. 重标定：为什么不能照抄常数

公开 PoC 的 profile 是 8.4 + 12 MiB 场景，本部署全部要重测：

| 常数 | 公开 PoC (8.4) | 本部署 (8.5.11-apache, Debian trixie) |
| --- | --- | --- |
| `zif_system` | libphp+0x43a870 | **libphp+0x5996e0** |
| `zval_ptr_dtor` | libphp+0x65eb60 | **libphp+0x7b47a0** |
| fake HT 落点 `htdata` | chunk+0x6e0d8 | **chunk+0xB3018** |
| `PS(http_session_vars)` | — | libphp+0x1771a40（value 在 +0x168，type 在 +0x170） |
| 悬空 reference `R0` | chunk+0x24e0 | **chunk+0x68160** |
| B 的 carrier 形状 | 2×55B fake ref | **899×39B token + 15×167B HT** |

标定过程（本地 `docker run php:8.5.11-apache` + 同款三个 ini，容器内装 gdb）：

1. **符号表**：从 `/usr/lib/apache2/modules/libphp.so` 解析出
   `ps_globals=0x1771a40`、`zif_system=0x5996e0`、`zval_ptr_dtor=0x7b47a0`、
   `zend_reference_destroy=0x7b4740`、`zend_array_destroy=0x769080`。
2. **stage1 直接可用**：A(6 MiB)+B(841 个 48B 值) 就泄漏出 4096 字节，
   只需把 PoC 里硬编码的指针范围 `0x7F00…–0x8000…` 放宽（本机堆落在 `0x7a38…/0x7f74…`）。
3. **R0 定位**：gdb 读 `ps_globals+0x168` 的 zval，实测 `R0 = chunk+0x68160`：
   ```
   02 00 00 00 | 1a 00 00 00 | 18 58 c5 03 3f 73 00 00 | 07 03 00 00
   rc=2          IS_REFERENCE  val.value (堆上数组)       val.type=0x307
   ```
4. **fake HT 落点**：给 15 个 167 字节串在 data 偏移 0 打 marker，发到 `sleep(25)` 页面后
   从宿主读 `/proc/<pid>/mem` 扫 2 MiB chunk：命中 `rel=0x690d8`，步长 `0xC0`，
   每个命中点前 0x18 字节正是 `01 00 00 00 16 00 00 00 | h=0 | len=0xa7`（zend_string 头）
   → 167B 串的数据区起点 = chunk+0x690d8（与 PoC 的 `htdata_offset` 一致）。

   但**真正能命中的 carrier 落点不是它**：用 15 B / 31 B flood 覆盖 R0 全部失败 ——
   Zend MM 按 size-class 分 run，15 B（bin-40）和 31 B 的 run 根本不在 `0x68160` 这一段。
   换成 **899 个 39 字节值**（39 B 属于 R0 所在的那类 40 B 槽）后，fake ref 才落进 R0。

5. **htdata=0xB3018**：B 里 15 份 167B fake HT 实际被分配在 `chunk+0xB3018` 起的连续区域
   （借用 UpWatch 已标定的同镜像常数），而不是 stage1 标定出的 0x690d8 ——
   stage 之间的 heap 历史不同，落点会漂；0xB3018 在本部署稳定。

6. **progress 字段放最后**：`PHP_SESSION_UPLOAD_PROGRESS` 一旦解析就触发 session init，
   若它排在 carrier 前面，销毁发生在 fake HT 还没分配时，链就断。

### 失败的尝试（教训）

- 用 15 B "carrier"（`pack('<II',1,0x1A)+pack('<Q',htdata)[:7]`）想直接覆盖 R0：B 直接崩、
  扫不到 marker —— 尺寸类不对，且 R0 是 40 B 槽。
- 悬挂式测落点（cut 掉最终 boundary）：扫到的全是原始 multipart body 文本，
  因为 part 未提交，`$_POST` 里根本没有那 15 个串。
- gdb 断点写成 `zval_ptr_dtor if $rdi==R0` 永远不命中：`rdi` 是 `&PS_zval`
  （`ps_globals+0x168`），不是 R0；正确做法是断 `php_session_track_init` 后读
  `ps_globals+0x168` 的 value。
- `docker exec … /proc/self/mem` 在容器内打不开（apache 子进程 setuid 后 `dumpable=0`），
  必须从宿主进程读 `/proc/<pid>/mem`。

## 5. 复现

### 5.1 本地 lab

```bash
# 目录：C:\Users\{{USER}}\lp-lab（www/index.php 原样、zz-harden.ini、zz-prefork.conf、zz-body.conf、flag）
docker run -d --name ledgerpad-lab --cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
  -p 127.0.0.1:18200:80 \
  -v "C:/Users/{{USER}}/lp-lab/www:/var/www/html" \
  -v "C:/Users/{{USER}}/lp-lab/zz-harden.ini:/usr/local/etc/php/conf.d/zz-harden.ini:ro" \
  -v "C:/Users/{{USER}}/lp-lab/zz-prefork.conf:/etc/apache2/conf-enabled/zz-prefork.conf:ro" \
  -v "C:/Users/{{USER}}/lp-lab/zz-body.conf:/etc/apache2/conf-enabled/zz-body.conf:ro" \
  -v "C:/Users/{{USER}}/lp-lab/flag:/flag:ro" php:8.5.11-apache
```

```text
$ python _dl/ledgerpad_solve.py http://127.0.0.1:18200/index.php --tries 2
[*] chunk  = 0x7cb492000000
[*] libphp = 0x7cb493c00000
[*] htdata = 0x7cb4920b3018  zif = 0x7cb4941996e0
[+] response tail: b'1e\r\nlocal{{FLAG}}\n\r\n'
[+] secret recovered
```

冷启动（`docker restart` 后第一个请求即开打）同样一次成功；连续 5 次运行 5 次成功。

### 5.2 线上

```bash
python _dl/ledgerpad_solve.py http://172.16.219.2/index.php --tries 2
[*] chunk  = 0x7cb693200000
[*] libphp = 0x7cb694e00000
[*] htdata = 0x7cb6932b3018  zif = 0x7cb6953996e0
[+] response tail: b'26\r\n{{FLAG}}\r\n'
[+] secret recovered
```

两次独立运行均一次成功，远程堆地址与本地 lab 低位完全一致（`chunk=0x…3200000`、
`R0=chunk+0x68160`、`htdata=chunk+0xB3018`），说明配置复刻与重标定都正确。

**{{FLAG}}**

## 6. 修复建议

- 升级 PHP 到修复版本（8.5.12+ / 8.4.x 安全版），该系列 CVE 是 session 与 multipart
  解析器的双重缺陷；
- `display_errors=Off`（本部署为 On，警告泄漏直接帮助了 headers_sent 判定）；
- 生产环境不要给单 worker 长驻进程（`MaxConnectionsPerChild 0` 放大了跨请求堆状态复用）；
- 更根本的：`memory_limit` 与 `post_max_size` 不是安全边界，multipart 解析的
  中间态内存需要由 SAPI 层限制（本次正是靠 8 MiB 上限才需要换 6 MiB 载荷，
  但换载荷后链依旧成立）。
