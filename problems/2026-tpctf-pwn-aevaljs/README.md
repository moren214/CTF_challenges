# AevalJS — 常驻内存脚本求值服务

```
> TPCTF 2026 · pwn · 挑战 ID `AUTHORED-0C9A1A59` · 状态 solved
```

## 一句话

AevalJS 是一个长驻内存的 JavaScript 求值服务：一条 TCP 连接独占一个 持久运行时，逐行提交源码，取回 JSON 结果。

## 附件

| 文件 | 大小 | sha256 |
| --- | --- | --- |
| `src/quickjs-base-bundle.tar.gz` | 1.5 MB | `a69e0f7f77c5…` |
| `src/patch.diff` | 2.2 KB | `02a09a9a5c3c…` |

## 分析与利用

FLAG：«FLAG»

分值：动态计分

### 漏洞

补丁在 js_dataview_getValue() / js_datavalue_setValue() 中把视图长度提前缓存：

uint32_t vlen = ta->length;         /* 在 JS_ToIndex(pos) 之前 */

...

```
if ((pos + size) > vlen) goto out_of_bound;                       /* 旧长度 */
if ((int64_t)ta->offset + ta->length > abuf->byte_length) ...     /* 新长度 */
ptr = abuf->data + ta->offset + pos;
```

对 new ArrayBuffer(len, {maxByteLength: len}) 上的 未显式指定 byteLength 的 DataView，构造时 track_rab = 1，ta->length 会随后备存储的 resize 更新。在 pos 参数的valueOf 回调里调用 ab.resize(0x10) 后：

• 第一处检查用的是缩容前的 vlen，pos+size <= 0x1F000 通过；
• 第二处检查里 ta->length 已被 js_array_buffer_update_typed_arrays() 改成新长度， offset+ta->length <= byte_length 也通过；
• 而 abuf->data 仍是原 0x1F000 字节块（realloc 收缩后原块被 free），于是 ptr = data + pos 对已释放的旧后备存储做 OOB 读写。

### 利用链

1. 篡改 JSString 长度：把 0x1F000 的 RAB 收缩到 0x10，随后 "S".repeat(0x2000) 作为第一个大分配（>504 字节走 js_malloc_large）落在旧块前端 data+0x20 （JSMallocLargeBlockHeader 占 8 字节）。用一次 OOB setBigUint64(pos=0x20, 0x7fffffff) 把 JSString.len 改成 0x7fffffff（is_wide_char=0）， s.charCodeAt(i) 变成向前连续堆读。
2. 堆地址泄露：arr[0x40]=s 的 JSValue 在 fast array 的 values 块里；扫描 s 的字符找字符串 tag（f9 ff ff ff ff ff ff ff），校验前一槽为 null， 读出 union 指针即得 s 的绝对地址，从而得 abuf->data、values 块基址。
3. 伪造 JSObject：在旧块内分配 fakebuf = new Uint8Array(0x1000)，在其数据里 构造伪对象：class_id=23 (UINT8_ARRAY)、u.array.u.ptr、count=0x7fffffff， 并在对象前 8 字节头里把 ref_count 置高，避免 JS_DupValue/JS_FreeValue 释放。
4. 多次 OOB 写：利用嵌套 DataView 调用——每一层都在 resize 前缓存了 vlen， 所以同一次求值里可以有多次 OOB 写，且各层 valueOf 里能读取已完成 OOB 的结果：
• L0 收缩 + 分配 + 返回 0x18；
• L1 读 data+0x18 自校准，返回写 s.len 的位置（0x20 或 0x1010）；
• W0 写 0x7fffffff 到 s.len；
• L2 扫描得到 data/values 块/fakeabs，返回 baseoff+0x500；
• W1 把 fakeabs 写进 arr[0x50] 的 union（原值是 Array.prototype.push， tag 保持 OBJECT=-1，只覆盖 8 字节指针）；
• L3 用 arr[0x50][k] 作为任意地址字节读写视图，通过改写 fakebuf 中伪对象的 u.ptr 重定向目标。
5. 取凭据：读 arr[0x50] 所指 C_FUNCTION JSObject 的 +40（u.cfunc.realm） 得 JSContext*；ctx+16 得 JSRuntime*；rt+0x4c8 得 stack_top （QuickJS 2026-06-04，JSRuntime 以 JSMallocContext 开头，该偏移用 gdb 核实）； 从 stack_top 向上逐字节扫描 QJS_CTF_FLAG=，读到 NUL 即得环境变量值。

### 自校准

不同脚本分配历史会让旧块前端先落入 class-72 arena 或字符串。payload 先做一次嵌套 OOB 读 data+0x18：

• 值 < 0x10^11（JSMallocLargeBlockHeader：block_idx=0xffff、block_size_idx=0xff） → 字符串头就在 data+0x18，S_OFF = 0x20；
• 值是大堆指针（arena）→ S_OFF = 0x1010（class-72 arena 占 0xFF0 字节块）。

### 复现

# 本地：打补丁编译后

```
cd /mnt/d/work/aevaljs && make -j4 runner
```

QJS_CTF_FLAG='«FLAG»' ./build/qjs_runner   # 二进制协议，见 localrun.py

# 远程（需 WireGuard 隧道）

```bash
python3 aevaljs_solve/remote.py aevaljs_solve/exploit.js
```

exploit.js 为最终 payload（约 4.4 KB，本地/远程均 <0.1 s），远程返回：

["flag",...,"«FLAG»",...]

## 结果

- flag sha256：`b442668530e4eee5e3477f9f07d05a2ad3ab1f04c6bcf2ffc6f1c1bed3d06763`, `c3b5737a3902dd8d137c0c19fc591c191783970d7a4b58214fd52691ceb2020d`
- 明文 flag 不入库；提交记录见 `.ctf-submissions.jsonl` 或原始 WP。

## 脚本

- `solve/remote.py`
- `solve/exploit.js`

## 待核实

- 本条目由 WP 第 27 节《AevalJS — 常驻内存脚本求值服务》与平台附件自动合成，建议人工复核 summary 与 fingerprints。
