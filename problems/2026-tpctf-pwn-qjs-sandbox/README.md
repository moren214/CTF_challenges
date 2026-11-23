# QJS Sandbox — expression service

```
> TPCTF 2026 · pwn · 挑战 ID `AUTHORED-4230E93C` · 状态 solved
```

## 一句话

A hardened JavaScript expression service evaluates untrusted source in a pinned QuickJS runtime and returns the JSON result.

## 附件

| 文件 | 大小 | sha256 |
| --- | --- | --- |
| `AUTHORED-4230E93C.zip` | 798.6 KB | `5d9f439043b3…` |
| `zip/README.txt` | 187 B | `a06a3ef93247…` |
| `zip/patch.diff` | 1.5 KB | `66c7c74629a8…` |

## 分析与利用

FLAG：«FLAG»

分值：动态计分

### 结论

动态 flag：

«FLAG»

三次独立连接得到同一 flag（三次的栈地址 S 都不同），说明读取的是 worker 进程环境里的实例 secret，而不是偶然的栈数据。

### 漏洞

patch.diff 修改了 third_party/quickjs/src/quickjs.c 的js_array_buffer_constructor3()（patch.diff:11-38，改动后的源码在third_party/quickjs/src/quickjs.c:56563-56567 和 :56585）：

```
if (buf == NULL) {
/* scratch buffer used while the object is still being built */
uint8_t scratch[32];
abuf->data = scratch;
stack_backed = TRUE;
} else {
abuf->data = js_mallocz(ctx, max_int(len, 1));
```

...

```
}
```

...

```
abuf->free_func = stack_backed ? NULL : free_func;
```

普通 new ArrayBuffer(n)（buf == NULL）时，abuf->data 指向构造函数栈帧里的scratch[32]；函数返回后该栈内存仍然有效，byteLength 却是调用者指定的任意长度，且没有堆分配。于是 new Uint8Array(ab) 可以从 scratch 开始读写整个栈，包括越界到调用者栈帧、初始栈的 argc/argv/envp 表和 auxv、以及栈顶附近的参数字符串和环境字符串。free_func = NULL 保证 GC 不会释放这个栈地址。

### 栈布局与利用

adapter 启动 worker 时的环境是固定的（adapter/server.py:162-171）：

• LC_ALL=C
• LANG=C
• QJS_CTF_FLAG=<动态 flag>
• argv[0] = /app/build/qjs_runner

scratch 地址记为 S。S 往上依次是：

1. 当前 C 调用帧；
2. 初始栈的 argc、argv[]、envp[] 指针表；
3. auxv（AT_PLATFORM=15、AT_RANDOM=25、AT_EXECFN=31 等）；
4. 一段随机对齐空隙；
5. argv/env 字符串（按 envp 顺序连续排列）；
6. 栈顶 T。

其中 AT_PLATFORM 的值 Vplat 指向字符串 "x86_64"；AT_RANDOM 的值Vrand 指向它前面的 16 字节随机数，因此 Vplat - Vrand == 16。在 buffer里扫到 "x86_64\0" 的偏移 ox 后：

```
S = Vplat - ox
```

再用 Vrand == Vplat - 16 以及 S 的 16 字节对齐/栈地址范围做校验。得到 S 后，envp[j] - S 就是第 j 个环境字符串在 buffer 中的偏移；直接读"QJS_CTF_FLAG=..." 即可。该字符串位于 AT_EXECFN 字符串之前，而AT_EXECFN 字符串在 T 以下，因此读取范围 [envp[j], AT_EXECFN) 不会越过 T。

qjs/exploit.py 生成的 JS 主要步骤：

```js
var ab = new ArrayBuffer(0x10000);
var u = new Uint8Array(ab);
// 1. 扫描 "x86_64\0" -> ox
// 2. 扫描 argc=1 / argv[0] / envp[] / auxv 表
// 3. 从 auxv 取 AT_PLATFORM/AT_RANDOM/AT_EXECFN
// 4. S = Vplat - ox
// 5. 对每个 envp[j]，读 envp[j]-S 处的字符串
// 6. 返回 "QJS_CTF_FLAG=" 后面的值
```

qjs/localtest.py 在本地用相同源码构建的 runner 上验证，20/20 成功。

### 复现步骤

1. 用题目提供的 ctfy-b2dd14012c.conf 起隧道（WSL 里已装 wireguard-tools； 去掉 DNS 行以避免 resolvconf 依赖）：

cp ctfy-b2dd14012c.conf /etc/wireguard/ctfy.conf

sed -i '/^DNS/d' /etc/wireguard/ctfy.conf

```bash
chmod 600 /etc/wireguard/ctfy.conf
```

wg-quick up ctfy

2. 解析内部域名：

dig +short @172.16.170.3 {{INSTANCE_HOST}} A

# 172.16.170.2

3. 运行利用：

```bash
cd qjs
python3 remote_exploit.py
```

实际输出（第一次）：

attempt 1 L0=0x1000 0.05s ok=True result=[2601, 140728578695040, 8290, 3]

FLAG: «FLAG»

第二次连接（S 不同）：

attempt 1 L0=0x1000 0.05s ok=True result=[2601, 140721318035664, 3858, 3]

FLAG: «FLAG»

第三次连接抓到的原始响应（保存在 qjs/remote_raw.json）：

```
{"ok":true,"result":[2601,140729591695152,6322,3,"«FLAG»"]}
```

结果数组含义：[ox, S, A_execfn-S, envc, flag]（ox 是 "x86_64" 在 buffer 中的偏移，envc 是 envp 条目数）。

### 修复建议

alloc_flag && buf == NULL 时必须使用堆分配，不能把长期存活对象的数据指针指向构造函数栈帧：

```
if (buf == NULL) {
abuf->data = js_mallocz(ctx, max_int(len, 1));
if (!abuf->data)
goto fail;
}
```

并让 abuf->free_func 与实际分配方式一致；stack_backed 这类临时状态不应在对象构造完成后继续影响 free_func。如果确实需要构造期 scratch，只能让它在对象返回前被替换成堆指针，且不能设置可被 JS 观测到的 byteLength。

### 文件

• qjs/exploit.py：生成利用 JS。
• qjs/localtest.py：本地复现（精确 env，20 次）。
• qjs/remote_exploit.py：连接 172.16.170.2:8000，发送 JSON line 并解析结果。
• qjs/probe_remote.py：协议探测。
• qjs/sim_parse.py：用保存的栈 dump 验证表解析算法。

## 结果

- flag sha256：`5ff752ded86da8fe73ec6447d87f01cfb5d48c3890f84a0c3508db0d5cf6fb9a`
- 明文 flag 不入库；提交记录见 `.ctf-submissions.jsonl` 或原始 WP。

## 脚本

- `solve/exploit.py`
- `solve/client.py`

## 待核实

- 本条目由 WP 第 30 节《QJS Sandbox — expression service》与平台附件自动合成，建议人工复核 summary 与 fingerprints。
