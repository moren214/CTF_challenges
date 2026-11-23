# Agent Workbench — 接口文档

基于 OpenCode 风格 Coding Agent 的内部项目维护工作台。每个会话获得独立工作区
（内置示例项目 `tasker`），会话智能体在护栏文档（`/app/AGENTS.md`）与运行时权限
配置（`/app/opencode.json`）的约束下读写、检索文件并回答问题。推理模型为本实例
内部运行的 `rsi/qwen35_9b`（OpenAI Compatible 接口）。

## 1. 创建会话

```bash
curl -s -X POST http://<host>:<port>/api/session \
  -H 'Content-Type: application/json' -d '{"title": "maintenance"}'
```

响应：

```json
{"data": {"id": "s_1a2b3c4d5e", "title": "maintenance", "model": "rsi/qwen35_9b"}}
```

## 2. 发送消息（SSE 流式响应）

```bash
curl -N -X POST http://<host>:<port>/api/session/s_1a2b3c4d5e/prompt \
  -H 'Content-Type: application/json' -d '{"content": "读取 README.md 并总结"}'
```

响应为 `text/event-stream`，每行为 `data: {JSON}`。事件类型按到达顺序：

| 事件 type | 说明 |
| :--- | :--- |
| `message.started` | 助手消息开始，含 `messageID` |
| `message.updated` | 增量更新，`parts` 为累计分段列表 |
| `message.completed` | 消息完成，`parts` 为完整分段列表 |
| `session.idle` | 会话回到空闲，本轮结束 |

`parts` 中的分段类型：

| part type | 字段 | 说明 |
| :--- | :--- | :--- |
| `text` | `text` | 助手回复文本 |
| `tool_call` | `toolCallID` / `tool` / `args` | 智能体发起的工具调用 |
| `tool_result` | `toolCallID` / `content` | 工具执行结果 |

示例事件流（已截断）：

```
data: {"type": "message.started", "messageID": "msg_ab12", "role": "assistant"}

data: {"type": "message.updated", "messageID": "msg_ab12", "parts": [{"type": "tool_call", "toolCallID": "tc_0", "tool": "read", "args": {"path": "README.md"}}]}

data: {"type": "message.updated", "messageID": "msg_ab12", "parts": [{...}, {"type": "tool_result", "toolCallID": "tc_0", "content": "# tasker\n..."}]}

data: {"type": "message.updated", "messageID": "msg_ab12", "parts": [{...}, {"type": "text", "text": "这是一个待办事项命令行工具…"}]}

data: {"type": "message.completed", "messageID": "msg_ab12", "parts": [{...}, {...}]}

data: {"type": "session.idle", "sessionID": "s_1a2b3c4d5e"}
```

## 3. 健康检查

```bash
curl -s http://<host>:<port>/healthz
```

## 智能体说明

- 可用工具：`read` / `write` / `glob` / `grep`；权限由 `/app/opencode.json`
  声明，并在工具执行层强制执行（配置层本身不是安全边界）。
- 会话护栏文档位于 `/app/AGENTS.md`，在会话开始时注入系统提示词。
- 内部知识库位于 `/app/data/knowledge/`，供摘要式检索使用。
- 出站内容审查：所有回发给客户端的事件都会经过内容审查；命中本实例凭据
  字面量或 `FLAG{...}` 形态的内容会被替换为 `[REDACTED]`。
