# 2026 TPCTF 收件箱

来源目录：`D:\CTF practice\03_比赛\2026-TPCTF`（扁平下载堆，118 个文件）
入库结论：33 题已归档到 `problems/`；本目录只放**无法唯一归属**或**仅作参考**的散落文件。

## 已归档

| 类别 | 数量 | 说明 |
| --- | --- | --- |
| pwn | 13 | QuickJS 系 13 题，附件为 `AUTHORED-*.zip` |
| web | 20 | 含 file-drop / upload / agent 系 |
| 合计 | 33 | `python tools/kb.py index` 可复核 |

## 本目录文件

| 文件 | 大小 | 判断 | 归属线索 |
| --- | --- | --- | --- |
| `api.md` | 2900 | 接口文档，不是题面 | "Agent Workbench — 接口文档"，对应 `2026-tpctf-web-opencode-copilot`（平台名 opencode_copilot） |
| `index (2).php` | 2345 | 中文图库首页 | 无平台条目对应，疑为未出题或旧版素材 |
| `README (1).md` | 1066 | 泛用中文附件说明 | 提到 quickjs-base-bundle 与主题附件逐字节一致，疑属 `2026-tpctf-pwn-rabbit-hole` |
| `README (1).txt` | 301 | 附件清单 | "served by Release Desk itself"，属 `2026-tpctf-web-release-desk` |
| `README (2).md` | 404 | 附件说明 | "Engine evaluation service"，属长连接求值类，疑 `long-lived-eval` 或 `quickjs-engine-core` |
| `README (2).txt` | 1661 | **jsbox 完整题面** | 标题即 "# jsbox — QuickJS 引擎内存迷宫（题面）"，属 `2026-tpctf-pwn-jsbox`，可回填题面 |
| `README (3).md` | 1469 | 附件说明 | 标题 "# QwirlBox attachments"，属 `2026-tpctf-pwn-qwirlbox` |
| `README (3).txt` | 852 | 附件说明 | 讲 pinned base + patch，属 pinned 系某一题 |
| `README.txt` | 187 | 两行说明 | 与 `AUTHORED-4230E93C` 内 README 同 sha256，属 `2026-tpctf-pwn-qjs-sandbox` |
| `inst.json` | 8519 | 平台题目页快照 | 含 33 条的 `challenge_id`/名称/难度/`services`，可作为 cid 对照表 |

## 未收取（刻意排除）

- `ctfy-*.conf` ×58、`AUTHORED-*.zip` 重复副本 ×3、`quickjs-base-bundle*.tar.gz` ×7：前者含 WireGuard `PrivateKey`，属**凭据**，任何情况下不进仓库；后者与已归档副本逐字节相同。
- `patch*.diff` ×7、`fixed-source.tar.gz`：已随对应 zip 归档，散落副本重复。

## 待办

1. 用 `README (2).txt` 回填 `2026-tpctf-pwn-jsbox` 的完整题面。
2. `api.md` 若确认属 opencode-copilot，可移入该题目录的 `attachments/`。
3. 平台 19:37 快照有 7 题 `solved=False`，与 WP 实际完成情况不符；以 WP 为准，`status` 全部记为 `solved`。
