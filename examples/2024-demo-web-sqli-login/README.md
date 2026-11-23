# 登录框 SQL 注入（结构示例）

> 这是一条**示例记录**，用来演示目录、字段和写作粒度，不是真实赛题。
> 它放在 `examples/` 下，不进入 `index/problems.jsonl`；可以整目录复制到 `problems/` 当模板。

| 项目 | 值 |
| --- | --- |
| 编号 | `2024-demo-web-sqli-login` |
| 赛事 | demo 2024 |
| 分类 | web |
| 解题日期 | 2024-05-01 |
| 附件 | `attachments/app.py`，哈希见 `meta.yaml` |

## 题面

本地 Flask demo，`POST /login` 接收 `username` / `password`。
目标：拿到管理员密码（flag 形态 `flag{...}`）。源码随附件给出。

## 观察与证据

- `app.py:23` 用 f-string 把 `username` 拼进 `SELECT`，没有参数化。
- `app.py:15` 的过滤列表是 `(" ", "union", "select", "--")`，且只检查 `username`。
- 直接提交 `admin' -- ` 返回 403：空格和 `--` 被拦。
- 提交 `admin'/**/or/**/'1'='1` 返回 200 且页面出现「欢迎 admin」，确认注入成立。

## 分析与验证

1. 假设：过滤只做字面匹配，注释符 `/**/` 可替代空格。
2. 验证：`'/**/or/**/1=1/**/or/**/'` 使 WHERE 恒真，页面长度从 1002 变成 1024。
3. 结论：可用 `substr()` 做布尔盲注；`select` 用 `SeLeCt` 混写绕过。

```bash
# 本地复现
python attachments/app.py            # 起服务 :5000
python solve/exp.py                  # 盲注出 pass
```

## 关键判断来源

- self：全部由附件源码和本地回显推出。
- human：无。
- external：无。

## 结果

- 拿到管理员密码，形态 `flag{...}`；明文不入库，只保留在当次提交回执里。
- 复现命令见上，预期输出 `{{FLAG}}`（示例值）。

## 死路与踩坑

- 直接 `union select 1,2` 被 WAF 拦：关键字原样出现。
- 想用时间盲注：sqlite 没有 `sleep()`，换布尔。

## 待核实

- 无（示例记录）。
