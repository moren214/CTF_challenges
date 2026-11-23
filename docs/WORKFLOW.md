# 工作流

## A. 赛后归档（目标 5 分钟）

1. 确认 `ctf_progress` 的解题目录里有 `notes.md`（四段：结论/命令/排除/待办）。
2. 生成草稿：

   ```bash
   python tools/ingest_ctf.py --from "<解题目录>" \
       --year 2024 --event 强网杯 --category web --slug ezsql --title ezsql \
       --attach challenge.zip
   ```

3. 人工补三样，其它可以慢慢来：
   - `summary`：一句话，讲清「考什么 + 怎么解」；
   - `tags`：从 `tags.yaml` 挑，缺词就加；
   - `fingerprints`：至少 2 条「看到 X 就该想到 Y」。这是以后能否被搜到的关键。
4. 把 `notes.md` 里没进模板的内容补进 README 对应小节，删掉没用的 TODO。
5. 收尾：

   ```bash
   python tools/kb.py index && python tools/kb.py validate
   git add -A && git commit -m "add: 2024-强网杯-web-ezsql"
   ```

## B. 旧题补录（一次一批）

1. 先按 `<年份>-<赛事>-<分类>-<slug>` 规划好 id；同一场比赛放同一年份。
2. 有附件和脚本的，用 `ingest_ctf.py`；只有记忆的，用 `kb.py new` 后手填。
3. 一次不要超过 10 题：批量录入最容易把 `fingerprints` 写成空话。
4. 每批结束跑一次 `validate`，错误清零再进下一批。

## B2. 整场比赛批量入库（有平台记录 + 官方/队内 WP）

1. `python tools/wp_split.py --docx <WP.docx>`：拆成一题一节，拿到章节号。
2. 写 `mappings/<年份>-<赛事>.json`：每题 `id / cid（平台挑战 ID）/ title / cat / wp（章节号）/ zip 或 files / tags / scripts`。
   - 附件对不上题时，先 `python tools/match_wp_patch.py` 用补丁新增行在 WP 里做包含率匹配。
   - `files` 支持 `{"src": "散落文件名", "dst": "src/规范名"}`，用于没有 zip 的散题。
3. `python tools/wp_import.py --mapping ... --dry-run` 核对附件数、脚本数、摘要；确认后去掉 `--dry-run`。
   - 导入时自动跑 `normalize_md`：补空行、代码行包围栏、`2.1 xxx` 步骤标题加粗——解决 docx 导出后整段并成一坨的问题。
4. `python tools/kb.py index && python tools/kb.py validate`。
5. `python tools/build_view.py` 重建本地浏览页，肉眼过一遍排版。
6. 无法归属的散落文件进 `inbox/<年份>-<赛事>/`，并写 `REPORT.md` 记录判读与归属线索。
7. 凭据类文件（WireGuard 私钥、token、靶机口令）**任何情况下不入库**，只在报告里记「已排除」。

## C. 发布公开版（GitHub）

```bash
python tools/scrub.py --dry-run      # 私库自查：明文 flag / 凭据
python tools/scrub.py                # 就地换成占位符
python tools/sanitize_public.py --force
cd dist/public
python tools/kb.py index && python tools/kb.py validate
git init -b main
git add -A && git commit -m "publish: $(date +%F)"
git remote add origin git@github.com:<user>/<repo>.git
git push -u origin main
```

发布前人工确认三件事：

- `grep -rnE "(flag|ctf|dh|nss|buu|hgame|n1ctf)\{[^}]{8,}" dist/public` 无输出；
- `grep -rn "PrivateKey = " dist/public` 只剩 `{{WG_PRIVATE_KEY}}`；
- `grep -rnE "10844|/Users/[A-Za-z]+" dist/public` 无本机路径；
- `dist/public` 里没有 `private/`、`.ctf-submissions.jsonl`、`handoff.md`；
- 外部 WP 的引用只有结论和链接，没有大段原文。

三类规则都写在 `kb.config.yaml` 的 `public:` 下（`flag_patterns` / `secret_patterns` / `path_patterns`），
`scrub.py` 与 `sanitize_public.py` 共用同一份，改规则只改一处。

私库和公开库是两份独立 git 历史：私库提交原件与全部字段，公开库只提交脱敏结果。
**不要给公开库配 `sanitize` 之外的推送路径**，避免哪天直接 `git push` 私库。

## D. 标签维护

- 新增技术：先在 `tags.yaml` 的 `techniques` 加一条（`zh`/`en`/`aliases`/`category`），再在题目里用。
- 同义词写进 `aliases`，AI 检索时不同叫法才能命中。
- 删改 id 会导致历史题目失配：先 `grep -rn "<old-id>" problems/` 全局替换，再改词表。

## E. 技术决策卡（`techniques/`）

现在不建。满足下面任一条再提升：

- 同一套路在 ≥3 道题里出现；
- 你发现自己每次都要重新想判断顺序；
- 某类题在比赛里反复卡住同一处。

提升时用 `templates/technique.md`，并在相关题目的 `related` 里互相引用。

## 质量门槛

一条记录算「归档完成」需要同时满足：

- `python tools/kb.py validate` 通过；
- `summary` 不含 TODO，且 ≤160 字；
- `tags` 至少 1 个，`fingerprints` 至少 2 条；
- `sources` 写清 self/human/external；
- 有脚本的，`solve/` 里能直接跑（依赖写进 `environment`）。
