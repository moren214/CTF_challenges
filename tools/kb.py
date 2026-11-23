#!/usr/bin/env python3
"""CTF 知识库维护 CLI。

子命令:
  new       按命名规范新建题目骨架
  index     由 problems/*/meta.yaml 重建 index/problems.jsonl
  search    在索引上做关键词反查（--json 供 AI 调用）
  validate  校验元数据、附件哈希、索引新鲜度
  stats     分类/年份/标签统计

只依赖标准库 + PyYAML。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import date
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
CFG = yaml.safe_load((ROOT / "kb.config.yaml").read_text(encoding="utf-8"))
PATHS = CFG["paths"]

CATEGORIES = ["web", "pwn", "reverse", "crypto", "misc", "blockchain", "ai", "hardware", "other"]
STATUSES = ["solved", "partial", "unsolved"]
DIFFICULTIES = ["easy", "medium", "hard", "insane"]
SOURCE_TYPES = ["self", "human", "external"]

REQUIRED = ["schema", "id", "title", "event", "year", "category",
            "status", "summary", "tags", "fingerprints", "sources"]
RECOMMENDED = ["difficulty", "solved_at", "attachments", "scripts", "evidence",
               "environment", "dead_ends", "related", "flag_format",
               "challenge_id", "flag_sha256", "attachments_complete"]
KNOWN = set(REQUIRED) | set(RECOMMENDED)


def out(msg: str = "") -> None:
    print(msg)


def as_str(v) -> str:
    return "" if v is None else str(v)


def load_yaml(path: Path):
    with path.open(encoding="utf-8") as f:
        return yaml.safe_load(f)


def dump_yaml(data) -> str:
    return yaml.safe_dump(data, allow_unicode=True, sort_keys=False,
                          default_flow_style=False, width=100)


def tag_index() -> dict[str, dict]:
    doc = load_yaml(ROOT / PATHS["tags"]) or {}
    idx: dict[str, dict] = {}
    for section in ("techniques", "tools"):
        for key, val in (doc.get(section) or {}).items():
            idx[key] = {"section": section, **(val or {})}
    return idx


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def problem_dirs() -> list[Path]:
    base = ROOT / PATHS["problems"]
    if not base.is_dir():
        return []
    return sorted(p for p in base.iterdir() if p.is_dir() and not p.name.startswith("."))


def load_problem(d: Path) -> dict:
    meta = load_yaml(d / "meta.yaml")
    if not isinstance(meta, dict):
        raise ValueError(f"{d.name}/meta.yaml 不是映射结构")
    return meta


def index_record(meta: dict, d: Path) -> dict:
    rec = {
        "id": as_str(meta.get("id")),
        "title": as_str(meta.get("title")),
        "challenge_id": as_str(meta.get("challenge_id")),
        "event": as_str(meta.get("event")),
        "year": meta.get("year"),
        "category": as_str(meta.get("category")),
        "difficulty": as_str(meta.get("difficulty")) or "unknown",
        "status": as_str(meta.get("status")),
        "summary": as_str(meta.get("summary")),
        "tags": [as_str(t) for t in (meta.get("tags") or [])],
        "fingerprints": [as_str(f) for f in (meta.get("fingerprints") or [])],
        "scripts": [as_str(s) for s in (meta.get("scripts") or [])],
        "solved_at": as_str(meta.get("solved_at")),
        "attachments": len(meta.get("attachments") or []),
        "path": d.relative_to(ROOT).as_posix(),
    }
    return rec


def build_index_text() -> str:
    records = []
    for d in problem_dirs():
        if not (d / "meta.yaml").is_file():
            continue
        records.append(index_record(load_problem(d), d))
    records.sort(key=lambda r: (str(r.get("year")), r["id"]), reverse=True)
    return "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in records)


def load_index() -> list[dict]:
    path = ROOT / PATHS["index"]
    if not path.is_file():
        return []
    recs = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            recs.append(json.loads(line))
    return recs


# ---------------------------------------------------------------- new

def cmd_new(args) -> int:
    pattern = re.compile(CFG["naming"]["pattern"])
    slug = args.slug.strip().lower()
    ident = f"{args.year}-{args.event}-{args.category}-{slug}"
    m = pattern.match(ident)
    if not m:
        out(f"[x] 目录名不符合规范: {ident}")
        out(f"    要求: {CFG['naming']['pattern']}")
        return 2
    d = ROOT / PATHS["problems"] / ident
    if d.exists():
        out(f"[x] 已存在: {d.relative_to(ROOT)}")
        return 2

    for sub in ("solve", "evidence", "attachments"):
        (d / sub).mkdir(parents=True, exist_ok=True)

    meta = {
        "schema": 1,
        "id": ident,
        "title": args.title,
        "event": args.event,
        "year": int(args.year),
        "category": args.category,
        "difficulty": args.difficulty,
        "status": "solved",
        "solved_at": date.today().isoformat(),
        "summary": "TODO 一句话说明考点和解法（<=160 字）",
        "tags": [],
        "fingerprints": ["TODO 题面出现什么/附件长什么样时该想到这题"],
        "attachments": [],
        "scripts": [],
        "evidence": [],
        "environment": [],
        "dead_ends": [],
        "related": [],
        "flag_format": "",
        "sources": [{"type": "self", "note": "TODO 自己做/队友提示/参考外部 WP"}],
    }
    (d / "meta.yaml").write_text(dump_yaml(meta), encoding="utf-8")

    tpl = (ROOT / PATHS["templates"] / "problem-README.md").read_text(encoding="utf-8")
    readme = (tpl.replace("{{ID}}", ident).replace("{{TITLE}}", args.title)
                 .replace("{{EVENT}}", args.event).replace("{{YEAR}}", str(args.year))
                 .replace("{{CATEGORY}}", args.category).replace("{{DATE}}", date.today().isoformat())
                 .replace("{{OBSERVATIONS}}", "- 附件结构与关键偏移：\n- 运行/访问后的实际输出：\n- 支撑判断的文件、行号、字节偏移：")
                 .replace("{{ANALYSIS}}", "1. 假设：\n2. 验证命令与输出：\n3. 结论：")
                 .replace("{{COMMANDS}}", "# TODO 从干净环境复现的最小命令")
                 .replace("{{DEAD_ENDS}}", "- TODO 试过但没用的方向，以及为什么没用")
                 .replace("{{TODO}}", "- TODO 当前材料无法确认的点"))
    (d / "README.md").write_text(readme, encoding="utf-8")

    out(f"[+] 已创建 {d.relative_to(ROOT)}")
    out("    下一步: 填 meta.yaml -> 放脚本到 solve/ -> python tools/kb.py index")
    return 0


# ---------------------------------------------------------------- index

def cmd_index(args) -> int:
    path = ROOT / PATHS["index"]
    path.parent.mkdir(parents=True, exist_ok=True)
    new = build_index_text()
    old = path.read_text(encoding="utf-8") if path.is_file() else ""
    path.write_text(new, encoding="utf-8")
    n = len([l for l in new.splitlines() if l.strip()])
    state = "无变化" if new == old else "已更新"
    out(f"[+] 索引{state}: {n} 题 -> {path.relative_to(ROOT)}")
    return 0


# ---------------------------------------------------------------- search

WEIGHTS = {"title": 6, "id": 4, "tags": 5, "summary": 4, "fingerprints": 3, "event": 1}


def score_record(rec: dict, tokens: list[str], whole: str) -> int:
    fields = {
        "title": as_str(rec.get("title")).casefold(),
        "id": as_str(rec.get("id")).casefold(),
        "tags": " ".join(rec.get("tags") or []).casefold(),
        "summary": as_str(rec.get("summary")).casefold(),
        "fingerprints": " ".join(rec.get("fingerprints") or []).casefold(),
        "event": as_str(rec.get("event")).casefold(),
    }
    score = 0
    for tok in tokens:
        for name, hay in fields.items():
            if tok and tok in hay:
                score += WEIGHTS[name]
    if whole and any(whole in hay for hay in fields.values()):
        score += 8
    return score


def cmd_search(args) -> int:
    recs = load_index()
    if not recs:
        out("[!] 索引为空，先运行: python tools/kb.py index")
        return 1
    query = " ".join(args.query).strip()
    tokens = [t for t in re.split(r"[\s,，]+", query.casefold()) if t]

    # 收窄范围：分类 / 标签 / 状态，先过滤再打分，交给 AI 精确命中
    if args.category:
        recs = [r for r in recs if as_str(r.get("category")) == args.category]
    if args.status:
        recs = [r for r in recs if as_str(r.get("status")) == args.status]
    if args.tag:
        recs = [r for r in recs if args.tag in (r.get("tags") or [])]
    if not recs:
        out("[!] 过滤后没有题目")
        return 1

    scored = [(score_record(r, tokens, query.casefold()), r) for r in recs]
    if tokens:
        scored = [(s, r) for s, r in scored if s > 0]
    scored.sort(key=lambda x: (-x[0], x[1]["id"]))
    hits = scored[: args.top]

    if args.json:
        if args.brief:
            out(json.dumps([brief_record(r, s) for s, r in hits], ensure_ascii=False, indent=1))
        else:
            out(json.dumps([{**r, "score": s} for s, r in hits], ensure_ascii=False, indent=2))
        return 0
    if not hits:
        out(f"[!] 无命中: {query}")
        return 1
    out(f"[+] 命中 {len(scored)} 题，显示前 {len(hits)} 题")
    for i, (s, r) in enumerate(hits, 1):
        out("")
        out(f"{i}. {r['id']}  [{r['category']}/{r['difficulty']}]  score={s}")
        out(f"   {r['title']} - {r['summary']}")
        if r.get("fingerprints"):
            out(f"   指纹: {' | '.join(r['fingerprints'][:3])}")
        out(f"   tags: {', '.join(r.get('tags') or [])}")
        out(f"   path: {r['path']}")
    return 0


BRIEF_KEYS = ("id", "title", "category", "difficulty", "status", "tags", "summary", "path")


def brief_record(rec: dict, score: int | None = None) -> dict:
    """给 AI 的精简记录：一题约 200 字节，33 题全量也不到 8 KB。"""
    d = {k: rec.get(k) for k in BRIEF_KEYS if rec.get(k) not in (None, "", [])}
    if score is not None:
        d["score"] = score
    return d


def cmd_card(args) -> int:
    """单题速览卡：不读 README 就能判断「要不要展开」。"""
    recs = load_index()
    key = args.id.strip()
    rec = next((r for r in recs if r["id"] == key), None)
    if rec is None:
        k = key.casefold()
        rec = next((r for r in recs
                    if as_str(r.get("challenge_id")).casefold() in (k, "authored-" + k)
                    or as_str(r.get("challenge_id")).casefold().endswith(k)), None)
    if rec is None:
        cand = [r for r in recs if r["id"].startswith(key)]
        if len(cand) == 1:
            rec = cand[0]
        else:
            out(f"[!] 没找到: {key}" + (f"（{len(cand)} 个前缀候选）" if cand else ""))
            return 1

    prob_dir = ROOT / PATHS["problems"] / rec["id"]
    meta_path = prob_dir / "meta.yaml"
    meta = yaml.safe_load(meta_path.read_text(encoding="utf-8")) if meta_path.is_file() else {}
    atts = meta.get("attachments") or []
    scripts = rec.get("scripts") or []

    card = {
        "id": rec["id"],
        "title": rec.get("title"),
        "challenge_id": rec.get("challenge_id"),
        "event": f"{rec.get('event')} {rec.get('year')}",
        "category": rec.get("category"),
        "difficulty": rec.get("difficulty"),
        "status": rec.get("status"),
        "summary": rec.get("summary"),
        "tags": rec.get("tags") or [],
        "fingerprints": rec.get("fingerprints") or [],
        "path": rec.get("path"),
        "readme": str(meta_path.parent.joinpath("README.md").relative_to(ROOT)),
        "attachments": [{"path": a.get("path"), "size": a.get("size")} for a in atts],
        "scripts": scripts,
    }
    if args.json:
        out(json.dumps(card, ensure_ascii=False, indent=2))
        return 0

    out(f"{card['title']}  ({card['id']})")
    out(f"  {card['event']} · {card['category']}/{card['difficulty']} · {card['status']} · {card['challenge_id']}")
    out(f"  一句话: {card['summary']}")
    out(f"  标签: {', '.join(card['tags']) or '（无）'}")
    out("  指纹:")
    for fp in card["fingerprints"]:
        out(f"    - {fp}")
    out(f"  题解: {card['readme']}")
    if card["attachments"]:
        names = ", ".join(str(a["path"]) for a in card["attachments"][:6])
        out(f"  附件 {len(card['attachments'])} 个: {names}{' …' if len(card['attachments']) > 6 else ''}")
    if scripts:
        out(f"  脚本: {', '.join(scripts)}")
    return 0


# ---------------------------------------------------------------- validate

def cmd_validate(args) -> int:
    errors: list[str] = []
    warns: list[str] = []
    tags = tag_index()
    strict = bool((CFG.get("tags") or {}).get("strict"))
    pattern = re.compile(CFG["naming"]["pattern"])
    limit_mb = CFG["limits"]["attachment_mb"]
    summary_max = CFG["limits"]["summary_max"]

    dirs = problem_dirs()
    ids: dict[str, Path] = {}
    for d in dirs:
        ident = d.name
        m = pattern.match(ident)
        if not m:
            errors.append(f"{ident}: 目录名不符合命名规范")
        meta_path = d / "meta.yaml"
        if not meta_path.is_file():
            errors.append(f"{ident}: 缺少 meta.yaml")
            continue
        try:
            meta = load_problem(d)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{ident}: meta.yaml 解析失败: {exc}")
            continue

        ids[ident] = d
        for key in REQUIRED:
            if meta.get(key) in (None, "", [], {}):
                errors.append(f"{ident}: 必填字段缺失或为空: {key}")
        for key in meta:
            if key not in KNOWN:
                warns.append(f"{ident}: 未知字段 {key}（拼写？）")

        if as_str(meta.get("id")) != ident:
            errors.append(f"{ident}: meta.id={meta.get('id')!r} 与目录名不一致")
        if meta.get("category") not in CATEGORIES:
            errors.append(f"{ident}: category 非法: {meta.get('category')!r}")
        if meta.get("status") not in STATUSES:
            errors.append(f"{ident}: status 非法: {meta.get('status')!r}")
        if "difficulty" in meta and meta["difficulty"] not in DIFFICULTIES:
            errors.append(f"{ident}: difficulty 非法: {meta.get('difficulty')!r}")
        if not isinstance(meta.get("year"), int):
            errors.append(f"{ident}: year 必须是整数")
        if as_str(meta.get("year")) != (m.group("year") if m else as_str(meta.get("year"))):
            warns.append(f"{ident}: year 与目录名年份不一致")

        summary = as_str(meta.get("summary"))
        if len(summary) > summary_max:
            errors.append(f"{ident}: summary {len(summary)} 字，超过 {summary_max}")
        if "TODO" in summary:
            warns.append(f"{ident}: summary 仍是 TODO")

        fps = meta.get("fingerprints") or []
        if not isinstance(fps, list):
            errors.append(f"{ident}: fingerprints 必须是列表")
        else:
            for fp in fps:
                if "TODO" in as_str(fp):
                    warns.append(f"{ident}: fingerprints 含 TODO")
                if len(as_str(fp)) > 200:
                    warns.append(f"{ident}: 指纹过长（>200 字），建议拆成多条")

        for tag in meta.get("tags") or []:
            if tag not in tags:
                msg = f"{ident}: 标签不在词表: {tag}"
                (errors if strict else warns).append(msg)

        srcs = meta.get("sources") or []
        if not isinstance(srcs, list) or not srcs:
            errors.append(f"{ident}: sources 至少一条")
        else:
            for s in srcs:
                if not isinstance(s, dict) or s.get("type") not in SOURCE_TYPES:
                    errors.append(f"{ident}: sources.type 必须是 {SOURCE_TYPES}")
                elif s.get("type") == "external" and not s.get("url"):
                    warns.append(f"{ident}: external 来源建议补 url")

        for att in meta.get("attachments") or []:
            if not isinstance(att, dict) or not att.get("path"):
                errors.append(f"{ident}: attachments 条目缺少 path")
                continue
            f = d / att["path"]
            if att.get("external"):
                continue
            if not f.is_file():
                errors.append(f"{ident}: 附件不存在: {att['path']}")
                continue
            size = f.stat().st_size
            if att.get("size") is not None and int(att["size"]) != size:
                errors.append(f"{ident}: 附件 {att['path']} size 不符（记录 {att['size']} 实际 {size}）")
            if att.get("sha256") and att["sha256"].lower() != sha256_file(f):
                errors.append(f"{ident}: 附件 {att['path']} sha256 不符")
            if size > limit_mb * 1024 * 1024:
                warns.append(f"{ident}: 附件 {att['path']} 超过 {limit_mb}MB，应改为外链")

        for script in meta.get("scripts") or []:
            if not (d / script).is_file():
                errors.append(f"{ident}: 脚本不存在: {script}")

        if not (d / "README.md").is_file():
            errors.append(f"{ident}: 缺少 README.md")

    # 关联题必须存在
    for ident, d in ids.items():
        try:
            meta = load_problem(d)
        except Exception:  # noqa: BLE001
            continue
        for rel in meta.get("related") or []:
            if rel not in ids:
                warns.append(f"{ident}: related 指向不存在的题目: {rel}")

    # 索引新鲜度
    idx_path = ROOT / PATHS["index"]
    expected = build_index_text()
    actual = idx_path.read_text(encoding="utf-8") if idx_path.is_file() else ""
    if expected != actual:
        errors.append("index/problems.jsonl 过期，请运行: python tools/kb.py index")

    for w in warns:
        out(f"[!] {w}")
    for e in errors:
        out(f"[x] {e}")
    out("")
    out(f"题目 {len(dirs)} 道 | 错误 {len(errors)} | 告警 {len(warns)}")
    if not errors:
        out("[+] 校验通过")
    return 1 if errors else 0


# ---------------------------------------------------------------- stats

def cmd_stats(args) -> int:
    recs = load_index()
    if not recs:
        out("[!] 索引为空，先运行: python tools/kb.py index")
        return 1
    out(f"题目总数: {len(recs)}")
    by_cat: dict[str, int] = {}
    by_year: dict[str, int] = {}
    by_tag: dict[str, int] = {}
    for r in recs:
        by_cat[r["category"]] = by_cat.get(r["category"], 0) + 1
        by_year[as_str(r.get("year"))] = by_year.get(as_str(r.get("year")), 0) + 1
        for t in r.get("tags") or []:
            by_tag[t] = by_tag.get(t, 0) + 1
    out("按分类: " + ", ".join(f"{k}={v}" for k, v in sorted(by_cat.items(), key=lambda x: -x[1])))
    out("按年份: " + ", ".join(f"{k}={v}" for k, v in sorted(by_year.items(), reverse=True)))
    top = sorted(by_tag.items(), key=lambda x: -x[1])[:10]
    if top:
        out("高频标签: " + ", ".join(f"{k}({v})" for k, v in top))
    return 0


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="CTF 知识库维护 CLI")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("new", help="新建题目骨架")
    p.add_argument("--year", required=True)
    p.add_argument("--event", required=True)
    p.add_argument("--category", required=True, choices=CATEGORIES)
    p.add_argument("--slug", required=True)
    p.add_argument("--title", required=True)
    p.add_argument("--difficulty", default="medium", choices=DIFFICULTIES)
    p.set_defaults(func=cmd_new)

    p = sub.add_parser("index", help="重建索引")
    p.set_defaults(func=cmd_index)

    p = sub.add_parser("search", help="关键词反查")
    p.add_argument("query", nargs="*", help="检索词；留空则按 --category/--tag/--status 或全量列出")
    p.add_argument("--top", type=int, default=5)
    p.add_argument("--json", action="store_true")
    p.add_argument("--brief", action="store_true", help="配 --json 用，只返回定位所需字段")
    p.add_argument("--category", help="只查某一分类")
    p.add_argument("--tag", help="只查带某标签的题")
    p.add_argument("--status", help="solved / unsolved / partial")
    p.set_defaults(func=cmd_search)

    p = sub.add_parser("card", help="单题速览卡")
    p.add_argument("id", help="题目 id、challenge_id 或 id 前缀")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_card)

    p = sub.add_parser("validate", help="校验")
    p.set_defaults(func=cmd_validate)

    p = sub.add_parser("stats", help="统计")
    p.set_defaults(func=cmd_stats)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
