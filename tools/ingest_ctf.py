#!/usr/bin/env python3
"""把一次 CTF 解题现场（ctf_progress 工作目录）转成知识库草稿。

用法:
  python tools/ingest_ctf.py --from "D:/CTF practice/2024-强网杯/ezsql" \
      --year 2024 --event 强网杯 --category web --slug ezsql --title ezsql \
      [--attach challenge.zip] [--dry-run]

读取:
  notes.md 的四段（结论/命令/排除/待办）-> README 的对应小节
  目录内的解题脚本 -> solve/
  --attach 指定的附件 -> attachments/（超过 20MB 只登记哈希与外链占位）

不复制: .ctf/、.git/、__pycache__/、已有的 notes.md 本体。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
from datetime import date
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
CFG = yaml.safe_load((ROOT / "kb.config.yaml").read_text(encoding="utf-8"))
PATHS = CFG["paths"]
LIMIT_MB = CFG["limits"]["attachment_mb"]
PATTERN = re.compile(CFG["naming"]["pattern"])

SCRIPT_SUFFIX = {".py", ".sh", ".sage", ".js", ".php", ".rb", ".c", ".cpp", ".go", ".rs", ".ps1", ".bat"}
SKIP_DIRS = {".ctf", ".git", "__pycache__", ".venv", "node_modules", ".idea"}
SKIP_FILES = {"notes.md", "handoff.md", "meta.yaml", "README.md"}
MAX_SCRIPT_BYTES = 2 * 1024 * 1024

# notes.md 的小节关键词 -> README 占位符
SECTION_MAP = [
    (("结论", "结果", "分析"), "ANALYSIS"),
    (("观察", "证据", "证据链"), "OBSERVATIONS"),
    (("命令", "复现", "操作"), "COMMANDS"),
    (("排除", "死路", "踩坑"), "DEAD_ENDS"),
    (("待办", "待核实", "下一步"), "TODO"),
]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_notes(path: Path) -> dict[str, str]:
    """按 '## 标题' 切分 notes.md，返回 {占位符: 正文}。"""
    if not path.is_file():
        return {}
    text = path.read_text(encoding="utf-8", errors="replace")
    parts = re.split(r"(?m)^##\s+", text)
    result: dict[str, str] = {}
    for chunk in parts[1:]:
        lines = chunk.splitlines()
        if not lines:
            continue
        heading = lines[0].strip()
        body = "\n".join(lines[1:]).strip()
        for keys, slot in SECTION_MAP:
            if any(k in heading for k in keys) and slot not in result:
                result[slot] = strip_fence(body) if slot == "COMMANDS" else body
                break
    return result


def strip_fence(text: str) -> str:
    """notes 里的命令常自带 ``` 围栏，塞进模板的代码块会嵌套，这里剥掉。"""
    lines = text.strip().splitlines()
    if len(lines) >= 2 and lines[0].strip().startswith("```") and lines[-1].strip() == "```":
        return "\n".join(lines[1:-1]).strip()
    return text.strip()


def collect_scripts(src: Path) -> list[Path]:
    found = []
    for p in sorted(src.rglob("*")):
        if not p.is_file():
            continue
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if p.suffix.lower() in SCRIPT_SUFFIX and p.stat().st_size <= MAX_SCRIPT_BYTES:
            found.append(p)
    return found


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="把解题现场转成知识库草稿")
    ap.add_argument("--from", dest="src", required=True, help="解题工作目录")
    ap.add_argument("--year", required=True)
    ap.add_argument("--event", required=True)
    ap.add_argument("--category", required=True,
                    choices=["web", "pwn", "reverse", "crypto", "misc", "blockchain", "ai", "hardware", "other"])
    ap.add_argument("--slug", required=True)
    ap.add_argument("--title", required=True)
    ap.add_argument("--difficulty", default="medium",
                    choices=["easy", "medium", "hard", "insane"])
    ap.add_argument("--attach", action="append", default=[], help="可重复，附件路径（相对 --from 或绝对）")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    src = Path(args.src).expanduser().resolve()
    if not src.is_dir():
        print(f"[x] 源目录不存在: {src}")
        return 2

    ident = f"{args.year}-{args.event}-{args.category}-{args.slug.strip().lower()}"
    if not PATTERN.match(ident):
        print(f"[x] 目录名不符合规范: {ident}")
        return 2
    dest = ROOT / PATHS["problems"] / ident
    if dest.exists():
        print(f"[x] 目标已存在: {dest.relative_to(ROOT)}")
        return 2

    notes = parse_notes(src / "notes.md")
    scripts = collect_scripts(src)

    attachments: list[dict] = []
    copies: list[tuple[Path, str]] = []   # (源文件, 目标相对路径)
    for raw in args.attach:
        p = Path(raw)
        if not p.is_absolute():
            p = src / p
        p = p.resolve()
        if not p.is_file():
            print(f"[!] 跳过不存在的附件: {raw}")
            continue
        size = p.stat().st_size
        item = {"path": f"attachments/{p.name}", "sha256": sha256_file(p), "size": size}
        if size > LIMIT_MB * 1024 * 1024:
            item["path"] = ""
            item["external"] = "TODO 外链（超过 %dMB 不入库）" % LIMIT_MB
            print(f"[!] {p.name} 超过 {LIMIT_MB}MB，只登记哈希")
        else:
            copies.append((p, item["path"]))
        attachments.append(item)

    summary = "TODO 一句话说明考点和解法（<=160 字）"
    analysis = notes.get("ANALYSIS", "").strip()
    if analysis:
        first = next((ln.strip(" -*\t") for ln in analysis.splitlines() if ln.strip()), "")
        if first:
            summary = first[: CFG["limits"]["summary_max"]]

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
        "summary": summary,
        "tags": [],
        "fingerprints": ["TODO 题面出现什么/附件长什么样时该想到这题"],
        "attachments": attachments,
        "scripts": [f"solve/{p.name}" for p in scripts],
        "evidence": [],
        "environment": [],
        "dead_ends": [ln.strip("- \t") for ln in notes.get("DEAD_ENDS", "").splitlines() if ln.strip()][:10],
        "related": [],
        "flag_format": "",
        "sources": [{"type": "self", "note": "由 ingest_ctf.py 从解题现场生成，待复核"}],
    }

    tpl = (ROOT / PATHS["templates"] / "problem-README.md").read_text(encoding="utf-8")
    readme = (tpl.replace("{{ID}}", ident).replace("{{TITLE}}", args.title)
                 .replace("{{EVENT}}", args.event).replace("{{YEAR}}", str(args.year))
                 .replace("{{CATEGORY}}", args.category).replace("{{DATE}}", date.today().isoformat())
                 .replace("{{OBSERVATIONS}}", notes.get("OBSERVATIONS") or "- 附件结构与关键偏移：\n- 运行/访问后的实际输出：\n- 支撑判断的文件、行号、字节偏移：")
                 .replace("{{ANALYSIS}}", notes.get("ANALYSIS") or "1. 假设：\n2. 验证命令与输出：\n3. 结论：")
                 .replace("{{COMMANDS}}", notes.get("COMMANDS") or "# TODO 从干净环境复现的最小命令")
                 .replace("{{DEAD_ENDS}}", notes.get("DEAD_ENDS") or "- TODO 试过但没用的方向，以及为什么没用")
                 .replace("{{TODO}}", notes.get("TODO") or "- TODO 当前材料无法确认的点"))

    print(f"[+] 题目编号: {ident}")
    print(f"    notes 小节: {', '.join(sorted(notes)) or '无'}")
    print(f"    脚本 {len(scripts)} 个, 附件 {len(attachments)} 个")
    if args.dry_run:
        print("[dry-run] 未写入")
        return 0

    for sub in ("solve", "evidence", "attachments"):
        (dest / sub).mkdir(parents=True, exist_ok=True)
    (dest / "meta.yaml").write_text(
        yaml.safe_dump(meta, allow_unicode=True, sort_keys=False, width=100), encoding="utf-8")
    (dest / "README.md").write_text(readme, encoding="utf-8")
    for p in scripts:
        shutil.copy2(p, dest / "solve" / p.name)
    for p, rel in copies:
        shutil.copy2(p, dest / rel)

    print(f"[+] 已写入 {dest.relative_to(ROOT)}")
    print("    下一步: 补 tags/fingerprints -> python tools/kb.py index -> python tools/kb.py validate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
