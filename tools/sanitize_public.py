#!/usr/bin/env python3
"""生成可公开的镜像（默认 dist/public），供 GitHub 公开仓使用。

做三件事:
  1. 剔除 private/、.ctf/、提交回执、handoff 等敏感路径
  2. 按 meta.yaml 过滤附件：超过 public 体积上限或 redistributable=false 的不带走，只留哈希
  3. 全文正则兜底替换明文 flag（私库本就不该有，这是第二道闸）

用法:
  python tools/sanitize_public.py [--out dist/public] [--force] [--dry-run]
"""
from __future__ import annotations

import argparse
import fnmatch
import re
import shutil
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
CFG = yaml.safe_load((ROOT / "kb.config.yaml").read_text(encoding="utf-8"))

DROP_DIRS = {".git", "dist", "private", "__pycache__", ".venv", ".ctf", ".idea", "node_modules"}
DROP_FILES = {".ctf-submissions.jsonl", "handoff.md", "Thumbs.db", ".DS_Store"}
TEXT_SUFFIX = {".md", ".yaml", ".yml", ".json", ".jsonl", ".py", ".sh", ".txt", ".html", ".js", ".css", ".toml"}
FLAG_RES = [re.compile(p) for p in CFG["public"]["flag_patterns"]]
SECRET_RULES = [(re.compile(s["pattern"]), s["replace"])
                for s in CFG["public"].get("secret_patterns", [])]
PATH_RULES = [(re.compile(s["pattern"]), s["replace"])
              for s in CFG["public"].get("path_patterns", [])]
PUBLIC_LIMIT_MB = CFG["limits"]["public_attachment_mb"]
EXCLUDE_GLOBS = CFG["public"].get("exclude_globs", [])


def is_excluded(p: Path) -> bool:
    rel = p.resolve().relative_to(ROOT).as_posix()
    return any(fnmatch.fnmatch(rel, pat) for pat in EXCLUDE_GLOBS)


def is_problem_dir(p: Path) -> bool:
    return p.is_dir() and (p / "meta.yaml").is_file()


def plan_attachments() -> tuple[set[Path], dict[Path, dict]]:
    """返回 (公开版不带的文件, 需要重写的 meta)。"""
    skip: set[Path] = set()
    rewrites: dict[Path, dict] = {}
    base = ROOT / CFG["paths"]["problems"]
    if not base.is_dir():
        return skip, rewrites
    for d in sorted(base.iterdir()):
        if not is_problem_dir(d):
            continue
        meta = yaml.safe_load((d / "meta.yaml").read_text(encoding="utf-8")) or {}
        new_meta = {k: v for k, v in meta.items() if k not in set(CFG["public"]["drop_meta_keys"])}
        atts = []
        for att in meta.get("attachments") or []:
            if not isinstance(att, dict):
                continue
            item = dict(att)
            rel = item.get("path") or ""
            f = d / rel if rel else None
            too_big = bool(f and f.is_file() and f.stat().st_size > PUBLIC_LIMIT_MB * 1024 * 1024)
            not_redist = item.get("redistributable") is False
            if item.get("external") or too_big or not_redist or not f or not f.is_file():
                if f and f.is_file():
                    skip.add(f.resolve())
                item["path"] = ""
                item["external"] = item.get("external") or "TODO 外链（公开版不带此附件）"
            atts.append(item)
        new_meta["attachments"] = atts
        rewrites[(d / "meta.yaml").resolve()] = new_meta
    return skip, rewrites


def copy_tree(src: Path, dst: Path, skip: set[Path]) -> tuple[int, list[str]]:
    copied, skipped = 0, []
    dst.mkdir(parents=True, exist_ok=True)
    for item in sorted(src.iterdir()):
        if item.is_dir():
            if item.name in DROP_DIRS:
                continue
            n, s = copy_tree(item, dst / item.name, skip)
            copied += n
            skipped += s
        else:
            if item.name in DROP_FILES or item.suffix == ".pyc":
                continue
            if is_excluded(item):
                skipped.append(str(item.relative_to(ROOT)))
                continue
            if item.resolve() in skip:
                skipped.append(str(item.relative_to(ROOT)))
                continue
            shutil.copy2(item, dst / item.name)
            copied += 1
    return copied, skipped


def scrub(path: Path) -> int:
    if path.suffix.lower() not in TEXT_SUFFIX:
        return 0
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return 0
    total = 0
    for rx in FLAG_RES:
        text, n = rx.subn("{{FLAG}}", text)
        total += n
    for rx, rep in SECRET_RULES:
        text, n = rx.subn(rep, text)
        total += n
    for rx, rep in PATH_RULES:
        text, n = rx.subn(rep, text)
        total += n
    if total:
        path.write_text(text, encoding="utf-8")
    return total


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="生成公开镜像")
    ap.add_argument("--out", default=CFG["paths"]["public_out"])
    ap.add_argument("--force", action="store_true", help="覆盖已存在的输出目录")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    out = (ROOT / args.out).resolve()
    if out.exists():
        if not args.force:
            print(f"[x] {args.out} 已存在，加 --force 覆盖")
            return 2
        if not args.dry_run:
            shutil.rmtree(out)

    skip, rewrites = plan_attachments()
    print(f"[i] 公开版不携带附件 {len(skip)} 个")
    if args.dry_run:
        for p in sorted(skip):
            print(f"    - {p.relative_to(ROOT)}")
        return 0

    out.mkdir(parents=True, exist_ok=True)
    copied, skipped = copy_tree(ROOT, out, skip)

    for meta_path, new_meta in rewrites.items():
        rel = meta_path.relative_to(ROOT)
        target = out / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            yaml.safe_dump(new_meta, allow_unicode=True, sort_keys=False, width=100), encoding="utf-8")

    scrubbed = 0
    for p in out.rglob("*"):
        if p.is_file():
            scrubbed += scrub(p)

    print(f"[+] 公开镜像: {out.relative_to(ROOT)}")
    print(f"    复制文件 {copied} 个, 跳过附件 {len(skipped)} 个, 替换明文 flag {scrubbed} 处")
    print("    下一步: cd dist/public && python tools/kb.py index && python tools/kb.py validate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
