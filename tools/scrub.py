#!/usr/bin/env python3
"""在私库里就地脱敏：把明文 flag 和凭据换成占位符。

判据来自 kb.config.yaml 的 public.flag_patterns / public.secret_patterns，
与公开镜像用的是同一套规则，避免两处规则漂移。

用法:
    python tools/scrub.py --dry-run     # 只报会改哪些文件
    python tools/scrub.py               # 就地改写
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
CFG = yaml.safe_load((ROOT / "kb.config.yaml").read_text(encoding="utf-8"))
PUB = CFG["public"]

TEXT_SUFFIX = {".md", ".yaml", ".yml", ".json", ".jsonl", ".py", ".sh", ".txt",
               ".html", ".js", ".css", ".toml", ".conf", ".ini"}
SKIP_DIRS = {".git", "dist", "private", "__pycache__", ".venv", "attachments"}

FLAG_RULES = [(re.compile(p), "{{FLAG}}") for p in PUB["flag_patterns"]]
SECRET_RULES = [(re.compile(s["pattern"]), s["replace"]) for s in PUB.get("secret_patterns", [])]


def scrub_text(text: str) -> tuple[str, dict[str, int]]:
    hits: dict[str, int] = {}
    for rx, rep in FLAG_RULES + SECRET_RULES:
        text, n = rx.subn(rep, text)
        if n:
            hits[rx.pattern[:40]] = hits.get(rx.pattern[:40], 0) + n
    return text, hits


def iter_text_files():
    for p in ROOT.rglob("*"):
        if p.is_dir() or p.suffix.lower() not in TEXT_SUFFIX:
            continue
        if any(part in SKIP_DIRS for part in p.relative_to(ROOT).parts):
            continue
        yield p


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="私库脱敏")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    files = total = 0
    for p in iter_text_files():
        try:
            text = p.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        new, hits = scrub_text(text)
        if not hits:
            continue
        files += 1
        total += sum(hits.values())
        print(f"[{'dry' if args.dry_run else 'fix'}] {p.relative_to(ROOT)}: "
              + ", ".join(f"{k}×{v}" for k, v in hits.items()))
        if not args.dry_run:
            p.write_text(new, encoding="utf-8")

    print(f"[i] 命中 {files} 个文件，共 {total} 处")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
