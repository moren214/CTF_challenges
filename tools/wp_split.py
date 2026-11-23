#!/usr/bin/env python3
"""把整篇 WP 按二级标题拆成一题一个文件，并打印清单（不打印明文 flag）。

用法:
  python tools/wp_split.py private/2026-tpctf-wp.md private/wp

清单每行：序号 | slug | 标题 | 字符数 | 小节数 | flag 数(sha256 前 12 位)
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

FLAG_RE = re.compile(r"(?:FLAG|flag)\{[^}\n]{1,120}\}")
CATEGORY = {"web", "pwn", "ai", "misc", "crypto", "reverse", "blockchain", "forensics"}


def slugify(title: str) -> str:
    s = title.lower()
    s = re.sub(r"[^a-z0-9]+", "-", s).strip("-")
    return s or "section"


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    src, out_dir = Path(sys.argv[1]), Path(sys.argv[2])
    text = src.read_text(encoding="utf-8")
    lines = text.split("\n")

    marks = [i for i, ln in enumerate(lines) if ln.startswith("## ")]
    sections: list[tuple[str, str]] = []
    manifest: list[dict] = []
    current_category = "?"
    for n, start in enumerate(marks):
        end = marks[n + 1] if n + 1 < len(marks) else len(lines)
        title = lines[start][3:].strip()
        body = "\n".join(lines[start + 1:end]).strip()
        if title.lower() in CATEGORY or len(body) < 40:
            current_category = title
            continue
        sections.append((title, body))
        first = next((ln.strip() for ln in body.split("\n") if ln.strip() and not ln.startswith(("###", "#", "|"))), "")
        manifest.append({
            "index": len(sections),
            "title": title,
            "category": current_category,
            "chars": len(body),
            "subs": len(re.findall(r"^### ", body, re.M)),
            "first": first[:180],
            "flag_sha8": [hashlib.sha256(f.encode()).hexdigest()[:8] for f in FLAG_RE.findall(body)],
        })

    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"{'#':>2} | {'slug':<28} | {'标题':<34} | 字符 | 小节 | flag")
    for i, (title, body) in enumerate(sections, 1):
        slug = slugify(title)
        flags = FLAG_RE.findall(body)
        subs = len(re.findall(r"^### ", body, re.M))
        (out_dir / f"{i:02d}-{slug}.md").write_text(f"## {title}\n\n{body}\n", encoding="utf-8")
        fp = ",".join(hashlib.sha256(f.encode()).hexdigest()[:8] for f in flags)
        print(f"{i:>2} | {slug:<28} | {title:<34} | {len(body):>5} | {subs:>3} | {len(flags)} {fp}")
    (out_dir / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"[i] 共 {len(sections)} 题 -> {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
