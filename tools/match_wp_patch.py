#!/usr/bin/env python3
"""把附件里的 patch 与 WP 章节对应起来：按补丁新增行的文本重合度打分。

用于「一堆散落的 patch*.diff 到底属于哪道题」。只打印分数，不打印补丁内容。

用法: python tools/match_wp_patch.py <附件目录> <WP 章节目录>
"""
from __future__ import annotations

import re
import sys
import zipfile
from pathlib import Path


def added_lines(diff: str) -> list[str]:
    out = []
    for ln in diff.split("\n"):
        if ln.startswith("+") and not ln.startswith("+++"):
            s = re.sub(r"\s+", "", ln[1:])
            if len(s) >= 12:
                out.append(s)
    return out


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    src, wpdir = Path(sys.argv[1]), Path(sys.argv[2])

    patches: dict[str, str] = {}
    for z in sorted(src.glob("AUTHORED-*.zip")):
        with zipfile.ZipFile(z) as zf:
            for n in zf.namelist():
                if n.endswith(".diff"):
                    patches[f"{z.stem}:{n}"] = zf.read(n).decode("utf-8", "replace")
    for p in sorted(src.glob("patch*.diff")):
        patches[p.name] = p.read_text(encoding="utf-8", errors="replace")

    sections = {
        p.name: re.sub(r"\s+", "", p.read_text(encoding="utf-8"))
        for p in sorted(wpdir.glob("[0-9][0-9]-*.md"))
    }

    for name, diff in patches.items():
        adds = added_lines(diff)
        if not adds:
            print(f"{name}: 无新增行，跳过")
            continue
        scored = sorted(
            ((sum(1 for a in adds if a in text) / len(adds), fn) for fn, text in sections.items()),
            reverse=True,
        )
        top = ", ".join(f"{fn[:24]}={s:.2f}" for s, fn in scored[:3])
        print(f"{name:<34} +{len(adds):<4} -> {top}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
