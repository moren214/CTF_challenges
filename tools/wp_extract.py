#!/usr/bin/env python3
"""把 .docx 的段落和表格导成 Markdown，供入库时对照（不依赖 python-docx）。

用法:
  python tools/wp_extract.py <in.docx> <out.md>

只保留文字与表格；图片仅记录占位编号，避免把二进制塞进知识库。
"""
from __future__ import annotations

import sys
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET

NS = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}


def para_text(p: ET.Element) -> str:
    return "".join(t.text or "" for t in p.iter(f"{{{NS['w']}}}t")).strip()


def para_style(p: ET.Element) -> str:
    st = p.find("w:pPr/w:pStyle", NS)
    if st is None:
        return ""
    return st.get(f"{{{NS['w']}}}val", "")


def cell_text(cell: ET.Element) -> str:
    return " ".join(para_text(p) for p in cell.iter(f"{{{NS['w']}}}p") if para_text(p))


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    src, dst = Path(sys.argv[1]), Path(sys.argv[2])
    with zipfile.ZipFile(src) as zf:
        xml = zf.read("word/document.xml")
    root = ET.fromstring(xml)
    body = root.find("w:body", NS)
    out: list[str] = [f"<!-- extracted from {src.name} -->", ""]
    n_img = 0
    for node in body:
        tag = node.tag.split("}")[-1]
        if tag == "p":
            text = para_text(node)
            if node.findall(".//w:drawing", NS) or node.findall(".//w:pict", NS):
                n_img += 1
                out.append(f"_[图片 {n_img}]_")
            if not text:
                continue
            style = para_style(node)
            if style.lower().startswith("heading") or style in ("1", "2", "3"):
                level = int(style[-1]) if style[-1].isdigit() else 1
                out.append("#" * min(level, 4) + " " + text)
            else:
                out.append(text)
        elif tag == "tbl":
            rows = []
            for tr in node.findall("w:tr", NS):
                rows.append([cell_text(tc) for tc in tr.findall("w:tc", NS)])
            if not rows:
                continue
            width = max(len(r) for r in rows)
            rows = [r + [""] * (width - len(r)) for r in rows]
            out.append("| " + " | ".join(rows[0]) + " |")
            out.append("| " + " | ".join(["---"] * width) + " |")
            for r in rows[1:]:
                out.append("| " + " | ".join(c.replace("|", "\\|") for c in r) + " |")
    dst.parent.mkdir(parents=True, exist_ok=True)
    text = "\n".join(out) + "\n"
    dst.write_text(text, encoding="utf-8")
    print(f"[ok] {src.name} -> {dst} | {len(text)} 字符 | {text.count(chr(10))} 行 | 图片 {n_img}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
