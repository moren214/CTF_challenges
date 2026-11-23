"""把批量导入的题解正文整理成各处理解器都能看懂的 Markdown。

背景：队内 WP 是 docx，导出成一题一个 Markdown 后，Word 里「一行 = 一段」的
结构丢了空行，代码行、`2.5 xxx` 步骤标题、正文连成一串。按 CommonMark 规则
"连续行 = 同一段落"，于是代码和步骤全被并成一大坨。

本模块做的三件事：
  1. 连续代码行 -> ``` 围栏代码块（按内容猜语言）
  2. `2.5 找 libc` 这类步骤标题 -> 独占一行的 **加粗**
  3. 其余每一行 -> 独立段落，块与块之间恰好一个空行

已有围栏、表格、标题、列表原样保留；重复执行结果不变（幂等）。
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# 明显的源码 / 命令形态（只看行首，避免把中文正文误判）
CODE_HEAD = re.compile(
    r"^(?:[{}]|//|/\*|#!|\$ |>|"
    r"(?:var|let|const|function|for|while|if|else|return|import|from|export|def|class|"
    r"await|async|try|catch|switch|case|break|continue|yield|lambda|public|private|protected|"
    r"static|void|int|long|char|unsigned|struct|typedef|#include|#define|"
    r"print|echo|cd|ls|cat|curl|wget|python3?|nc|ncat|nmap|gdb|objdump|readelf|"
    r"su|sudo|chmod|chown|export|mkfifo|base64)\b)")

# 2.1 / 3.4.1 这类步骤编号
STEP_RE = re.compile(r"^\d+(?:\.\d+)+\s+\S.{0,60}$")

_ASSIGN = re.compile(r"^[A-Za-z_$][\w$.\[\]]*\s*(?:=|\+=|-=|\*=|\|=)\s*\S")
_LIST = re.compile(r"^(?:[-*]|\d+\.)\s+")


def is_code_line(line: str) -> bool:
    """判定一行是不是源码/命令。看不懂的一律当正文，宁可少包不误包。"""
    s = line.strip()
    if not s:
        return False
    if re.search(r"[\u4e00-\u9fff]", s) and not CODE_HEAD.match(s):
        return False
    if len(s) < 200 and CODE_HEAD.match(s):
        return True
    if len(s) >= 200:
        return False
    if re.search(r"[;}]\s*$", s) and re.search(r"[=();{}\[\]]", s):
        return True
    if _ASSIGN.match(s):
        return True
    return False


def guess_lang(block: list[str]) -> str:
    t = "\n".join(block)
    if re.search(r"<\?php|\$\w+\s*=", t):
        return "php"
    if re.search(r"\b(?:var|let|const|function|ArrayBuffer|Uint32Array|=>)\b", t):
        return "js"
    if re.search(r"^\s*(?:def|import|from|class)\s", t, re.M):
        return "python"
    if re.search(r"^#!|^\s*(?:python3?|pip|curl|wget|nc|ncat|sudo|apt|npm|chmod)\b", t, re.M):
        return "bash"
    return ""


def _push_block_start(out: list[str]) -> None:
    """块之间保证恰好一个空行。"""
    while out and out[-1] == "":
        out.pop()
    if out:
        out.append("")


def normalize(md: str) -> tuple[str, dict[str, int]]:
    lines = md.replace("\r\n", "\n").split("\n")
    out: list[str] = []
    stats = {"para": 0, "code": 0, "step": 0}
    i = 0
    while i < len(lines):
        s = lines[i].strip()
        if not s:
            i += 1
            continue

        # 已有围栏：整段照抄，不再包裹
        if s.startswith("```"):
            _push_block_start(out)
            j = i + 1
            while j < len(lines) and not lines[j].strip().startswith("```"):
                j += 1
            out.extend(lines[i:j + 1])
            i = j + 1
            continue

        # 表格照抄
        if s.startswith("|"):
            _push_block_start(out)
            while i < len(lines) and lines[i].strip().startswith("|"):
                out.append(lines[i].rstrip())
                i += 1
            continue

        # 标题照抄
        if re.match(r"^#{1,6}\s", s):
            _push_block_start(out)
            out.append(s)
            i += 1
            continue

        # 列表（含 WP 里的 • ）整组照抄
        if _LIST.match(s) or s.startswith("•"):
            _push_block_start(out)
            while i < len(lines):
                t = lines[i].strip()
                if not (_LIST.match(t) or t.startswith("•")):
                    break
                out.append(lines[i].rstrip())
                i += 1
            continue

        # 连续代码行 -> 围栏
        if is_code_line(s):
            j = i
            while j < len(lines) and lines[j].strip() and not lines[j].strip().startswith("```") and is_code_line(lines[j]):
                j += 1
            _push_block_start(out)
            out.append("```" + guess_lang(lines[i:j]))
            out.extend(x.rstrip() for x in lines[i:j])
            out.append("```")
            stats["code"] += 1
            i = j
            continue

        # 步骤标题 -> 加粗独占一行
        if STEP_RE.match(s) and not re.search(r"[=();{}\[\]]", s):
            _push_block_start(out)
            out.append(f"**{s}**")
            stats["step"] += 1
            i += 1
            continue

        # 其余：一行一段
        _push_block_start(out)
        out.append(s)
        stats["para"] += 1
        i += 1

    text = "\n".join(out).rstrip() + "\n"
    return text, stats


def main() -> int:
    ap = argparse.ArgumentParser(description="整理题解 Markdown 的分段与代码块")
    ap.add_argument("paths", nargs="*", help="要处理的文件；省略则按 --glob 在题库里找")
    ap.add_argument("--glob", default="problems/*/README.md")
    ap.add_argument("--write", action="store_true", help="就地写回（默认只报告）")
    args = ap.parse_args()

    files = [Path(p) for p in args.paths] or sorted(ROOT.glob(args.glob))
    if not files:
        print("[!] 没有匹配到文件")
        return 1

    changed = 0
    total = {"para": 0, "code": 0, "step": 0}
    for f in files:
        old = f.read_text(encoding="utf-8")
        new, st = normalize(old)
        for k in total:
            total[k] += st[k]
        if new == old:
            continue
        changed += 1
        delta = len(new) - len(old)
        print(f"[改] {f.relative_to(ROOT)} | 代码块 {st['code']} | 步骤 {st['step']} | 段落 {st['para']} | {delta:+d} 字节")
        if args.write:
            f.write_text(new, encoding="utf-8")

    verb = "已写回" if args.write else "未写回（加 --write 生效）"
    print(f"[+] {len(files)} 个文件，{changed} 个需要整理，{verb}；合计 代码块 {total['code']} / 步骤 {total['step']} / 段落 {total['para']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
