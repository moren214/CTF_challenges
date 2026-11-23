#!/usr/bin/env python3
"""把 WP（Markdown）+ 平台附件 + 解题脚本合成知识库条目。

与 import_batch.py 的区别：这个脚本把队内 WP 的正文脱敏后直接嵌进 README，
所以每条目都是「已解出、有利用链、有脚本」的完整记录，而不是空壳。

用法:
  python tools/wp_import.py --mapping tools/mappings/2026-tpctf.json [--dry-run] [--force]

映射字段见 tools/mappings/2026-tpctf.json：id/cid/title/cat/wp/zip|files/tags/scripts。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
import zipfile
from pathlib import Path, PurePosixPath

import yaml

from normalize_md import normalize as normalize_md

ROOT = Path(__file__).resolve().parent.parent
CFG = yaml.safe_load((ROOT / "kb.config.yaml").read_text(encoding="utf-8"))
PROBLEMS = ROOT / CFG["paths"]["problems"]
EXTRACT_MAX = 256 * 1024
FLAG_RE = re.compile(r"(?:FLAG|FLIG|flag|flig)\{[^}\n]{1,120}\}")
CATS = {"web", "pwn", "ai", "misc", "crypto", "reverse", "blockchain", "forensics"}
SKIP_PREFIX = ("• 题目：", "• 分值：", "• 附件：", "• 本实例", "• 实例", "FLAG：", "flag：", "分值：")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def split_wp(md_path: Path) -> list[tuple[str, str]]:
    """与 wp_split.py 相同的切分规则，保证 wp 序号一致。"""
    lines = md_path.read_text(encoding="utf-8").split("\n")
    marks = [i for i, ln in enumerate(lines) if ln.startswith("## ")]
    out: list[tuple[str, str]] = []
    for n, start in enumerate(marks):
        end = marks[n + 1] if n + 1 < len(marks) else len(lines)
        title = lines[start][3:].strip()
        body = "\n".join(lines[start + 1:end]).strip()
        if title.lower() in CATS or len(body) < 40:
            continue
        out.append((title, body))
    return out


def redact(text: str) -> tuple[str, list[str]]:
    flags = FLAG_RE.findall(text)
    hashes = [sha256_bytes(f.encode()) for f in flags]
    return FLAG_RE.sub("«FLAG»", text), hashes


def content_lines(body: str) -> list[str]:
    lines = []
    fence = False
    for ln in body.split("\n"):
        if ln.strip().startswith("```"):
            fence = not fence
            continue
        if fence:
            continue
        s = ln.strip()
        if not s or s.startswith(("###", "|", "```")):
            continue
        lines.append(s)
    return lines


def derive_summary(body: str) -> str:
    text, _ = redact(body)
    lines = [ln for ln in content_lines(text) if not ln.startswith(SKIP_PREFIX)]
    # 只看开头的题面区，避免把「修复建议」里的句子当成摘要
    window = lines[:8]
    best = ""
    for ln in window:
        s = re.sub(r"^[•\-]\s*", "", ln)
        s = re.sub(r"\s+", " ", s).strip()
        if len(s) < 24 or s.endswith(("：", "->", "→")):
            continue
        if s.endswith(("。", "）", ")", "`", "}")):
            best = s
            break
        if not best and len(s) >= 30:
            best = s
    if not best:
        for ln in lines:
            s = re.sub(r"^[•\-]\s*", "", ln).strip()
            if len(s) >= 24 and not s.endswith(("：", "->", "→")):
                best = s
                break
    if not best:
        return "（WP 未给出一句话摘要）"
    cut = best.find("。")
    return (best[:cut + 1] if 0 < cut < 150 else best[:150])


def load_platform_desc(path: Path) -> dict[str, str]:
    """从平台元数据里取每题官方 desc，作为 summary 的首选来源。"""
    if not path.is_file():
        return {}
    out: dict[str, str] = {}
    text = path.read_text(encoding="utf-8", errors="replace")
    marks = list(re.finditer(r"^### \d+ (AUTHORED-[0-9A-F]{8}) \|", text, re.M))
    for n, m in enumerate(marks):
        end = marks[n + 1].start() if n + 1 < len(marks) else len(text)
        block = text[m.end():end]
        pos = block.find("desc: ")
        if pos < 0:
            continue
        desc = " ".join(block[pos + 6:].split())
        desc = re.sub(r"^\|.*?\| ", "", desc)
        cut = max(desc.find("。"), desc.find(". "))
        if 0 < cut < 170:
            desc = desc[:cut + 1]
        elif len(desc) > 160:
            desc = desc[:160].rsplit(" ", 1)[0] + "…"
        out[m.group(1)] = desc
    return out


FP_HINTS = ("服务", "接口", "协议", "端口", "版本", "CVE", "源码", "附件", "依赖",
            "参数", "漏洞", "入口", "上传", "请求", "响应", "路由", "配置", "补丁",
            "沙箱", "TCP", "HTTP", "JSON", "PHP", "QuickJS", "Agent", "agent")
FP_BAD = re.compile(r"^[A-Z_]{2,}=|\.(diff|zip|tar\.gz|php|py|md|txt|json|html|conf|sh|so|js)$")
FP_NOISE = re.compile(r"\.py\b|argv\[|python3?\s|curl\s|^\S+/\S+\.|修复|建议|不应|至少要|必须假设"
                      r"|^SHA-256|^Interface Address|^Endpoint|^AllowedIPs|^PrivateKey|^DNS")


def derive_fingerprints(body: str, limit: int = 3) -> list[str]:
    """挑「看到什么就该想到这题」的 bullet：偏服务/接口/版本/漏洞，剔环境变量与纯文件名。"""
    text, _ = redact(body)
    scored = []
    lines = content_lines(text)[:80]  # 只看题面与前半段，避免把修复建议当指纹
    for i, ln in enumerate(lines):
        if ln.startswith(SKIP_PREFIX) or not ln.startswith("•"):
            continue
        s = re.sub(r"^•\s*", "", ln).strip()
        if len(s) < 10 or FP_BAD.search(s) or FP_NOISE.search(s):
            continue
        score = sum(1 for h in FP_HINTS if h in s)
        score += 1 if 24 <= len(s) <= 90 else 0
        if score <= 0:
            continue
        scored.append((score, i, s[:90]))
    scored.sort(key=lambda t: (-t[0], t[1]))
    picked = sorted(scored[:limit], key=lambda t: t[1])
    return [s for _, _, s in picked]


def copy_zip(src: Path, dest_dir: Path) -> list[dict]:
    atts = [{"path": f"attachments/{src.name}", "sha256": sha256_file(src), "size": src.stat().st_size}]
    (dest_dir / "zip").mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(src) as zf:
        for info in zf.infolist():
            if info.is_dir() or info.file_size > EXTRACT_MAX:
                continue
            rel = PurePosixPath(info.filename.replace("\\", "/"))
            if rel.is_absolute() or ".." in rel.parts:
                continue
            data = zf.read(info)
            out = dest_dir / "zip" / rel.as_posix()
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(data)
            atts.append({"path": f"attachments/zip/{rel.as_posix()}", "size": len(data), "sha256": sha256_bytes(data)})
    shutil.copy2(src, dest_dir / src.name)
    return atts


def copy_files(specs: list, src_dir: Path, dest_dir: Path) -> list[dict]:
    atts = []
    (dest_dir / "src").mkdir(parents=True, exist_ok=True)
    for spec in specs:
        rel_src, rel_dst = (spec["src"], spec["dst"]) if isinstance(spec, dict) else (spec, spec)
        p = src_dir / rel_src
        if not p.is_file():
            raise FileNotFoundError(p)
        data = p.read_bytes()
        out = dest_dir / "src" / rel_dst
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(data)
        atts.append({"path": f"attachments/src/{rel_dst}", "size": len(data), "sha256": sha256_bytes(data)})
    return atts


def human(n: int) -> str:
    return f"{n / 1024 / 1024:.1f} MB" if n >= 1 << 20 else f"{n / 1024:.1f} KB" if n >= 1024 else f"{n} B"


def build(mapping: dict, entry: dict, dry: bool) -> str:
    ident = entry["id"]
    dest = PROBLEMS / ident
    if dest.exists() and not dry:
        return f"[skip] {ident}"
    sections = split_wp(ROOT / mapping["wp"])
    idx = entry["wp"] - 1
    if not 0 <= idx < len(sections):
        return f"[error] {ident}: wp 序号 {entry['wp']} 越界"
    wp_title, wp_body = sections[idx]
    body, flag_hashes = redact(wp_body)
    body, md_stats = normalize_md(body)   # docx 导出丢了空行与围栏，这里补回来

    atts: list[dict] = []
    try:
        if entry.get("zip"):
            src = Path(mapping["attach_dir"]) / entry["zip"]
            if not src.is_file():
                return f"[error] {ident}: 缺附件 {src}"
            if dry:
                atts = [{"path": f"attachments/{src.name}", "size": src.stat().st_size, "sha256": sha256_file(src)}]
                with zipfile.ZipFile(src) as zf:
                    atts += [{"path": f"attachments/zip/{i.filename}", "size": i.file_size, "sha256": ""}
                             for i in zf.infolist() if not i.is_dir() and i.file_size <= EXTRACT_MAX]
            else:
                atts = copy_zip(src, dest / "attachments")
        if entry.get("files"):
            if dry:
                for spec in entry["files"]:
                    p = Path(mapping["attach_dir"]) / (spec["src"] if isinstance(spec, dict) else spec)
                    if p.is_file():
                        atts.append({"path": f"attachments/src/{(spec['dst'] if isinstance(spec, dict) else spec)}",
                                     "size": p.stat().st_size, "sha256": sha256_file(p)})
            else:
                atts += copy_files(entry["files"], Path(mapping["attach_dir"]), dest / "attachments")
    except FileNotFoundError as e:
        return f"[error] {ident}: 缺文件 {e.filename}"

    scripts: list[str] = []
    for rel in entry.get("scripts", []):
        p = Path(mapping["work_dir"]) / rel
        if not p.is_file():
            print(f"       ! 脚本不存在，跳过: {rel}")
            continue
        q = dest / "solve" / Path(rel).name
        if not dry:
            q.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(p, q)
        scripts.append(f"solve/{Path(rel).name}")

    summary = mapping.get("_desc", {}).get(entry["cid"]) or derive_summary(wp_body)
    fps = derive_fingerprints(wp_body)
    if len(fps) < 2:  # 兜底：用附件名与考点拼可反查的指纹
        names = [PurePosixPath(a["path"]).name for a in atts][:3]
        if names:
            fps.append("附件：" + "、".join(names))
        if entry.get("tags"):
            fps.append("考点：" + "、".join(entry["tags"]))
        if len(fps) < 2 and summary and summary != "（WP 未给出一句话摘要）":
            fps.append(summary[:80])
    if dry:
        return f"[plan] {ident} | wp{entry['wp']} | 附件 {len(atts)} | 脚本 {len(scripts)} | {summary[:60]}"

    (dest / "solve").mkdir(parents=True, exist_ok=True)
    meta = {
        "schema": 1, "id": ident, "title": entry["title"],
        "event": mapping["event"], "year": int(mapping["year"]),
        "category": entry["cat"], "difficulty": "hard", "status": "solved",
        "challenge_id": entry["cid"],
        "summary": summary, "tags": entry.get("tags", []), "fingerprints": fps,
        "attachments": atts, "scripts": scripts,
        "evidence": [], "environment": [], "dead_ends": [], "related": [],
        "flag_format": "FLAG{...}", "flag_sha256": sorted(set(flag_hashes)),
        "attachments_complete": bool(atts) and entry.get("complete", True),
        "sources": [{"type": "self", "note": f"队内 WP《TPCTF 2026 · Final WriteUp》第 {entry['wp']} 节；附件与脚本来自比赛工作目录"}],
    }
    (dest / "meta.yaml").write_text(yaml.safe_dump(meta, allow_unicode=True, sort_keys=False, default_flow_style=False, width=100), encoding="utf-8")

    rows = "\n".join(f"| `{a['path'].split('/', 1)[1]}` | {human(a['size'])} | `{a['sha256'][:12]}…` |" for a in atts)
    script_list = "\n".join(f"- `{s}`" for s in scripts) or "- （未归档脚本，见原始工作目录）"
    readme = f"""# {entry['title']}

> {mapping['event']} {mapping['year']} · {entry['cat']} · 挑战 ID `{entry['cid']}` · 状态 solved

## 一句话

{summary}

## 附件

| 文件 | 大小 | sha256 |
| --- | --- | --- |
{rows if rows else "| （本题无附件） | | |"}

## 分析与利用

{body}

## 结果

- flag sha256：{", ".join(f"`{h}`" for h in sorted(set(flag_hashes))) or "（WP 未记录 flag）"}
- 明文 flag 不入库；提交记录见 `.ctf-submissions.jsonl` 或原始 WP。

## 脚本

{script_list}

## 待核实

- 本条目由 WP 第 {entry['wp']} 节《{wp_title}》与平台附件自动合成，建议人工复核 summary 与 fingerprints。
"""
    (dest / "README.md").write_text(readme, encoding="utf-8")
    return f"[ok]   {ident} | 附件 {len(atts)} | 脚本 {len(scripts)} | flag {len(set(flag_hashes))}"


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="WP + 附件 + 脚本 → 知识库条目")
    ap.add_argument("--mapping", required=True)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()
    mapping = json.loads(Path(args.mapping).read_text(encoding="utf-8"))
    mapping["_desc"] = load_platform_desc(Path(mapping["work_dir"]) / "_chal_meta.txt")
    if args.force:
        for e in mapping["entries"]:
            shutil.rmtree(PROBLEMS / e["id"], ignore_errors=True)
    print(f"[i] {len(mapping['entries'])} 条 | 附件源 {mapping['attach_dir']}")
    ok = 0
    for e in mapping["entries"]:
        msg = build(mapping, e, args.dry_run)
        print(msg)
        ok += msg.startswith(("[ok]", "[plan]", "[skip]"))
    print(f"[i] 完成 {ok}/{len(mapping['entries'])}")
    if not args.dry_run:
        print("[i] 下一步: python tools/kb.py index && python tools/kb.py validate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
