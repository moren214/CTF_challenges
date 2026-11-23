#!/usr/bin/env python3
"""按映射表批量导入比赛题目。

一个比赛目录里往往是「一堆平铺的附件 + 重名文件 + 平台下载的 (1)(2) 副本」，
这个脚本用一份映射表（JSON）把它们拆成一道题一个目录：

  problems/<id>/
    meta.yaml        机器字段（含附件 sha256）
    README.md        人读题解，题面从附件里的 README 抄录
    attachments/     原始压缩包（哈希可核验）
    attachments/src/ 解包出来的源码（< EXTRACT_MAX 的成员，便于 grep）

用法:
  python tools/import_batch.py --mapping tools/mappings/2026-tpctf.json \
      --source-dir "D:/CTF practice/03_比赛/2026-TPCTF" --dry-run
  去掉 --dry-run 即写入；--force 覆盖已存在的目录。

只依赖标准库 + PyYAML。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import zipfile
from datetime import date
from pathlib import Path, PurePosixPath

import yaml

ROOT = Path(__file__).resolve().parent.parent
CFG = yaml.safe_load((ROOT / "kb.config.yaml").read_text(encoding="utf-8"))
PROBLEMS = ROOT / CFG["paths"]["problems"]
TEMPLATES = ROOT / CFG["paths"]["templates"]
EXTRACT_MAX = 256 * 1024          # 超过此大小的成员只留在 zip 里
DEFAULT_EVENT = {"event": "", "year": 0}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def decode_bytes(data: bytes) -> str:
    for enc in ("utf-8", "gbk"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", "replace")


def safe_member(name: str) -> str | None:
    p = PurePosixPath(name.replace("\\", "/"))
    if p.is_absolute() or ".." in p.parts:
        return None
    return p.as_posix()


def human(n: int) -> str:
    return f"{n / 1024 / 1024:.1f} MB" if n >= 1024 * 1024 else f"{n / 1024:.1f} KB" if n >= 1024 else f"{n} B"


def collect_zip(src: Path) -> tuple[list[dict], str]:
    """返回附件清单和题面文本。"""
    att = [{"path": f"attachments/{src.name}", "sha256": sha256_file(src), "size": src.stat().st_size}]
    statement = ""
    with zipfile.ZipFile(src) as zf:
        members = [i for i in zf.infolist() if not i.is_dir()]
        readme = next((i for i in members if Path(i.filename).name.lower().startswith("readme")), None)
        if readme:
            statement = decode_bytes(zf.read(readme))
        for i in members:
            rel = safe_member(i.filename)
            if rel is None:
                continue
            large = i.file_size > EXTRACT_MAX or i.file_size == 0
            att.append({
                "path": f"attachments/zip/{rel}",
                "size": i.file_size,
                "sha256": "" if large else hashlib.sha256(zf.read(i)).hexdigest(),
                "extract": not large,
            })
        for i in members:
            rel = safe_member(i.filename)
            if rel is None or i.file_size > EXTRACT_MAX:
                continue
            out = None  # 由调用方决定落盘
            del out, rel
    return att, statement


def write_entry(entry: dict, mapping: dict, source_dir: Path, force: bool, dry: bool) -> str:
    ident = entry["id"]
    dest = PROBLEMS / ident
    if dest.exists() and not force:
        return f"[skip] {ident} 已存在"

    attachments = []
    statement = entry.get("statement_text", "")
    rows = []
    plan_files = []

    zip_name = entry.get("zip")
    files = entry.get("files") or []
    src_zip = source_dir / zip_name if zip_name else None
    if src_zip and not src_zip.is_file():
        return f"[error] {ident}: 找不到 {src_zip}"

    if src_zip:
        attachments.append({"path": f"attachments/{src_zip.name}",
                            "sha256": sha256_file(src_zip), "size": src_zip.stat().st_size})
        with zipfile.ZipFile(src_zip) as zf:
            members = [i for i in zf.infolist() if not i.is_dir()]
            want = entry.get("statement") or ""
            target = next((i for i in members if i.filename == want), None) if want else None
            if target is None:
                target = next((i for i in members if Path(i.filename).name.lower().startswith("readme")), None)
            if target is not None:
                statement = statement or decode_bytes(zf.read(target))
            for i in members:
                rel = safe_member(i.filename)
                if rel is None:
                    continue
                keep = i.file_size <= EXTRACT_MAX
                rows.append(f"| `{rel}` | {human(i.file_size)} | {'解包' if keep else '仅存于 zip'} |")
                if keep:
                    attachments.append({"path": f"attachments/zip/{rel}", "size": i.file_size,
                                        "sha256": hashlib.sha256(zf.read(i)).hexdigest()})
                    plan_files.append((zf.read(i), rel))
    for item in files:
        src_rel = item["src"] if isinstance(item, dict) else item
        dst_rel = item["dst"] if isinstance(item, dict) else item
        p = source_dir / src_rel
        if not p.is_file():
            return f"[error] {ident}: 找不到 {p}"
        data = p.read_bytes()
        attachments.append({"path": f"attachments/src/{dst_rel}", "size": len(data),
                            "sha256": hashlib.sha256(data).hexdigest()})
        rows.append(f"| `{dst_rel}` | {human(len(data))} | 入库（散落文件） |")
        plan_files.append((data, dst_rel))
        if not statement and Path(src_rel).name.lower().startswith("readme"):
            statement = decode_bytes(data)

    if dry:
        return f"[plan] {ident}: {len(plan_files)} 个入库文件, 附件 {len(attachments)} 项"

    (dest / "attachments" / "zip").mkdir(parents=True, exist_ok=True)
    (dest / "attachments" / "src").mkdir(parents=True, exist_ok=True)
    (dest / "solve").mkdir(exist_ok=True)
    if src_zip:
        shutil.copy2(src_zip, dest / "attachments" / src_zip.name)
    for data, rel in plan_files:
        out = dest / "attachments" / ("zip" if src_zip else "src") / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(data)

    meta = {
        "schema": 1,
        "id": ident,
        "title": entry["title"],
        "event": mapping.get("event", ""),
        "year": int(mapping["year"]),
        "category": entry["category"],
        "difficulty": entry.get("difficulty", "medium"),
        "status": entry.get("status", "unsolved"),
        "summary": entry["summary"],
        "tags": entry.get("tags", []),
        "fingerprints": entry.get("fingerprints", []),
        "attachments": attachments,
        "scripts": [],
        "evidence": [],
        "environment": [],
        "dead_ends": [],
        "related": entry.get("related", []),
        "flag_format": entry.get("flag_format", ""),
        "attachments_complete": entry.get("complete", True),
        "sources": entry.get("sources") or [
            {"type": "self", "note": f"题面与附件来自 {mapping.get('event','')} {mapping['year']} 平台下载；解法待补"}
        ],
    }
    (dest / "meta.yaml").write_text(
        yaml.safe_dump(meta, allow_unicode=True, sort_keys=False, default_flow_style=False, width=100),
        encoding="utf-8")

    tpl = (TEMPLATES / "problem-README.md").read_text(encoding="utf-8")
    observations = "\n".join([
        f"附件根目录：`attachments/`（原始材料，哈希见 `meta.yaml`）",
        "",
        "| 文件 | 大小 | 入库方式 |",
        "| --- | --- | --- |",
        *rows,
    ])
    todo = [f"- 题名来源：{entry.get('title_source', 'zip 内 README')}"]
    if not entry.get("complete", True):
        todo.append("- 附件不完整：只拿到部分文件，缺配置文件/源码")
    for note in entry.get("todo", []):
        todo.append(f"- {note}")
    readme = (tpl.replace("{{TITLE}}", entry["title"])
                 .replace("{{ID}}", ident)
                 .replace("{{EVENT}}", mapping.get("event", ""))
                 .replace("{{YEAR}}", str(mapping["year"]))
                 .replace("{{CATEGORY}}", entry["category"])
                 .replace("{{DATE}}", mapping.get("solved_at") or "未解出")
                 .replace("{{OBSERVATIONS}}", observations)
                 .replace("{{ANALYSIS}}", entry.get("analysis") or "未解出。附件是平台原始材料；先读题面与 diff，再决定入口。")
                 .replace("{{COMMANDS}}", "# 待补：从干净环境跑起来的命令")
                 .replace("{{DEAD_ENDS}}", entry.get("dead_ends") or "（暂未尝试）")
                 .replace("{{TODO}}", "\n".join(todo)))
    if statement.strip():
        head, _, tail = readme.partition("## 观察与证据")
        readme = head.replace("> 原题描述、目标、flag 格式。注明来源（平台页面 / 本地题面文件）。",
                              statement.strip()) + "## 观察与证据" + tail
    (dest / "README.md").write_text(readme, encoding="utf-8")
    return f"[ok]   {ident}: {len(plan_files)} 文件, 附件 {len(attachments)} 项"


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="按映射表批量导入比赛题目")
    ap.add_argument("--mapping", required=True, help="映射表 JSON")
    ap.add_argument("--source-dir", required=True, help="比赛附件所在目录")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()

    mapping = json.loads(Path(args.mapping).read_text(encoding="utf-8"))
    source_dir = Path(args.source_dir)
    print(f"[i] 映射 {args.mapping}: {len(mapping['entries'])} 题 | 源目录 {source_dir}")
    ok = 0
    for entry in mapping["entries"]:
        msg = write_entry(entry, mapping, source_dir, args.force, args.dry_run)
        print(msg)
        ok += msg.startswith("[ok]") or msg.startswith("[plan]") or msg.startswith("[skip]")
    print(f"[i] 完成 {ok}/{len(mapping['entries'])}")
    if not args.dry_run:
        print("[i] 下一步: python tools/kb.py index && python tools/kb.py validate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
