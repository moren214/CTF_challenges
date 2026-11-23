#!/usr/bin/env python3
"""把题库渲染成一个本地只读网页（单文件，双击即看）。

    python tools/build_view.py             # -> view/index.html
    python tools/build_view.py --out x.html

只用标准库：自带的 markdown 子集渲染器够覆盖本项目 README 的写法
（标题/段落/表格/代码块/列表/引用/加粗/行内代码/链接）。
"""

from __future__ import annotations

import argparse
import html
import json
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
CFG = yaml.safe_load((ROOT / "kb.config.yaml").read_text(encoding="utf-8"))
PROBLEMS = ROOT / CFG["paths"]["problems"]


# ---------- markdown 子集 ----------

def inline(text: str) -> str:
    s = html.escape(text, quote=False)
    s = re.sub(r"`([^`\n]+)`", r"<code>\1</code>", s)
    s = re.sub(r"\*\*([^*\n]+)\*\*", r"<strong>\1</strong>", s)
    s = re.sub(r"\[([^\]\n]+)\]\(([^)\s]+)\)", r'<a href="\2">\1</a>', s)
    return s


def render_table(rows: list[str]) -> str:
    cells = [[c.strip() for c in r.strip().strip("|").split("|")] for r in rows]
    head, body = cells[0], cells[2:]
    out = ["<table><thead><tr>"]
    out += [f"<th>{inline(c)}</th>" for c in head]
    out.append("</tr></thead><tbody>")
    for row in body:
        out.append("<tr>" + "".join(f"<td>{inline(c)}</td>" for c in row) + "</tr>")
    out.append("</tbody></table>")
    return "".join(out)


from normalize_md import STEP_RE as _STEP, is_code_line  # 与批量导入共用同一套判定


def render_para(buf: list[str]) -> str:
    """段落：代码行成块、步骤标题加粗、普通行保留换行（WP 的软换行是作者本意）。"""
    out: list[str] = []
    i = 0
    while i < len(buf):
        code = is_code_line(buf[i])
        j = i
        while j < len(buf) and is_code_line(buf[j]) == code:
            j += 1
        seg = buf[i:j]
        if code:
            out.append("<pre><code>" + html.escape("\n".join(x.rstrip() for x in seg)) + "</code></pre>")
        else:
            parts = []
            for x in seg:
                x = x.strip()
                if _STEP.match(x) and not re.search(r"[=();{}\[\]]", x):
                    parts.append(f'<span class="step">{inline(x)}</span>')
                else:
                    parts.append(inline(x))
            out.append("<p>" + "<br>".join(parts) + "</p>")
        i = j
    return "\n".join(out)


def md2html(md: str) -> str:
    lines = md.replace("\r\n", "\n").split("\n")
    out: list[str] = []
    i = 0
    while i < len(lines):
        ln = lines[i]
        s = ln.strip()

        if s.startswith("```"):
            i += 1
            buf = []
            while i < len(lines) and not lines[i].strip().startswith("```"):
                buf.append(lines[i])
                i += 1
            i += 1
            out.append("<pre><code>" + html.escape("\n".join(buf)) + "</code></pre>")
            continue

        if not s:
            i += 1
            continue

        # 缩进 4 空格的代码块（WP 里的 shell 片段常这么排）
        if ln.startswith("    "):
            buf = []
            while i < len(lines) and (lines[i].startswith("    ") or not lines[i].strip()):
                buf.append(lines[i][4:] if lines[i].startswith("    ") else "")
                i += 1
            while buf and not buf[-1].strip():
                buf.pop()
            out.append("<pre><code>" + html.escape("\n".join(buf)) + "</code></pre>")
            continue

        m = re.match(r"^(#{1,6})\s+(.*)$", s)
        if m:
            lvl = len(m.group(1))
            out.append(f"<h{lvl}>{inline(m.group(2))}</h{lvl}>")
            i += 1
            continue

        if s.startswith("|") and i + 1 < len(lines) and re.match(r"^\|[\s:|-]+\|$", lines[i + 1].strip()):
            rows = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                rows.append(lines[i])
                i += 1
            out.append(render_table(rows))
            continue

        if re.match(r"^[-*]\s+", s):
            items = []
            while i < len(lines) and re.match(r"^[-*]\s+", lines[i].strip()):
                items.append(lines[i].strip()[2:])
                i += 1
            out.append("<ul>" + "".join(f"<li>{inline(x)}</li>" for x in items) + "</ul>")
            continue

        if re.match(r"^\d+\.\s+", s):
            items = []
            while i < len(lines) and re.match(r"^\d+\.\s+", lines[i].strip()):
                items.append(re.sub(r"^\d+\.\s+", "", lines[i].strip()))
                i += 1
            out.append("<ol>" + "".join(f"<li>{inline(x)}</li>" for x in items) + "</ol>")
            continue

        if s.startswith(">"):
            buf = []
            while i < len(lines) and lines[i].strip().startswith(">"):
                buf.append(lines[i].strip()[1:].strip())
                i += 1
            out.append("<blockquote>" + inline(" ".join(buf)) + "</blockquote>")
            continue

        if re.fullmatch(r"-{3,}|\*{3,}", s):
            out.append("<hr>")
            i += 1
            continue

        buf = []
        while i < len(lines) and lines[i].strip() and not re.match(
                r"^(#{1,6}\s|```|\||[-*]\s|\d+\.\s|>)", lines[i].strip()):
            buf.append(lines[i].rstrip())      # 保留缩进，代码块要靠它对齐
            i += 1
        if not buf:            # 落到兜底分支时必须前进，否则死循环
            buf = [s]
            i += 1
        out.append(render_para(buf))

    return "\n".join(out)


# ---------- 数据 ----------

def collect() -> list[dict]:
    items = []
    if not PROBLEMS.is_dir():
        return items
    for d in sorted(PROBLEMS.iterdir(), reverse=True):
        meta_p = d / "meta.yaml"
        if not meta_p.is_file():
            continue
        meta = yaml.safe_load(meta_p.read_text(encoding="utf-8")) or {}
        readme = d / "README.md"
        md = readme.read_text(encoding="utf-8") if readme.is_file() else ""
        atts = []
        for a in meta.get("attachments") or []:
            p = str(a.get("path") or "")
            atts.append({"path": p, "size": a.get("size") or 0,
                         "href": f"../problems/{d.name}/{p}" if p else ""})
        items.append({
            "id": d.name,
            "title": meta.get("title") or d.name,
            "category": meta.get("category") or "other",
            "difficulty": meta.get("difficulty") or "",
            "status": meta.get("status") or "",
            "event": meta.get("event") or "",
            "year": meta.get("year") or "",
            "summary": meta.get("summary") or "",
            "tags": meta.get("tags") or [],
            "fingerprints": meta.get("fingerprints") or [],
            "attachments": atts,
            "scripts": meta.get("scripts") or [],
            "html": md2html(md),
            "text": re.sub(r"\s+", " ", md).lower(),
        })
    return items


def build_html(items: list[dict]) -> str:
    data = json.dumps(items, ensure_ascii=False).replace("</", "<\\/")
    cats = sorted({it["category"] for it in items})
    chips = "".join(
        f'<button class="chip" data-cat="{html.escape(c)}">{html.escape(c)}</button>' for c in cats)
    return f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CTF 知识库</title>
<style>
:root{{--bg:#0f1115;--panel:#171a21;--line:#262b36;--fg:#d7dce5;--dim:#8b94a7;--acc:#4da3ff}}
*{{box-sizing:border-box}}
body{{margin:0;font:14px/1.65 -apple-system,"Segoe UI","Microsoft YaHei",sans-serif;background:var(--bg);color:var(--fg);display:flex;height:100vh;overflow:hidden}}
#side{{width:330px;flex:0 0 330px;background:var(--panel);border-right:1px solid var(--line);display:flex;flex-direction:column}}
#side h1{{font-size:15px;margin:0;padding:14px 16px 8px;letter-spacing:.5px}}
#q{{margin:0 12px 8px;padding:8px 10px;background:#0d0f14;border:1px solid var(--line);border-radius:8px;color:var(--fg);outline:none}}
#q:focus{{border-color:var(--acc)}}
.chips{{display:flex;gap:6px;flex-wrap:wrap;padding:0 12px 8px}}
.chip{{font-size:12px;padding:2px 9px;border-radius:99px;border:1px solid var(--line);background:transparent;color:var(--dim);cursor:pointer}}
.chip.on{{border-color:var(--acc);color:var(--acc)}}
#list{{overflow:auto;flex:1;padding:0 8px 12px}}
.item{{padding:8px 10px;border-radius:8px;cursor:pointer;border:1px solid transparent}}
.item:hover{{background:#1d222c}}
.item.on{{background:#1d2432;border-color:#2f4a6f}}
.item .t{{font-weight:600;font-size:13px}}
.item .m{{color:var(--dim);font-size:12px;margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
.tag{{display:inline-block;font-size:11px;color:#8fc6ff;background:#1b2a3d;border-radius:4px;padding:0 5px;margin:3px 4px 0 0}}
#main{{flex:1;overflow:auto;padding:24px 32px 80px}}
#meta{{color:var(--dim);font-size:12px;border-bottom:1px solid var(--line);padding-bottom:10px;margin-bottom:18px}}
#meta b{{color:var(--fg)}}
h1,h2,h3{{line-height:1.3}}
h1{{font-size:24px;margin:.2em 0 .6em}} h2{{font-size:18px;margin-top:1.6em;border-left:3px solid var(--acc);padding-left:9px}}
h3{{font-size:15px;margin-top:1.3em;color:#c9d3e2}}
a{{color:var(--acc);text-decoration:none}} a:hover{{text-decoration:underline}}
code{{background:#1b2130;border-radius:4px;padding:1px 5px;font-size:12.5px;font-family:Consolas,monospace}}
pre{{background:#10141c;border:1px solid var(--line);border-radius:8px;padding:12px;overflow:auto}}
pre code{{background:none;padding:0}}
table{{border-collapse:collapse;margin:12px 0;font-size:13px}}
th,td{{border:1px solid var(--line);padding:5px 10px;text-align:left;vertical-align:top}}
th{{background:#1b2130}}
blockquote{{margin:10px 0;padding:6px 12px;border-left:3px solid #3a4a63;color:var(--dim)}}
p{{margin:0 0 10px;line-height:1.85}}
.step{{display:block;font-weight:600;color:#9ecbff;margin:14px 0 4px}}
hr{{border:none;border-top:1px solid var(--line);margin:22px 0}}
#empty{{color:var(--dim);padding:40px 0}}
@media(max-width:760px){{body{{flex-direction:column}}#side{{width:100%;flex:0 0 45vh}}}}
</style></head><body>
<div id="side">
  <h1>CTF 知识库 <span style="color:var(--dim);font-weight:400" id="cnt"></span></h1>
  <input id="q" placeholder="搜索题名 / 标签 / 指纹 / 正文   ( / 聚焦)">
  <div class="chips">{chips}</div>
  <div id="list"></div>
</div>
<div id="main"><div id="meta"></div><div id="doc"></div></div>
<script>
const DATA = {data};
const list = document.getElementById('list'), q = document.getElementById('q');
const doc = document.getElementById('doc'), meta = document.getElementById('meta');
let cur = 0, cat = '';
document.getElementById('cnt').textContent = '(' + DATA.length + ')';

function show(i){{
  cur = i; const d = DATA[i];
  document.querySelectorAll('.item').forEach((e,j)=>e.classList.toggle('on', j===i));
  doc.innerHTML = d.html || '<p id="empty">这道题还没写题解。</p>';
  const att = d.attachments.map(a=>`<a href="${{a.href}}">${{a.path.split('/').pop()}}</a>`).join(' · ');
  const scr = d.scripts.map(s=>`<code>${{s}}</code>`).join(' ');
  meta.innerHTML = `<b>${{d.event}} ${{d.year}}</b> · ${{d.category}} · ${{d.difficulty}} · ${{d.status}} · <code>${{d.id}}</code>`
    + (att?`<div>附件：${{att}}</div>`:'') + (scr?`<div>脚本：${{scr}}</div>`:'')
    + (d.tags.length?`<div>标签：${{d.tags.map(t=>'#'+t).join(' ')}}</div>`:'');
  document.getElementById('main').scrollTop = 0;
}}

function render(){{
  const kw = q.value.trim().toLowerCase();
  const rows = DATA.map((d,i)=>({{d,i}})).filter(({{d}})=>
      (!cat || d.category===cat) &&
      (!kw || (d.title+' '+d.id+' '+d.tags.join(' ')+' '+d.fingerprints.join(' ')+' '+d.text).toLowerCase().includes(kw)));
  list.innerHTML = rows.map(({{d,i}})=>`<div class="item" data-i="${{i}}">
      <div class="t">${{d.title}}</div>
      <div class="m">${{d.category}} · ${{d.difficulty}} · ${{d.event}} ${{d.year}}</div>
      <div>${{d.tags.slice(0,4).map(t=>'<span class="tag">'+t+'</span>').join('')}}</div>
    </div>`).join('') || '<div id="empty">没有匹配的题。</div>';
  list.querySelectorAll('.item').forEach(e=>e.onclick=()=>show(+e.dataset.i));
  if (rows.length) show(rows[0].i);
}}

document.querySelectorAll('.chip').forEach(c=>c.onclick=()=>{{
  document.querySelectorAll('.chip').forEach(x=>x.classList.toggle('on', x===c));
  cat = (cat===c.dataset.cat)?'':c.dataset.cat;
  if(!cat) c.classList.remove('on');
  render();
}});
q.oninput = render;
document.addEventListener('keydown', e=>{{
  if (e.key==='/' && document.activeElement!==q){{ e.preventDefault(); q.focus(); }}
  if (e.key==='ArrowDown'||e.key==='ArrowUp'){{
    const n = DATA.length; if(!n) return;
    e.preventDefault(); show((cur + (e.key==='ArrowDown'?1:-1) + n) % n);
    document.querySelectorAll('.item')[cur]?.scrollIntoView({{block:'nearest'}});
  }}
}});
render();
</script></body></html>
"""


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="生成本地浏览页")
    ap.add_argument("--out", default="view/index.html")
    args = ap.parse_args()
    items = collect()
    out = (ROOT / args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(build_html(items), encoding="utf-8")
    print(f"[+] 已生成 {out} （{len(items)} 题，{out.stat().st_size/1024:.0f} KB）")
    print(f"[i] 双击打开: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
