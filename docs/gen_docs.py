#!/usr/bin/env python3
# Render the NebulaSentinel markdown manuals to HTML using the styling from
# /nebulasentinel/formatting/docs_template.html (exact CSS reused).
import re, os, html as _html

SRC = os.path.dirname(os.path.abspath(__file__)) + "/src"
OUT = "/nebulasentinel/docs/html"
TPL = "/nebulasentinel/formatting/docs_template.html"

# ── Page registry: (source rel path, output html, nav label, section, doc-meta)
PAGES = [
    ("00_INDEX.md",                       "00_INDEX.html",                       "System Overview",              "Overview", "Overview"),
    ("01_architecture.md",                "01_architecture.html",                "Architecture & Data Flow",     "Overview", "Architecture"),
    ("agent/01_core_config.md",           "agent__01_core_config.html",          "Core & Configuration",         "Agent",    "nebula-agent"),
    ("agent/02_detection_behavioral.md",  "agent__02_detection_behavioral.html", "Detection — Behavioral",       "Agent",    "nebula-agent"),
    ("agent/03_detection_content_rules.md","agent__03_detection_content_rules.html","Detection — Files & Rules",  "Agent",    "nebula-agent"),
    ("agent/04_network.md",               "agent__04_network.html",              "Network Defense",              "Agent",    "nebula-agent"),
    ("agent/05_response_posture.md",      "agent__05_response_posture.html",     "Response, Posture & Hardening","Agent",    "nebula-agent"),
    ("agent/06_collection_forensics.md",  "agent__06_collection_forensics.html", "Collection & Forensics",       "Agent",    "nebula-agent"),
    ("agent/07_llm_gossip.md",            "agent__07_llm_gossip.html",           "Embedded LLM & GOSSIP",        "Agent",    "nebula-agent"),
    ("agent/08_windows.md",               "agent__08_windows.html",              "Windows Platform Support",     "Agent",    "sentinel-v2"),
    ("nexus/01_api_auth.md",              "nexus__01_api_auth.html",             "Core, API & Auth",             "Nexus",    "nexus-server"),
    ("nexus/02_intel_rules.md",           "nexus__02_intel_rules.html",          "Intel, Rules & Synthesis",     "Nexus",    "nexus-server"),
    ("nexus/03_compliance_reporting.md",  "nexus__03_compliance_reporting.html", "Compliance & Reporting",       "Nexus",    "nexus-server"),
    ("gossip/01_protocol.md",             "gossip__01_protocol.html",            "GOSSIP Protocol & Signing",    "Gossip",   "nebula-gossip"),
    ("90_SECURITY_MODEL.md",              "90_SECURITY_MODEL.html",              "Security Model",               "Security", "Security"),
    ("91_CONFIGURATION.md",               "91_CONFIGURATION.html",               "Configuration & Deployment",   "Operations","Operations"),
]

def slug(text):
    t = re.sub(r'`', '', text.lower())
    t = re.sub(r'[^\w\s-]', '', t)
    t = re.sub(r'\s+', '-', t.strip())
    return t

def map_link(url):
    anchor = ''
    if '#' in url:
        url, a = url.split('#', 1); anchor = '#' + a
    u = url
    if u.endswith('.md') or '.md#' in url:
        while u.startswith('../'): u = u[3:]
        while u.startswith('./'):  u = u[2:]
        u = u.lstrip('/')
        u = u.replace('/', '__')
        if u.endswith('.md'): u = u[:-3] + '.html'
        return u + anchor
    return url + anchor

def esc(t):
    return t.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')

def inline(text):
    # 1. Stash inline-code spans as placeholders so emphasis can span across them
    #    (e.g. **word `code`**) and their contents aren't treated as markdown.
    codes = []
    def stash(m):
        codes.append(esc(m.group(1)))
        return f'\x00{len(codes)-1}\x00'
    tmp = re.sub(r'`([^`]+)`', stash, text)
    # 2. Escape the remaining prose
    tmp = esc(tmp)
    # 3. Links, then bold, then italic
    tmp = re.sub(r'\[([^\]]+)\]\(([^)]+)\)',
                 lambda m: f'<a href="{map_link(m.group(2))}">{m.group(1)}</a>', tmp)
    tmp = re.sub(r'\*\*([^*]+?)\*\*', r'<strong>\1</strong>', tmp)
    tmp = re.sub(r'(?<!\*)\*([^*]+?)\*(?!\*)', r'<em>\1</em>', tmp)
    # 4. Restore code spans
    tmp = re.sub(r'\x00(\d+)\x00', lambda m: '<code>' + codes[int(m.group(1))] + '</code>', tmp)
    return tmp

def is_block_start(line, lines, i):
    if re.match(r'^#{1,6}\s', line): return True
    s = line.lstrip()
    if s.startswith('```') or s.startswith('>'): return True
    if re.match(r'^\s*([-*+]|\d+\.)\s+', line): return True
    if re.match(r'^\s*-{3,}\s*$', line): return True
    if '|' in line and i + 1 < len(lines) and re.match(r'^\s*\|?[\s:|-]*-{2,}[\s:|-]*\|', lines[i+1]):
        return True
    return False

def render_table(header, rows):
    def cells(row):
        r = row.strip()
        if r.startswith('|'): r = r[1:]
        if r.endswith('|'): r = r[:-1]
        return [c.strip() for c in r.split('|')]
    head = cells(header)
    h = ['<table>', '<thead><tr>'] + [f'<th>{inline(c)}</th>' for c in head] + ['</tr></thead>', '<tbody>']
    for row in rows:
        cs = cells(row)
        cs += [''] * (len(head) - len(cs))
        h.append('<tr>' + ''.join(f'<td>{inline(c)}</td>' for c in cs[:len(head)]) + '</tr>')
    h.append('</tbody></table>')
    return ''.join(h)

def render_list(block):
    items = []
    for l in block:
        m = re.match(r'^(\s*)([-*+]|\d+\.)\s+(.*)$', l)
        if m:
            indent = len(m.group(1).replace('\t', '  '))
            typ = 'ol' if re.match(r'\d+\.', m.group(2)) else 'ul'
            items.append([indent, typ, m.group(3)])
        elif items:
            items[-1][2] += ' ' + l.strip()
    if not items: return ''
    def build(idx, cur):
        typ = items[idx][1]
        lis = []
        while idx < len(items) and items[idx][0] >= cur:
            ind, _t, txt = items[idx]
            if ind > cur:
                nested, idx = build(idx, ind)
                if lis: lis[-1] = lis[-1][:-5] + nested + '</li>'
                continue
            lis.append('<li>' + inline(txt) + '</li>')
            idx += 1
        return f'<{typ}>' + ''.join(lis) + f'</{typ}>', idx
    html_out, _ = build(0, items[0][0])
    return html_out

def convert(md):
    lines = md.split('\n')
    i, n, out = 0, len(md.split('\n')), []
    while i < n:
        line = lines[i]
        s = line.lstrip()
        if s.startswith('```'):
            i += 1; buf = []
            while i < n and not lines[i].lstrip().startswith('```'):
                buf.append(lines[i]); i += 1
            i += 1
            out.append('<pre><code>' + esc('\n'.join(buf)) + '</code></pre>'); continue
        if line.strip() == '':
            i += 1; continue
        m = re.match(r'^(#{1,6})\s+(.*)$', line)
        if m:
            lv = len(m.group(1)); txt = m.group(2).strip()
            out.append(f'<h{lv} id="{slug(txt)}">{inline(txt)}</h{lv}>'); i += 1; continue
        if re.match(r'^\s*-{3,}\s*$', line):
            out.append('<hr />'); i += 1; continue
        if '|' in line and i + 1 < n and re.match(r'^\s*\|?[\s:|-]*-{2,}[\s:|-]*\|', lines[i+1]):
            header = line; i += 2; rows = []
            while i < n and '|' in lines[i] and lines[i].strip() != '':
                rows.append(lines[i]); i += 1
            out.append(render_table(header, rows)); continue
        if s.startswith('>'):
            buf = []
            while i < n and lines[i].lstrip().startswith('>'):
                buf.append(re.sub(r'^\s*>\s?', '', lines[i])); i += 1
            out.append('<blockquote>' + convert('\n'.join(buf)) + '</blockquote>'); continue
        if re.match(r'^\s*([-*+]|\d+\.)\s+', line):
            block = []
            while i < n and lines[i].strip() != '' and (
                    re.match(r'^\s*([-*+]|\d+\.)\s+', lines[i]) or lines[i].startswith(('  ', '\t'))):
                block.append(lines[i]); i += 1
            out.append(render_list(block)); continue
        buf = [line]; i += 1
        while i < n and lines[i].strip() != '' and not is_block_start(lines[i], lines, i):
            buf.append(lines[i]); i += 1
        out.append('<p>' + inline(' '.join(x.strip() for x in buf)) + '</p>')
    return '\n'.join(out)

# ── Shell (CSS reused verbatim from the template) ────────────────
with open(TPL, encoding='utf-8') as f:
    tpl = f.read()
CSS = re.search(r'<style>(.*?)</style>', tpl, re.S).group(1)

SECTIONS = ["Overview", "Agent", "Nexus", "Gossip", "Security", "Operations"]
def sidebar(active):
    parts = ['<aside class="side">',
             '<div class="brand"><div class="logo">Nebula<span>Sentinel</span></div>',
             '<div class="sub">Technical Documentation</div></div>', '<nav>']
    for sec in SECTIONS:
        parts.append(f'<div class="navsec">{sec}</div>')
        for src, htmlf, label, section, meta in PAGES:
            if section != sec: continue
            cls = "navitem active" if htmlf == active else "navitem"
            parts.append(f'<a class="{cls}" href="{htmlf}">{_html.escape(label)}</a>')
    parts.append('</nav></aside>')
    return ''.join(parts)

def page(title, meta, active, body):
    return f"""<!DOCTYPE html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_html.escape(title)} — Nebula Sentinel Docs</title>
<style>{CSS}</style></head><body>
<div class="topbar"><button class="menu-btn" onclick="document.querySelector('.side').classList.toggle('open')">☰ Menu</button>
<strong>{_html.escape(title)}</strong></div>
<div class="layout">
{sidebar(active)}
<main class="content">
  <div class="doc-meta">{_html.escape(meta)}</div>
{body}
  <div class="footer">Nebula Sentinel — source-level technical documentation · fix release 2026-08-07.</div>
</main>
</div></body></html>"""

os.makedirs(OUT, exist_ok=True)
count = 0
for src, htmlf, label, section, meta in PAGES:
    with open(os.path.join(SRC, src), encoding='utf-8') as f:
        md = f.read()
    body = convert(md)
    with open(os.path.join(OUT, htmlf), 'w', encoding='utf-8') as f:
        f.write(page(label, meta, htmlf, body))
    count += 1
# Convenience: index.html → the overview page
with open(os.path.join(OUT, 'index.html'), 'w', encoding='utf-8') as f:
    with open(os.path.join(OUT, '00_INDEX.html'), encoding='utf-8') as g:
        f.write(g.read())
print(f"rendered {count} pages + index.html into {OUT}")
