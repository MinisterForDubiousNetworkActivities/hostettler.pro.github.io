#!/usr/bin/env python3
"""
cms.py — Static page generator for hostettler.pro CVE findings

Commands:
  build [slug]     Generate HTML for all findings (or one by slug)
  new <slug>       Create a new finding template in findings/
  list             List all findings with metadata
"""

import html as _html
import json
import re
import sys
from datetime import datetime
from pathlib import Path

BASE             = Path(__file__).resolve().parent
FINDINGS_DIR     = BASE / "findings"
PENDING_DIR      = BASE / "findings" / "pending"
POSTS_DIR        = BASE / "posts"
CVES_HTML        = BASE / "cves.html"
SITEMAP_XML      = BASE / "sitemap.xml"
RSS_CVES_XML     = BASE / "feed-cves.xml"
RSS_PUBS_XML     = BASE / "feed-publications.xml"
RSS_ALL_XML      = BASE / "feed-all.xml"
FEEDS_HTML       = BASE / "feeds.html"
BASE_URL         = "https://hostettler.pro"

TRASH_PRODUCTS = {"online-shopping-system-advanced", "event-management"}

_RSS_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" '
    'fill="currentColor" style="vertical-align:middle">'
    '<path d="M6.18 15.64a2.18 2.18 0 0 1 2.18 2.18C8.36 19.01 7.38 20 6.18 20C4.98 20 4 19.01 4 '
    '17.82a2.18 2.18 0 0 1 2.18-2.18M4 4.44A15.56 15.56 0 0 1 19.56 20h-2.83A12.73 12.73 0 0 0 4 '
    '7.27V4.44m0 5.66a9.9 9.9 0 0 1 9.9 9.9h-2.83A7.07 7.07 0 0 0 4 12.93V10.1z"/></svg>'
)

_RSS_NAV_ITEM = f'                <li><a href="/feeds.html" title="RSS Feeds" aria-label="RSS Feeds">{_RSS_SVG}</a></li>\n'

# ── SVG icons ──────────────────────────────────────────────────────────────────

_GITHUB_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" '
    'fill="currentColor" style="vertical-align:middle">'
    '<path d="M12 0C5.374 0 0 5.373 0 12c0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261'
    '.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756'
    '-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304'
    ' 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469'
    '-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23A11.509 '
    '11.509 0 0 1 12 5.803c1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23'
    '.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479'
    ' 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576C20.566 21.797 24 17.3 '
    '24 12c0-6.627-5.373-12-12-12z"/></svg>'
)

_LINKEDIN_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" '
    'fill="currentColor" style="vertical-align:middle">'
    '<path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 '
    '1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 '
    '0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433a2.062 2.062 0 0 1-2.063-2.065 2.064 2.064'
    ' 0 1 1 2.063 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0'
    ' 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 '
    '.774 23.2 0 22.222 0h.003z"/></svg>'
)

# ── Inline markdown → HTML ─────────────────────────────────────────────────────

def inline_md(text):
    """Convert inline markdown to HTML, safely escaping all plain text."""
    result = []
    i = 0
    while i < len(text):
        # Inline code `...`
        if text[i] == '`':
            j = text.find('`', i + 1)
            if j != -1:
                result.append(f'<code>{_html.escape(text[i+1:j])}</code>')
                i = j + 1
                continue
        # Link [text](url)
        if text[i] == '[':
            m = re.match(r'\[([^\]]+)\]\(([^)]+)\)', text[i:])
            if m:
                result.append(
                    f'<a href="{_html.escape(m.group(2))}">'
                    f'{_html.escape(m.group(1))}</a>'
                )
                i += len(m.group(0))
                continue
        # Bold **...**
        if text[i:i+2] == '**':
            j = text.find('**', i + 2)
            if j != -1:
                result.append(f'<strong>{_html.escape(text[i+2:j])}</strong>')
                i = j + 2
                continue
        # Unicode punctuation → named entities
        if text[i] == '—':   # em dash —
            result.append('&mdash;')
            i += 1
            continue
        if text[i] == '–':   # en dash –
            result.append('&ndash;')
            i += 1
            continue
        if text[i] == '→':   # arrow →
            result.append('&rarr;')
            i += 1
            continue
        # Everything else: escape and emit
        result.append(_html.escape(text[i]))
        i += 1
    return ''.join(result)


# ── Markdown body → HTML ───────────────────────────────────────────────────────

def md_to_html(text):
    lines  = text.split('\n')
    output = []
    state  = None   # 'p' | 'ul' | None
    buf    = []     # paragraph line buffer

    def flush():
        nonlocal state, buf
        if state == 'p' and buf:
            content = ' '.join(buf).strip()
            if content:
                output.append(f'        <p>{inline_md(content)}</p>')
            buf   = []
            state = None
        elif state == 'ul':
            output.append('        </ul>')
            state = None

    i = 0
    while i < len(lines):
        line     = lines[i]
        stripped = line.strip()

        # Fenced code block
        if stripped.startswith('```'):
            flush()
            lang = stripped[3:].strip()
            i += 1
            code_lines = []
            while i < len(lines) and not lines[i].strip().startswith('```'):
                code_lines.append(lines[i])
                i += 1
            code = '\n'.join(code_lines)
            cls  = f' class="language-{_html.escape(lang)}"' if lang else ''
            output.append(f'        <pre><code{cls}>{_html.escape(code)}</code></pre>')
            i += 1
            continue

        # Empty line — flush buffer
        if not stripped:
            flush()
            i += 1
            continue

        # H2
        if stripped.startswith('## '):
            flush()
            output.append(f'        <h2>{inline_md(stripped[3:].strip())}</h2>')
            i += 1
            continue

        # H3 → rendered as h4
        if stripped.startswith('### '):
            flush()
            output.append(f'        <h4>{inline_md(stripped[4:].strip())}</h4>')
            i += 1
            continue

        # Standalone bold line → sub-heading with > prefix
        if re.match(r'^\*\*[^*]+\*\*$', stripped):
            flush()
            inner = stripped[2:-2]
            output.append(f'        <h4>&gt; {inline_md(inner)}</h4>')
            i += 1
            continue

        # Standalone image ![caption](url)
        if stripped.startswith('!['):
            m = re.match(r'!\[([^\]]*)\]\(([^)]+)\)', stripped)
            if m:
                flush()
                alt = _html.escape(m.group(1))
                src = _html.escape(m.group(2))
                cap_html = inline_md(m.group(1))
                cap = f'\n            <figcaption>{cap_html}</figcaption>' if alt else ''
                output.append(
                    f'        <figure>\n'
                    f'            <img src="{src}" alt="{alt}">{cap}\n'
                    f'        </figure>'
                )
                i += 1
                continue

        # List item
        if stripped.startswith('- '):
            if state != 'ul':
                flush()
                output.append('        <ul>')
                state = 'ul'
            output.append(f'            <li>{inline_md(stripped[2:].strip())}</li>')
            i += 1
            continue

        # Paragraph line
        if state == 'ul':
            flush()
        state = 'p'
        buf.append(stripped)
        i += 1

    flush()
    return '\n'.join(output)


# ── Finding parser ─────────────────────────────────────────────────────────────

def parse_finding(path):
    text  = path.read_text(encoding='utf-8')
    lines = text.split('\n')
    i = 0

    # H1 title
    title = ''
    while i < len(lines):
        if lines[i].startswith('# '):
            title = lines[i][2:].strip()
            i += 1
            break
        i += 1

    # Skip blank lines before table
    while i < len(lines) and not lines[i].strip():
        i += 1

    # Metadata table
    meta = {}
    while i < len(lines) and lines[i].strip().startswith('|'):
        line = lines[i].strip()
        if re.match(r'^\|[-| :]+\|$', line):   # separator row
            i += 1
            continue
        inner = line.strip('|')
        parts = inner.split('|', 1)
        if len(parts) == 2:
            key = parts[0].strip()
            val = parts[1].strip()
            if key and key.lower() != 'field':  # skip table header row
                meta[key] = val
        i += 1

    body = '\n'.join(lines[i:])

    return {'slug': path.stem, 'title': title, 'meta': meta, 'body': body}


def all_findings():
    findings = [parse_finding(p) for p in sorted(FINDINGS_DIR.glob('*.md'))]
    def sort_key(f):
        try:
            date = datetime.strptime(f['meta'].get('Date', '').strip(), '%d/%m/%Y')
        except Exception:
            date = datetime.min
        m = re.search(r'CVE-\d+-(\d+)', f['meta'].get('CVE', ''))
        cve_seq = int(m.group(1)) if m else 0
        return (date, cve_seq)
    findings.sort(key=sort_key, reverse=True)
    return findings


def _product_slug(meta):
    raw = meta.get('Product', '')
    m = re.match(r'\[([^\]]+)\]', raw)
    return (m.group(1) if m else raw).strip().lower()


def _score_key(f):
    m = re.match(r'([\d.]+)', f['meta'].get('CVSS Score', '0').strip())
    return float(m.group(1)) if m else 0.0


def all_trash_findings():
    if not PENDING_DIR.exists():
        return []
    findings = [
        parse_finding(p)
        for p in sorted(PENDING_DIR.glob('*.md'))
        if _product_slug(parse_finding(p)['meta']) in TRASH_PRODUCTS
    ]
    findings.sort(key=_score_key, reverse=True)
    return findings


def all_undisclosed_findings():
    if not PENDING_DIR.exists():
        return []
    findings = [
        parse_finding(p)
        for p in sorted(PENDING_DIR.glob('*.md'))
        if _product_slug(parse_finding(p)['meta']) not in TRASH_PRODUCTS
    ]
    findings.sort(key=_score_key, reverse=True)
    return findings


# ── Stats ──────────────────────────────────────────────────────────────────────

def count_publications():
    pub_file = BASE / "publications.html"
    if not pub_file.exists():
        return 0
    text = pub_file.read_text(encoding='utf-8')
    links = re.findall(r'<a href="([^"]+)">', text)
    return sum(1 for l in links if l.startswith('http') and 'linkedin' not in l and 'github' not in l)


def compute_stats(findings, trash_findings, undisclosed_findings):
    all_f = findings + trash_findings + undisclosed_findings
    scores = []
    for f in all_f:
        m = re.match(r'([\d.]+)', f['meta'].get('CVSS Score', '0').strip())
        scores.append(float(m.group(1)) if m else 0.0)
    return {
        'total':       len(all_f),
        'critical':    sum(1 for s in scores if s >= 9.0),
        'high':        sum(1 for s in scores if 7.0 <= s < 9.0),
        'medium':      sum(1 for s in scores if 4.0 <= s < 7.0),
        'published':   len(findings),
        'pending':     len(undisclosed_findings),
        'trash':       len(trash_findings),
        'publications': count_publications(),
    }


def render_stats_block(stats, show_publications=True):
    t, cr, hi, me = stats['total'], stats['critical'], stats['high'], stats['medium']
    pu, pe, tr, pb = stats['published'], stats['pending'], stats['trash'], stats['publications']
    pub_label = "Publications" if pb != 1 else "Publication"
    lines = (
        f'        <p class="stat-line">'
        f'<b>{pu}</b> CVEs &nbsp;&mdash;&nbsp; '
        f'<span class="sev-critical">{cr} Critical</span> &middot; '
        f'<span class="sev-high">{hi} High</span> &middot; '
        f'<span class="sev-medium">{me} Medium</span>'
        f'</p>\n'
        f'        <p class="stat-line stat-muted">'
        f'{pu} Published &middot; {pe + tr} Pending'
        f'</p>'
    )
    if show_publications:
        lines += (
            f'\n        <p class="stat-line">'
            f'<b>{pb}</b> {pub_label}'
            f'</p>'
        )
    return lines


def inject_stats(html_path, stats_block):
    text = html_path.read_text(encoding='utf-8')
    text = re.sub(
        r'<!-- STATS_START -->.*?<!-- STATS_END -->',
        f'<!-- STATS_START -->\n{stats_block}\n        <!-- STATS_END -->',
        text, flags=re.DOTALL
    )
    html_path.write_text(text, encoding='utf-8')


# ── RSS ────────────────────────────────────────────────────────────────────────

def _rss_date(date_str):
    try:
        return datetime.strptime(date_str.strip(), '%d/%m/%Y').strftime('%a, %d %b %Y 00:00:00 +0000')
    except Exception:
        return ''


def render_rss_cves(findings):
    items = []
    for f in findings:
        title   = _html.escape(f['title'])
        link    = f'{BASE_URL}/posts/{f["slug"]}.html'
        pubdate = _rss_date(f['meta'].get('Date', ''))
        score   = f['meta'].get('CVSS Score', '')
        desc    = _html.escape(f'CVSS {score} — {re.sub(r"^CVE-[\\dX-]+ — ", "", f["title"])}')
        items.append(
            f'    <item>\n'
            f'      <title>{title}</title>\n'
            f'      <link>{link}</link>\n'
            f'      <guid>{link}</guid>\n'
            + (f'      <pubDate>{pubdate}</pubDate>\n' if pubdate else '')
            + f'      <description>{desc}</description>\n'
            f'    </item>'
        )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">\n'
        '  <channel>\n'
        '    <title>Lennart Hostettler | CVE Disclosures</title>\n'
        f'    <link>{BASE_URL}/cves.html</link>\n'
        f'    <atom:link href="{BASE_URL}/feed-cves.xml" rel="self" type="application/rss+xml"/>\n'
        '    <description>CVE disclosures by Lennart Hostettler — Security Engineer &amp; Penetration Tester</description>\n'
        '    <language>en</language>\n'
        + '\n'.join(items) + '\n'
        '  </channel>\n'
        '</rss>\n'
    )


def parse_publications():
    pub_file = BASE / "publications.html"
    if not pub_file.exists():
        return []
    text  = pub_file.read_text(encoding='utf-8')
    pubs  = []
    for m in re.finditer(r'<p>(\d{2}/\d{2}/\d{4})\s*-\s*<a href="([^"]+)">([^<]+)</a>', text):
        date, href, title = m.group(1), m.group(2), m.group(3).strip()
        if href and not title.startswith('[Coming soon]'):
            pubs.append({'date': date, 'href': href, 'title': title})
    return pubs


def render_rss_publications(pubs):
    items = []
    for p in pubs:
        title   = _html.escape(p['title'])
        link    = _html.escape(p['href'])
        pubdate = _rss_date(p['date'])
        items.append(
            f'    <item>\n'
            f'      <title>{title}</title>\n'
            f'      <link>{link}</link>\n'
            f'      <guid>{link}</guid>\n'
            + (f'      <pubDate>{pubdate}</pubDate>\n' if pubdate else '')
            + f'    </item>'
        )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">\n'
        '  <channel>\n'
        '    <title>Lennart Hostettler | Publications</title>\n'
        f'    <link>{BASE_URL}/publications.html</link>\n'
        f'    <atom:link href="{BASE_URL}/feed-publications.xml" rel="self" type="application/rss+xml"/>\n'
        '    <description>Publications and write-ups by Lennart Hostettler</description>\n'
        '    <language>en</language>\n'
        + '\n'.join(items) + '\n'
        '  </channel>\n'
        '</rss>\n'
    )


def render_rss_all(findings, pubs):
    cve_items = []
    for f in findings:
        title   = _html.escape(f['title'])
        link    = f'{BASE_URL}/posts/{f["slug"]}.html'
        pubdate = _rss_date(f['meta'].get('Date', ''))
        score   = f['meta'].get('CVSS Score', '')
        desc    = _html.escape(f'CVSS {score} — {re.sub(r"^CVE-[\\dX-]+ — ", "", f["title"])}')
        cve_items.append((pubdate, (
            f'    <item>\n'
            f'      <title>{title}</title>\n'
            f'      <link>{link}</link>\n'
            f'      <guid>{link}</guid>\n'
            + (f'      <pubDate>{pubdate}</pubDate>\n' if pubdate else '')
            + f'      <description>{desc}</description>\n'
            f'    </item>'
        )))
    pub_items = []
    for p in pubs:
        title   = _html.escape(p['title'])
        link    = _html.escape(p['href'])
        pubdate = _rss_date(p['date'])
        pub_items.append((pubdate, (
            f'    <item>\n'
            f'      <title>{title}</title>\n'
            f'      <link>{link}</link>\n'
            f'      <guid>{link}</guid>\n'
            + (f'      <pubDate>{pubdate}</pubDate>\n' if pubdate else '')
            + f'    </item>'
        )))
    all_items = sorted(cve_items + pub_items, key=lambda x: x[0], reverse=True)
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">\n'
        '  <channel>\n'
        '    <title>Lennart Hostettler | All</title>\n'
        f'    <link>{BASE_URL}/</link>\n'
        f'    <atom:link href="{BASE_URL}/feed-all.xml" rel="self" type="application/rss+xml"/>\n'
        '    <description>CVE disclosures and publications by Lennart Hostettler</description>\n'
        '    <language>en</language>\n'
        + '\n'.join(item for _, item in all_items) + '\n'
        '  </channel>\n'
        '</rss>\n'
    )


def render_feeds_html():
    feeds = [
        ('feed-all.xml',          'All',          'CVE disclosures and publications'),
        ('feed-cves.xml',         'CVEs',          'Vulnerability disclosures'),
        ('feed-publications.xml', 'Publications',  'Write-ups and research'),
    ]
    items = '\n'.join(
        f'            <p><a href="/{slug}">{label}</a> &mdash; {desc}</p>'
        for slug, label, desc in feeds
    )
    return (
        '<!DOCTYPE html>\n'
        '<html lang="en">\n'
        '<head>\n'
        '    <meta charset="UTF-8">\n'
        '    <title>Lennart Hostettler | Feeds</title>\n'
        '    <meta name="viewport" content="width=device-width, initial-scale=1.0">\n'
        f'    <link rel="alternate" type="application/rss+xml" title="All" href="{BASE_URL}/feed-all.xml">\n'
        f'    <link rel="alternate" type="application/rss+xml" title="CVEs" href="{BASE_URL}/feed-cves.xml">\n'
        f'    <link rel="alternate" type="application/rss+xml" title="Publications" href="{BASE_URL}/feed-publications.xml">\n'
        '    <link rel="icon" href="/favicon.ico">\n'
        '    <link rel="stylesheet" href="style.css">\n'
        '</head>\n'
        '<body>\n'
        '    <header>\n'
        '        <h1 id="heading">lennart.hostettler@debian:~/</h1>\n'
        '        <nav id="menu">\n'
        '            <ul>\n'
        '                <li><a href="/">Home</a></li>\n'
        '                <li><a href="/publications.html">Publications</a></li>\n'
        '                <li><a href="/cves.html">CVEs</a></li>\n'
        f'                <li><a href="https://github.com/MinisterForDubiousNetworkActivities" title="GitHub" aria-label="GitHub">{_GITHUB_SVG}</a></li>\n'
        f'                <li><a href="https://www.linkedin.com/in/lennart-hostettler-8a2680297/" title="LinkedIn" aria-label="LinkedIn">{_LINKEDIN_SVG}</a></li>\n'
        + _RSS_NAV_ITEM
        + '            </ul>\n'
        '        </nav>\n'
        '    </header>\n'
        '\n'
        '    <main>\n'
        '        <section id="feeds">\n'
        '            <h2>Feeds</h2>\n'
        f'{items}\n'
        '        </section>\n'
        '    </main>\n'
        '\n'
        '    <footer>\n'
        '        <p>Contact: <a href="mailto:lennart.hostettler@proton.me">💌 lennart.hostettler@proton.me</a></p>\n'
        '        <p><a href="/privacy.html">Privacy Policy</a></p>\n'
        '    </footer>\n'
        '</body>\n'
        '</html>\n'
    )


# ── Severity helpers ───────────────────────────────────────────────────────────

def severity_class(score_str):
    m = re.search(r'\((\w+)\)', score_str)
    return f'severity-{m.group(1).lower()}' if m else ''


def severity_label(score_str):
    m = re.match(r'([\d.]+)\s*\((\w+)\)', score_str.strip())
    return f'[CVSS {m.group(1)} {m.group(2)}]' if m else f'[CVSS {score_str}]'


def to_iso_date(date_str):
    try:
        return datetime.strptime(date_str.strip(), '%d/%m/%Y').strftime('%Y-%m-%d')
    except Exception:
        return ''


# ── Renderers ──────────────────────────────────────────────────────────────────

def render_meta_table(meta):
    rows = []
    for field, value in meta.items():
        if field == 'Date':
            continue
        if field == 'CVSS Score':
            cls      = severity_class(value)
            val_html = f'<span class="{cls}">{inline_md(value)}</span>'
        else:
            val_html = inline_md(value)
        rows.append(f'            <tr><td>{_html.escape(field)}</td><td>{val_html}</td></tr>')
    return '        <table class="meta-table">\n' + '\n'.join(rows) + '\n        </table>'


_POST_NAV = (
    '        <nav id="menu">\n'
    '            <ul>\n'
    '                <li><a href="/">Home</a></li>\n'
    '                <li><a href="/publications.html">Publications</a></li>\n'
    '                <li><a class="active" href="/cves.html">CVEs</a></li>\n'
    f'                <li><a href="https://github.com/MinisterForDubiousNetworkActivities" title="GitHub" aria-label="GitHub">{_GITHUB_SVG}</a></li>\n'
    f'                <li><a href="https://www.linkedin.com/in/lennart-hostettler-8a2680297/" title="LinkedIn" aria-label="LinkedIn">{_LINKEDIN_SVG}</a></li>\n'
    + _RSS_NAV_ITEM
    + '            </ul>\n'
    '        </nav>'
)


def render_post(f):
    slug       = f['slug']
    title      = f['title']
    meta       = f['meta']
    body       = f['body']
    date       = meta.get('Date', '')
    cve        = meta.get('CVE', 'CVE-XXXX-XXXXX')
    short      = re.sub(r'^CVE-[\dX-]+ — ', '', title)
    canonical  = f'{BASE_URL}/posts/{slug}.html'
    desc       = f'{short}. Discovered by Lennart Hostettler.'
    page_title = f'{_html.escape(cve)} | {_html.escape(short)} | Lennart Hostettler'
    iso_date   = to_iso_date(date)
    json_ld    = (
        '    <script type="application/ld+json">\n'
        + json.dumps({
            '@context': 'https://schema.org',
            '@type': 'Article',
            'headline': short,
            'datePublished': iso_date,
            'url': canonical,
            'author': {
                '@type': 'Person',
                'name': 'Lennart Hostettler',
                'url': 'https://hostettler.pro/',
            },
        }, indent=4).replace('</', '<\\/')
        + '\n    </script>\n'
    ) if iso_date else ''

    return (
        '<!DOCTYPE html>\n'
        '<html lang="en">\n'
        '<head>\n'
        f'    <meta charset="UTF-8">\n'
        f'    <title>{page_title}</title>\n'
        f'    <meta name="viewport" content="width=device-width, initial-scale=1.0">\n'
        f'    <meta name="description" content="{_html.escape(desc)}">\n'
        f'    <meta name="robots" content="index, follow">\n'
        f'\n'
        f'    <meta property="og:title" content="{_html.escape(cve + " | " + short)}">\n'
        f'    <meta property="og:description" content="{_html.escape(desc)}">\n'
        f'    <meta property="og:type" content="article">\n'
        f'    <meta property="og:url" content="{canonical}">\n'
        f'    <meta property="og:image" content="{BASE_URL}/preview-image.jpg">\n'
        f'    <meta property="og:image:width" content="1280">\n'
        f'    <meta property="og:image:height" content="853">\n'
        f'\n'
        f'    <meta name="twitter:card" content="summary_large_image">\n'
        f'    <meta name="twitter:title" content="{_html.escape(cve + " | " + short)}">\n'
        f'    <meta name="twitter:description" content="{_html.escape(desc)}">\n'
        f'    <meta name="twitter:image" content="{BASE_URL}/preview-image.jpg">\n'
        f'\n'
        f'    <link rel="canonical" href="{canonical}">\n'
        f'    <link rel="icon" href="/favicon.ico">\n'
        f'    <link rel="stylesheet" href="/style.css">\n'
        f'    <link rel="stylesheet" href="/assets/atom-one-dark.min.css">\n'
        f'\n'
        f'{json_ld}'
        f'</head>\n'
        f'<body>\n'
        f'    <header>\n'
        f'        <h1 id="heading">lennart.hostettler@debian:~/posts</h1>\n'
        f'{_POST_NAV}\n'
        f'    </header>\n'
        f'\n'
        f'    <main>\n'
        f'\n'
        f'        <p class="post-date">{_html.escape(date)} &mdash; Security Advisory</p>\n'
        f'        <h2>{inline_md(title)}</h2>\n'
        f'\n'
        f'{render_meta_table(meta)}\n'
        f'\n'
        f'{md_to_html(body)}\n'
        f'    </main>\n'
        f'\n'
        f'    <footer>\n'
        f'        <p>Contact: <a href="mailto:lennart.hostettler@proton.me">💌 lennart.hostettler@proton.me</a></p>\n'
        f'        <p><a href="/privacy.html">Privacy Policy</a></p>\n'
        f'    </footer>\n'
        f'    <script src="/assets/highlight.min.js"></script>\n'
        f'    <script>hljs.highlightAll();</script>\n'
        f'</body>\n'
        f'</html>\n'
    )


def render_cves_html(findings, trash_findings=None, undisclosed_findings=None, stats_block=None):
    entries = []
    for f in findings:
        date  = f['meta'].get('Date', '')
        score = f['meta'].get('CVSS Score', '')
        label = severity_label(score)
        href  = f'/posts/{f["slug"]}.html'
        entries.append(
            f'            <p>{_html.escape(label)} '
            f'<a href="{href}">{inline_md(f["title"])}</a></p>'
        )

    undisclosed_section = ''
    if undisclosed_findings:
        ud_entries = []
        for f in undisclosed_findings:
            score = f['meta'].get('CVSS Score', '')
            label = severity_label(score)
            short = re.sub(r'^CVE-[\dX-]+ — ', '', f['title'])
            short = re.sub(r'\s+in\s+\S+.*$', '', short, flags=re.IGNORECASE)
            ud_entries.append(
                f'            <p>Pending - {_html.escape(label)} {_html.escape(short)}</p>'
            )
        undisclosed_section = (
            '\n'
            '        <section id="undisclosed-cves">\n'
            '            <h2>Pending / Not Yet Disclosed</h2>\n'
            '            <p><em>Findings reported to vendors. Details withheld pending CVE assignment and coordinated disclosure.</em></p>\n'
            + '\n'.join(ud_entries) + '\n'
            '        </section>'
        )

    trash_section = ''
    if trash_findings:
        trash_entries = []
        for f in trash_findings:
            score = f['meta'].get('CVSS Score', '')
            label = severity_label(score)
            short = re.sub(r'^CVE-[\dX-]+ — ', '', f['title'])
            short = re.sub(r'\s+in\s+\S+.*$', '', short, flags=re.IGNORECASE)
            trash_entries.append(
                f'            <p>Pending - {_html.escape(label)} {_html.escape(short)}</p>'
            )
        trash_section = (
            '\n'
            '        <section id="trash-cves">\n'
            '            <h2>Trash CVEs</h2>\n'
            '            <p><em>Low-quality findings in low-quality projects with at least a few hundred stars. Details withheld pending CVE assignment.</em></p>\n'
            + '\n'.join(trash_entries) + '\n'
            '        </section>'
        )

    return (
        '<!DOCTYPE html>\n'
        '<html lang="en">\n'
        '<head>\n'
        '    <meta charset="UTF-8">\n'
        '    <title>Lennart Hostettler | CVEs</title>\n'
        '    <meta name="viewport" content="width=device-width, initial-scale=1.0">\n'
        '    <meta name="description" content="CVEs discovered by Lennart Hostettler &ndash; Security Engineer &amp; Penetration Tester from Germany.">\n'
        '    <meta name="robots" content="index, follow">\n'
        '\n'
        '    <meta property="og:title" content="Lennart Hostettler | CVEs">\n'
        '    <meta property="og:description" content="CVEs discovered by Lennart Hostettler &ndash; Security Engineer &amp; Penetration Tester from Germany.">\n'
        '    <meta property="og:type" content="website">\n'
        f'    <meta property="og:url" content="{BASE_URL}/cves.html">\n'
        f'    <meta property="og:image" content="{BASE_URL}/preview-image.jpg">\n'
        '    <meta property="og:image:width" content="1280">\n'
        '    <meta property="og:image:height" content="853">\n'
        '\n'
        '    <meta name="twitter:card" content="summary_large_image">\n'
        '    <meta name="twitter:title" content="Lennart Hostettler | CVEs">\n'
        '    <meta name="twitter:description" content="CVEs discovered by Lennart Hostettler &ndash; Security Engineer &amp; Penetration Tester from Germany.">\n'
        f'    <meta name="twitter:image" content="{BASE_URL}/preview-image.jpg">\n'
        '\n'
        f'    <link rel="canonical" href="{BASE_URL}/cves.html">\n'
        f'    <link rel="alternate" type="application/rss+xml" title="All" href="{BASE_URL}/feed-all.xml">\n'
        f'    <link rel="alternate" type="application/rss+xml" title="CVE Disclosures" href="{BASE_URL}/feed-cves.xml">\n'
        '    <link rel="icon" href="/favicon.ico">\n'
        '    <link rel="stylesheet" href="style.css">\n'
        '</head>\n'
        '<body>\n'
        '    <header>\n'
        '        <h1 id="heading">lennart.hostettler@debian:~/</h1>\n'
        '        <nav id="menu">\n'
        '            <ul>\n'
        '                <li><a href="/">Home</a></li>\n'
        '                <li><a href="/publications.html">Publications</a></li>\n'
        '                <li><a class="active" href="/cves.html">CVEs</a></li>\n'
        f'                <li><a href="https://github.com/MinisterForDubiousNetworkActivities" title="GitHub" aria-label="GitHub">{_GITHUB_SVG}</a></li>\n'
        f'                <li><a href="https://www.linkedin.com/in/lennart-hostettler-8a2680297/" title="LinkedIn" aria-label="LinkedIn">{_LINKEDIN_SVG}</a></li>\n'
        + _RSS_NAV_ITEM
        + '            </ul>\n'
        '        </nav>\n'
        '        <span id="subheading">\n'
        '            <strong>Security Engineer &amp; Penetration Tester from Germany</strong><br><br>\n'
        '            I don\'t hate Bill Gates because he\'s a reptilian lizard injecting 5G chips from the hollow earth &mdash; I hate him because he invented Windows.\n'
        + (f'            <br><br>\n{stats_block}\n' if stats_block else '')
        + '        </span>\n'
        '    </header>\n'
        '\n'
        '    <main>\n'
        '        <section id="cves">\n'
        '            <h2>CVEs</h2>\n'
        + '\n'.join(entries) + '\n'
        '        </section>\n'
        + trash_section + '\n'
        + undisclosed_section + '\n'
        '    </main>\n'
        '\n'
        '    <footer>\n'
        '        <p>Contact: <a href="mailto:lennart.hostettler@proton.me">💌 lennart.hostettler@proton.me</a></p>\n'
        '        <p><a href="/privacy.html">Privacy Policy</a></p>\n'
        '    </footer>\n'
        '</body>\n'
        '</html>\n'
    )


def render_sitemap(findings):
    static = [
        ('/',                       '1.0', 'monthly'),
        ('/publications.html',      '0.8', 'monthly'),
        ('/cves.html',              '0.8', 'monthly'),
        ('/feeds.html',             '0.3', 'yearly'),
        ('/feed-all.xml',           '0.5', 'weekly'),
        ('/feed-cves.xml',          '0.5', 'weekly'),
        ('/feed-publications.xml',  '0.5', 'monthly'),
        ('/privacy.html',           '0.3', 'yearly'),
    ]
    blocks = []
    for loc, prio, freq in static:
        blocks.append(
            f'  <url>\n'
            f'    <loc>{BASE_URL}{loc}</loc>\n'
            f'    <changefreq>{freq}</changefreq>\n'
            f'    <priority>{prio}</priority>\n'
            f'  </url>'
        )
    for f in sorted(findings, key=lambda x: x['slug']):
        iso_date  = to_iso_date(f['meta'].get('Date', ''))
        lastmod   = f'\n    <lastmod>{iso_date}</lastmod>' if iso_date else ''
        blocks.append(
            f'  <url>\n'
            f'    <loc>{BASE_URL}/posts/{f["slug"]}.html</loc>{lastmod}\n'
            f'    <changefreq>never</changefreq>\n'
            f'    <priority>0.7</priority>\n'
            f'  </url>'
        )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset\n'
        '      xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"\n'
        '      xmlns:xhtml="http://www.w3.org/1999/xhtml">\n\n'
        + '\n\n'.join(blocks) +
        '\n\n</urlset>\n'
    )


# ── New finding template ───────────────────────────────────────────────────────

_TEMPLATE = """\
# CVE-XXXX-XXXXX — [Title]

| Field            | Value                                            |
|------------------|--------------------------------------------------|
| Product          | [Product Name](https://github.com/...)           |
| Version          | All versions                                     |
| File             | `file.php`                                       |
| CVE              | CVE-XXXX-XXXXX (pending)                         |
| CWE              | CWE-XX — [CWE Title]                             |
| CVSS 3.1 Vector  | AV:?/AC:?/PR:?/UI:?/S:?/C:?/I:?/A:?             |
| CVSS Score       | X.X (Severity)                                   |
| Auth Required    | No                                               |
| Discovered by    | Lennart Hostettler                               |
| Date             | {date}                                           |

## Description

...

## Proof of Concept

**Step 1 — ...**

```http
GET /...
```

## Impact

- ...

## Remediation

```php
// fixed code
```
"""

# ── CLI commands ───────────────────────────────────────────────────────────────

def cmd_build(args):
    POSTS_DIR.mkdir(exist_ok=True)

    if args:
        slug = args[0].removesuffix('.md')
        path = FINDINGS_DIR / f'{slug}.md'
        if not path.exists():
            print(f'error: findings/{slug}.md not found', file=sys.stderr)
            sys.exit(1)
        targets = [parse_finding(path)]
    else:
        targets = all_findings()

    for f in targets:
        out = POSTS_DIR / f'{f["slug"]}.html'
        out.write_text(render_post(f), encoding='utf-8')
        print(f'  built  posts/{f["slug"]}.html')

    # Always rebuild index + sitemap from all findings
    all_f           = all_findings()
    all_trash       = all_trash_findings()
    all_undisclosed = all_undisclosed_findings()
    stats            = compute_stats(all_f, all_trash, all_undisclosed)
    cve_stats_block  = render_stats_block(stats, show_publications=False)
    idx_stats_block  = render_stats_block(stats, show_publications=True)
    CVES_HTML.write_text(render_cves_html(all_f, all_trash, all_undisclosed, cve_stats_block), encoding='utf-8')
    print('  built  cves.html')
    inject_stats(BASE / 'index.html', idx_stats_block)
    print('  built  index.html (stats)')
    SITEMAP_XML.write_text(render_sitemap(all_f), encoding='utf-8')
    print('  built  sitemap.xml')
    pubs = parse_publications()
    RSS_CVES_XML.write_text(render_rss_cves(all_f), encoding='utf-8')
    print('  built  feed-cves.xml')
    RSS_PUBS_XML.write_text(render_rss_publications(pubs), encoding='utf-8')
    print('  built  feed-publications.xml')
    RSS_ALL_XML.write_text(render_rss_all(all_f, pubs), encoding='utf-8')
    print('  built  feed-all.xml')
    FEEDS_HTML.write_text(render_feeds_html(), encoding='utf-8')
    print('  built  feeds.html')


def cmd_new(args):
    if not args:
        print('usage: cms.py new <slug>', file=sys.stderr)
        sys.exit(1)
    slug = args[0].removesuffix('.md')
    path = FINDINGS_DIR / f'{slug}.md'
    if path.exists():
        print(f'error: findings/{slug}.md already exists', file=sys.stderr)
        sys.exit(1)
    FINDINGS_DIR.mkdir(exist_ok=True)
    today = datetime.now().strftime('%d/%m/%Y')
    path.write_text(_TEMPLATE.replace('{date}', today), encoding='utf-8')
    print(f'  created findings/{slug}.md')


def cmd_list(args):
    findings = all_findings()
    if not findings:
        print('no findings in findings/')
        return
    w = max(len(f['slug']) for f in findings)
    header = f'  {"slug":<{w}}  {"date":<10}  {"cvss":<4}  {"severity":<8}  title'
    print(header)
    print('  ' + '-' * (w + 44))
    for f in findings:
        meta  = f['meta']
        date  = meta.get('Date', '—')
        score_str = meta.get('CVSS Score', '—')
        m     = re.match(r'([\d.]+)\s*\((\w+)\)', score_str.strip())
        score = m.group(1) if m else '—'
        sev   = m.group(2) if m else '—'
        short = re.sub(r'^CVE-[\dX-]+ — ', '', f['title'])
        print(f'  {f["slug"]:<{w}}  {date:<10}  {score:<4}  {sev:<8}  {short}')


# ── Entry point ────────────────────────────────────────────────────────────────

COMMANDS = {'build': cmd_build, 'new': cmd_new, 'list': cmd_list}

def main():
    args = sys.argv[1:]
    if not args or args[0] not in COMMANDS:
        print(__doc__)
        sys.exit(0 if not args else 1)
    COMMANDS[args[0]](args[1:])

if __name__ == '__main__':
    main()
