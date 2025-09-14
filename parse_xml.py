#!/usr/bin/env python3
"""
burp_to_html_decode.py
Usage: python3 burp_to_html_decode.py <intruder_xml_file> <output_html_file>

Decodes CDATA and Base64-encoded request/response bodies when present.
Requires: beautifulsoup4
"""

import sys
import re
import base64
from bs4 import BeautifulSoup

if len(sys.argv) != 3:
    print("Usage: python3 burp_to_html_decode.py <intruder_xml_file> <output_html_file>")
    sys.exit(1)

infile = sys.argv[1]
outfile = sys.argv[2]

def is_likely_base64(s):
    # Heuristic: mostly base64 characters and length multiple of 4 (allow padding)
    s = s.strip()
    if not s:
        return False
    if len(s) < 8:
        return False
    if re.fullmatch(r'[A-Za-z0-9+/=\s\r\n]+', s) and (len(s.replace("\n","").replace("\r","")) % 4 == 0):
        # also check ratio of valid chars
        valid_chars = len(re.findall(r'[A-Za-z0-9+/=]', s))
        return (valid_chars / max(1, len(s))) > 0.9
    return False

def try_decode_base64(s):
    s_clean = re.sub(r'\s+', '', s)
    try:
        b = base64.b64decode(s_clean, validate=True)
        # try to decode to utf-8 text; if not text, return hex fallback
        try:
            return b.decode('utf-8'), 'text'
        except UnicodeDecodeError:
            return b.hex(), 'hex'
    except Exception:
        return s, 'raw'  # return original on failure

def extract_node_text(node):
    if node is None:
        return None, None
    # If node contains CDATA, BeautifulSoup will expose it as .string or with .contents
    raw = ""
    # If the node has attribute 'encoding' == 'base64', trust that
    enc_attr = node.get('encoding')
    if enc_attr and enc_attr.lower() == 'base64':
        raw = ''.join(node.strings)
        decoded, kind = try_decode_base64(raw)
        return decoded, kind

    # Otherwise, get full text including CDATA
    # node.string may be None if there are child nodes; join all text parts
    raw = ''.join(node.strings)
    # If it looks like base64, try decode
    if is_likely_base64(raw):
        decoded, kind = try_decode_base64(raw)
        return decoded, kind

    # else return raw text (strip trailing/leading whitespace)
    return raw.strip(), 'text'

# Read XML
with open(infile, 'r', encoding='utf-8', errors='ignore') as f:
    xml = f.read()

soup_xml = BeautifulSoup(xml, "xml")

# Create HTML skeleton
html_soup = BeautifulSoup("<!doctype html><html><head><meta charset='utf-8'><title>Burp Intruder Results (decoded)</title></head><body></body></html>", "html.parser")

style = html_soup.new_tag("style")
style.string = """
body{font-family:Segoe UI,Roboto,Arial;margin:18px;background:#f7f9fb;color:#111}
.container{max-width:1100px;margin:0 auto}
.entry{border:1px solid #ddd;background:#fff;padding:12px;margin:12px 0;border-radius:6px}
.hdr{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:8px;font-size:13px}
.kv{font-weight:600;color:#333}
.pre{background:#0f1724;color:#e6fffa;padding:10px;border-radius:6px;overflow:auto;font-family:monospace;font-size:13px;white-space:pre}
.req{border-left:4px solid #0b6; padding-left:8px}
.resp{border-left:4px solid #06c; padding-left:8px}
.status{font-weight:700;color:#b91c1c}
.url{color:#0b5}
.small{font-size:12px;color:#555}
.note{font-size:12px;color:#444;margin-top:6px}
.badge{display:inline-block;padding:2px 6px;border-radius:4px;background:#eee;font-size:12px;margin-left:6px}
"""
html_soup.head.append(style)

body = html_soup.body
container = html_soup.new_tag("div", **{"class":"container"})
body.append(container)

def add_entry(idx, item):
    entry = html_soup.new_tag("div", **{"class":"entry"})
    hdr = html_soup.new_tag("div", **{"class":"hdr"})
    eidx = html_soup.new_tag("div", **{"class":"kv"})
    eidx.string = f"Item #{idx}"
    hdr.append(eidx)
    pos = item.find("position")
    if pos and pos.string:
        p = html_soup.new_tag("div", **{"class":"small"})
        p.string = f"Position: {pos.string}"
        hdr.append(p)
    code = item.find("status")
    if code and code.string:
        st = html_soup.new_tag("div", **{"class":"status"})
        st.string = f"Status: {code.string}"
        hdr.append(st)
    clen = item.find("length")
    if clen and clen.string:
        cl = html_soup.new_tag("div", **{"class":"small"})
        cl.string = f"Length: {clen.string}"
        hdr.append(cl)
    entry.append(hdr)

    def add_block(title_text, node):
        if node is None:
            return
        decoded, kind = extract_node_text(node)
        block = html_soup.new_tag("div", **{"class": "req" if title_text=="Request" else "resp"})
        title = html_soup.new_tag("div", **{"class":"kv"})
        title.string = title_text
        if kind and kind != 'text':
            btag = html_soup.new_tag("span", **{"class":"badge"})
            btag.string = kind
            title.append(btag)
        block.append(title)
        pre = html_soup.new_tag("pre", **{"class":"pre"})
        # ensure string (escape handled by BeautifulSoup when converting to str)
        pre.string = decoded if decoded is not None else ''
        block.append(pre)
        entry.append(block)
        # show encoding attribute if present
        if node.get('encoding'):
            note = html_soup.new_tag("div", **{"class":"note"})
            note.string = f"Original node encoding attribute: {node.get('encoding')}"
            entry.append(note)

    add_block("Request", item.find("request"))
    add_block("Response", item.find("response"))

    host = item.find("host")
    if host and host.string:
        hdiv = html_soup.new_tag("div", **{"class":"small"})
        hdiv.string = f"Host: {host.string}"
        entry.append(hdiv)

    container.append(entry)

# Find items
items = soup_xml.find_all("item")
if not items:
    items = soup_xml.find_all("attackitem") + soup_xml.find_all("row") + soup_xml.find_all("requestitem")

if not items:
    pairs = list(zip(soup_xml.find_all("request"), soup_xml.find_all("response")))
    if pairs:
        for i, (r, s) in enumerate(pairs, 1):
            wrapper = BeautifulSoup("<item></item>", "xml").item
            wrapper.append(r)
            wrapper.append(s)
            add_entry(i, wrapper)
    else:
        msg = html_soup.new_tag("div", **{"class":"entry"})
        msg.string = "No <item> or recognizable request/response pairs found in XML."
        container.append(msg)
else:
    for i, it in enumerate(items, 1):
        add_entry(i, it)

with open(outfile, "w", encoding="utf-8") as f:
    f.write(str(html_soup))

print(f"Wrote {outfile}")
