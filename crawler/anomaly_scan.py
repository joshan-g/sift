"""Third pass: look for structural anomalies across all discovered pages --
inline <style> blocks, CSS visibility/order tricks, zero-width chars,
unusually-sized pages, or any tag/attribute vocabulary we haven't seen
before (e.g. <video>, <audio>, <iframe>, <object>, <template>, custom
elements) -- anything that would indicate a page renders differently than
its raw source reads.
"""
import re
import requests
from collections import Counter

import os  # noqa: E402
# Credentials read from environment; never hardcode/commit them.
AUTH = (os.environ.get("VP_USER", ""), os.environ.get("VP_PASS", ""))
if not AUTH[0] or not AUTH[1]:
    raise SystemExit("Set VP_USER and VP_PASS env vars (challenge HTTP Basic Auth credentials).")
TIMEOUT = 20

ZERO_WIDTH = ["​", "‌", "‍", "﻿", "⁠"]
SUSPICIOUS_CSS = re.compile(r"(order\s*:|direction\s*:\s*rtl|visibility\s*:\s*hidden|display\s*:\s*none|font-size\s*:\s*0|opacity\s*:\s*0\b|text-indent\s*:\s*-)", re.I)

with open("urls_discovered.txt", encoding="utf-8") as f:
    urls = [l.strip() for l in f if l.strip()]

session = requests.Session()
session.auth = AUTH

tag_counter = Counter()
sizes = []
inline_style_pages = []
suspicious_css_pages = []
zero_width_pages = []
unusual_tags_pages = []

KNOWN_TAGS = {"html","head","meta","title","link","script","body","header","a","nav","main","h1","h2",
              "section","ul","li","p","footer","img","figure","figcaption","table","thead","tr","th",
              "tbody","td","pre","code","strong","em","ol","span","div","br","!doctype"}

for i, url in enumerate(urls):
    if not url.endswith((".html", "/", "")) or "/static/" in url:
        # only look at HTML-ish page URLs for this pass
        if not (url.rstrip("/").endswith((".html",)) or ("/static/" not in url and "." not in url.rsplit("/",1)[-1])):
            continue
    try:
        resp = session.get(url, timeout=TIMEOUT)
    except requests.RequestException:
        continue
    ctype = resp.headers.get("Content-Type", "")
    if "html" not in ctype:
        continue
    text = resp.text
    sizes.append((len(text), url))

    if "<style" in text.lower():
        inline_style_pages.append(url)

    if SUSPICIOUS_CSS.search(text):
        suspicious_css_pages.append(url)

    for zw in ZERO_WIDTH:
        if zw in text:
            zero_width_pages.append((url, repr(zw)))
            break

    tags_here = set(t.lower() for t in re.findall(r"<\s*([a-zA-Z0-9!-]+)", text))
    unusual = tags_here - KNOWN_TAGS
    if unusual:
        unusual_tags_pages.append((url, unusual))
    tag_counter.update(tags_here)

    if (i + 1) % 150 == 0:
        print(f"...{i+1}/{len(urls)}")

print("\n=== Tag vocabulary across whole site ===")
for tag, count in tag_counter.most_common():
    print(f"  {tag}: {count}")

print(f"\n=== Pages with inline <style> blocks: {len(inline_style_pages)} ===")
for u in inline_style_pages[:20]:
    print(" ", u)

print(f"\n=== Pages with suspicious CSS (order/rtl/hidden/opacity0/etc): {len(suspicious_css_pages)} ===")
for u in suspicious_css_pages[:20]:
    print(" ", u)

print(f"\n=== Pages with zero-width unicode chars: {len(zero_width_pages)} ===")
for u, zw in zero_width_pages[:20]:
    print(" ", u, zw)

print(f"\n=== Pages with unusual tags: {len(unusual_tags_pages)} ===")
for u, tags in unusual_tags_pages[:20]:
    print(" ", u, tags)

sizes.sort()
print(f"\n=== Smallest 5 pages ===")
for sz, u in sizes[:5]:
    print(" ", sz, u)
print(f"=== Largest 5 pages ===")
for sz, u in sizes[-5:]:
    print(" ", sz, u)
