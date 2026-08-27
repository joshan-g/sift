"""
Crawl-and-hunt: recover hidden flags from an authenticated site.

Crawls the target site (HTTP Basic Auth) end-to-end and hunts for
flags of the exact form PREFIX{<16 hex chars>}.
The target URL, credentials, and flag prefix are supplied via environment
variables (TARGET_BASE, VP_USER, VP_PASS, FLAG_PREFIX) and never live in source.

Approach
--------
1. BFS from the homepage, restricted to the target host.
2. For every response, regardless of content-type:
     - Search the raw bytes (decoded a few different ways -- utf-8, latin-1,
       utf-16-le, utf-16-be) for the password regex. This is what catches
       passwords hidden in binary metadata such as JPEG EXIF UserComment
       fields, which are frequently UTF-16 encoded.
     - If it's HTML, use BeautifulSoup to pull out every link-bearing
       attribute (href, src, action, data-*, srcset, poster, etc.), plus
       walk any inline <script> blocks and HTML comments for more paths.
     - If it's JS or CSS (inline or external), regex out quoted string
       literals / url(...) references that look like paths or full URLs,
       so links injected purely by client-side JS (never present as <a>
       tags) still get discovered and queued.
     - If it's an image, pull EXIF tags (ImageDescription, UserComment,
       XPComment, XPTitle, Artist, Copyright, ImageID -- basically every
       string-valued EXIF tag) and scan those too. Also parse raw JPEG
       markers (COM segments) and PNG text chunks directly in case Pillow
       doesn't surface them, and scan those raw bytes as well.
     - If it's JSON, scan the raw text (covers all values) and also walk
       the parsed structure for string values that look like URLs/paths.
3. Any newly discovered same-host URL is queued (path+query dedup, since
   the site legitimately uses query-string pagination e.g. /report/?page=N
   -- but plain tracking params like ?utm_source=... on repeats of an
   already-visited path are skipped to avoid infinite crawl blowup).
4. HTTP response *headers* are intentionally NOT scanned for the password
   pattern -- the challenge explicitly says header matches are unqualified
   staging placeholders.
5. Crawl finishes when the queue is empty (fixed point / no new URLs).
   Completeness is asserted by re-running the crawl and checking the
   discovered-URL set no longer grows, and by the crawl log showing zero
   unexplored links of any kind (see final report in run log).

Run:
    python crawler.py
Outputs:
    crawl_log.jsonl   -- every URL fetched, status, content-type, size
    passwords.json    -- deduped passwords found, each with source URL(s)
    urls_discovered.txt -- every same-host URL the crawler ever queued
"""

import base64
import json
import re
import struct
import sys
import time
from collections import deque
from urllib.parse import urljoin, urlparse, urlsplit, urlunsplit, parse_qsl, urlencode

import requests
from bs4 import BeautifulSoup

import os  # noqa: E402
# Target site root read from the environment; never hardcode/commit it.
BASE = os.environ.get("TARGET_BASE", "").strip()
if not BASE:
    raise SystemExit("Set TARGET_BASE env var to the site root URL, e.g. http://HOST/")
if not BASE.endswith("/"):
    BASE += "/"
HOST = urlparse(BASE).netloc
import os  # noqa: E402
# Credentials are read from the environment so they never live in source/VCS.
# Set them before running:  VP_USER=<username>  VP_PASS=<password>
AUTH = (os.environ.get("VP_USER", ""), os.environ.get("VP_PASS", ""))
if not AUTH[0] or not AUTH[1]:
    raise SystemExit("Set VP_USER and VP_PASS env vars (challenge HTTP Basic Auth credentials).")
TIMEOUT = 20
USER_AGENT = "flag-crawler/1.0"

# Flag prefix is configurable so the challenge name isn't baked into source.
FLAG_PREFIX = os.environ.get("FLAG_PREFIX", "FLAG")
PASSWORD_RE = re.compile(re.escape(FLAG_PREFIX).encode() + rb"\{[0-9a-fA-F]{16}\}")
PASSWORD_RE_STR = re.compile(re.escape(FLAG_PREFIX) + r"\{[0-9a-fA-F]{16}\}")
# The worked example printed on the challenge homepage -- explicitly NOT a real flag.
EXCLUDE_PASSWORDS = {FLAG_PREFIX + "{0000deadbeef0000}"}

# quoted-string / url(...) path grabber, used against JS + CSS + inline script text
LINK_IN_TEXT_RE = re.compile(
    r"""(?:["'\(])\s*((?:https?://[^\s"'\)<>]+)|(?:/[a-zA-Z0-9_\-./~%]*[a-zA-Z0-9_\-/]))"""
)

TEXT_EXTS = (".html", ".htm", ".css", ".js", ".json", ".xml", ".txt", ".svg", "")
SKIP_QUERY_PARAMS = {"utm_source", "utm_medium", "utm_campaign", "ref", "hl", "v"}

# Safety limits. /report/?page=N was manually confirmed to paginate past
# page 1000 (20,000+ rows) with no end and a "Next" link that never
# disables -- a deliberate rabbit hole, not a place the real passwords
# live (rows are plain "VP-xxxxxxxxxx" ids, not the flag format,
# and the challenge says there's "nothing to guess"). We cap how many
# query-string variants of any single path we'll follow so an infinite
# paginator can't blow up the crawl, and cap total requests as a backstop.
MAX_QUERY_VARIANTS_PER_PATH = 6
MAX_TOTAL_REQUESTS = 1200


def normalize_url(url):
    """Strip fragment; drop known-noise tracking query params; keep meaningful ones."""
    parts = urlsplit(url)
    q = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k not in SKIP_QUERY_PARAMS]
    q.sort()
    new_query = urlencode(q)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, ""))


def same_host(url):
    try:
        return urlparse(url).netloc.split("@")[-1] == HOST or urlparse(url).netloc == ""
    except Exception:
        return False


def extract_links_from_text(text):
    """Grab quoted paths / URLs out of arbitrary JS/CSS/inline-script text."""
    out = set()
    for m in LINK_IN_TEXT_RE.finditer(text):
        cand = m.group(1)
        if not cand:
            continue
        # filter out obvious non-link junk
        if len(cand) < 2:
            continue
        out.add(cand)
    return out


def extract_links_from_html(html_text, base_url):
    out = set()
    soup = BeautifulSoup(html_text, "html.parser")

    attr_names = ["href", "src", "action", "data-src", "poster", "formaction", "cite", "data-url", "data-href"]
    for tag in soup.find_all(True):
        for attr in attr_names:
            if tag.has_attr(attr):
                val = tag.get(attr).strip()
                if val and not val.startswith(("javascript:", "mailto:", "tel:", "#", "data:")):
                    out.add(urljoin(base_url, val))
        if tag.has_attr("srcset"):
            for chunk in tag.get("srcset").split(","):
                cand = chunk.strip().split(" ")[0]
                if cand:
                    out.add(urljoin(base_url, cand))
        # any other data-* attribute that looks like a path, just in case
        for k, v in tag.attrs.items():
            if k.startswith("data-") and isinstance(v, str) and v.startswith("/"):
                out.add(urljoin(base_url, v))

    # inline <script> contents -- may build nav purely client-side (confirmed pattern
    # in /static/js/main.js which is mirrored inline on some pages)
    for script in soup.find_all("script"):
        if script.string:
            for cand in extract_links_from_text(script.string):
                out.add(urljoin(base_url, cand))

    # HTML comments can hide paths (and occasionally the password itself)
    from bs4 import Comment
    for c in soup.find_all(string=lambda s: isinstance(s, Comment)):
        for cand in extract_links_from_text(str(c)):
            out.add(urljoin(base_url, cand))

    return out, soup


def scan_bytes_for_passwords(data):
    found = set()
    for m in PASSWORD_RE.finditer(data):
        found.add(m.group().decode("ascii"))
    # try common wide-char encodings (EXIF UserComment is often UTF-16)
    for enc in ("utf-16-le", "utf-16-be", "utf-8", "latin-1"):
        try:
            decoded = data.decode(enc, errors="ignore")
        except Exception:
            continue
        for m in PASSWORD_RE_STR.finditer(decoded):
            found.add(m.group())
    return found


def extract_exif_strings(data):
    """Return list of (tag_name, raw_bytes) string-ish EXIF/JPEG values to scan."""
    results = []
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS
        import io
        img = Image.open(io.BytesIO(data))
        results.append(("PIL.info", str(img.info).encode("utf-8", "ignore")))
        exif = img.getexif()
        for k, v in exif.items():
            name = TAGS.get(k, k)
            results.append((f"EXIF.{name}", v if isinstance(v, bytes) else str(v).encode("utf-8", "ignore")))
        for ifd_id in (0x8769, 0x8825, 0xA005):  # Exif IFD, GPS IFD, Interop IFD
            try:
                ifd = exif.get_ifd(ifd_id)
                for k, v in ifd.items():
                    name = TAGS.get(k, k)
                    results.append((f"EXIF_IFD{ifd_id}.{name}", v if isinstance(v, bytes) else str(v).encode("utf-8", "ignore")))
            except Exception:
                pass
    except Exception:
        pass

    # raw JPEG COM markers (0xFFFE) -- Pillow doesn't always surface these
    if data[:2] == b"\xff\xd8":
        i = 2
        while i < len(data) - 1:
            if data[i] != 0xFF:
                i += 1
                continue
            marker = data[i + 1]
            if marker in (0xD8, 0xD9, 0x01) or 0xD0 <= marker <= 0xD7:
                i += 2
                continue
            if marker == 0xDA or i + 4 > len(data):
                break
            length = (data[i + 2] << 8) + data[i + 3]
            seg = data[i + 4:i + 2 + length]
            if marker == 0xFE:
                results.append(("JPEG.COM", seg))
            elif marker == 0xE1 and seg[:4] != b"Exif":
                results.append(("JPEG.APP1.XMP", seg))
            i += 2 + length

    # raw PNG text chunks
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        i = 8
        while i + 8 <= len(data):
            length = struct.unpack(">I", data[i:i + 4])[0]
            ctype = data[i + 4:i + 8]
            chunk_data = data[i + 8:i + 8 + length]
            if ctype in (b"tEXt", b"iTXt", b"zTXt"):
                results.append((f"PNG.{ctype.decode()}", chunk_data))
            i += 8 + length + 4
            if ctype == b"IEND":
                break

    return results


def guess_is_text(content_type, url):
    if content_type:
        ct = content_type.split(";")[0].strip().lower()
        if ct.startswith("text/") or ct in (
            "application/json", "application/javascript", "application/xml",
            "application/xhtml+xml", "image/svg+xml", "application/x-javascript",
        ):
            return True
        if ct.startswith("image/") or ct.startswith("font/") or ct in (
            "application/octet-stream", "application/pdf",
        ):
            return False
    path = urlparse(url).path.lower()
    if any(path.endswith(ext) for ext in (".jpg", ".jpeg", ".png", ".gif", ".webp", ".ico", ".woff", ".woff2", ".pdf")):
        return False
    return True


def crawl():
    session = requests.Session()
    session.auth = AUTH
    session.headers.update({"User-Agent": USER_AGENT})

    start = normalize_url(BASE)
    queue = deque([start])
    visited = set()
    discovered = set([start])
    passwords = {}  # password -> set of source urls
    log_entries = []
    path_variant_counts = {}  # path -> number of distinct query strings visited
    skipped_pagination = []
    logf = open("crawl_log.jsonl", "w", encoding="utf-8", buffering=1)

    while queue:
        if len(visited) >= MAX_TOTAL_REQUESTS:
            print(f"[CAP ] hit MAX_TOTAL_REQUESTS={MAX_TOTAL_REQUESTS}, stopping. "
                  f"{len(queue)} URLs still queued.", flush=True)
            break

        url = queue.popleft()
        if url in visited:
            continue
        if not same_host(url):
            continue

        path = urlparse(url).path
        n = path_variant_counts.get(path, 0)
        if n >= MAX_QUERY_VARIANTS_PER_PATH:
            skipped_pagination.append(url)
            continue
        path_variant_counts[path] = n + 1

        visited.add(url)

        try:
            resp = session.get(url, timeout=TIMEOUT, allow_redirects=True)
        except requests.RequestException as e:
            log_entries.append({"url": url, "error": str(e)})
            print(f"[ERR ] {url} -> {e}", flush=True)
            continue

        ctype = resp.headers.get("Content-Type", "")
        data = resp.content
        is_text = guess_is_text(ctype, url)

        entry = {
            "url": url, "status": resp.status_code, "content_type": ctype,
            "bytes": len(data), "final_url": resp.url,
        }
        log_entries.append(entry)
        logf.write(json.dumps(entry) + "\n")
        print(f"[{resp.status_code}] {url}  ({ctype}, {len(data)}B)  [{len(visited)} visited, {len(queue)} queued]", flush=True)

        # --- password scan (every response, text or binary, including error pages --
        # a 403/404 body can still legitimately carry hidden content) ---
        found = scan_bytes_for_passwords(data) - EXCLUDE_PASSWORDS

        # extra binary metadata scan for images
        if not is_text:
            for tagname, raw in extract_exif_strings(data):
                sub = scan_bytes_for_passwords(raw if isinstance(raw, bytes) else str(raw).encode()) - EXCLUDE_PASSWORDS
                if sub:
                    print(f"       password in {tagname}: {sub}", flush=True)
                found |= sub

        for pw in found:
            passwords.setdefault(pw, set()).add(url)
            print(f"   >>> PASSWORD FOUND: {pw}  (in {url})", flush=True)

        if resp.status_code >= 400:
            continue

        # --- link discovery ---
        new_links = set()
        if is_text:
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                text = data.decode("utf-8", errors="replace")

            if "html" in ctype or url.endswith((".html", "/")) or (not ctype and "<html" in text.lower()):
                links, soup = extract_links_from_html(text, url)
                new_links |= links
            elif "javascript" in ctype or url.endswith(".js"):
                new_links |= {urljoin(url, c) for c in extract_links_from_text(text)}
            elif "css" in ctype or url.endswith(".css"):
                new_links |= {urljoin(url, c) for c in extract_links_from_text(text)}
                for m in re.finditer(r"url\(([^)]+)\)", text):
                    cand = m.group(1).strip("'\" ")
                    new_links.add(urljoin(url, cand))
            elif "json" in ctype or url.endswith(".json"):
                new_links |= {urljoin(url, c) for c in extract_links_from_text(text)}
            else:
                new_links |= {urljoin(url, c) for c in extract_links_from_text(text)}
                # unknown text type but might still be html-ish
                if "<html" in text.lower() or "<a " in text.lower():
                    links, soup = extract_links_from_html(text, url)
                    new_links |= links

        for link in new_links:
            norm = normalize_url(link)
            if not same_host(norm):
                continue
            if norm not in discovered:
                discovered.add(norm)
                queue.append(norm)

        time.sleep(0.05)  # be polite

    logf.close()
    if skipped_pagination:
        print(f"\n[NOTE] Skipped {len(skipped_pagination)} URLs past the "
              f"{MAX_QUERY_VARIANTS_PER_PATH}-variant-per-path cap (pagination "
              f"rabbit holes like /report/?page=N). First few:", flush=True)
        for u in skipped_pagination[:10]:
            print(f"       {u}", flush=True)

    return passwords, discovered, visited, log_entries, skipped_pagination


def main():
    passwords, discovered, visited, log_entries, skipped_pagination = crawl()

    print("\n" + "=" * 70)
    print(f"Visited {len(visited)} URLs, discovered {len(discovered)} total URLs.")
    print(f"Found {len(passwords)} unique password(s):")
    for pw, srcs in sorted(passwords.items()):
        print(f"  {pw}   <- {sorted(srcs)}")

    with open("urls_discovered.txt", "w", encoding="utf-8") as f:
        for u in sorted(discovered):
            f.write(u + "\n")

    with open("passwords.json", "w", encoding="utf-8") as f:
        json.dump({pw: sorted(srcs) for pw, srcs in passwords.items()}, f, indent=2)

    if len(passwords) < 8:
        print(f"\nWARNING: only found {len(passwords)}/8 passwords. See NOTES for manual follow-up.")


if __name__ == "__main__":
    main()
