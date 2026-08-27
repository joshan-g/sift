"""
Second-pass deep scanner.

The first crawl (crawler.py) finds every reachable URL and matches the
literal flag pattern (including inside UTF-16 EXIF blobs). That misses flags
stored non-literally -- e.g. a flag built at runtime from a JS char-code
array rather than written out as a string.

This script re-fetches every URL discovered by the first crawl and tries a
battery of additional decodings on the raw text/bytes, looking for
anything that decodes to the flag format:

  - literal (already covered, kept as a sanity check)
  - JS numeric char-code arrays: [86, 73, 83, ...]
  - base64 blobs
  - hex-encoded ASCII blobs (flag spelled out in hex pairs)
  - ROT13
  - reversed text
  - URL (%xx) decoding
  - full EXIF/metadata dump for every image (all tags, not just the
    string-ish ones), to eyeball anything the first pass's tag allowlist
    might have missed
"""
import base64
import codecs
import io
import json
import re
import struct
from urllib.parse import urlparse, unquote

import requests

import os  # noqa: E402
# Credentials read from environment; never hardcode/commit them.
AUTH = (os.environ.get("VP_USER", ""), os.environ.get("VP_PASS", ""))
if not AUTH[0] or not AUTH[1]:
    raise SystemExit("Set VP_USER and VP_PASS env vars (challenge HTTP Basic Auth credentials).")
TIMEOUT = 20

FLAG_PREFIX = os.environ.get("FLAG_PREFIX", "FLAG")
PASSWORD_RE = re.compile(re.escape(FLAG_PREFIX) + r"\{[0-9a-fA-F]{16}\}")
# Public worked-example from the challenge homepage (not a recovered answer).
EXCLUDE = {FLAG_PREFIX + "{0000deadbeef0000}"}

CHARCODE_ARRAY_RE = re.compile(r"\[\s*\d{1,3}(?:\s*,\s*\d{1,3}){10,}\s*\]")
HEX_BLOB_RE = re.compile(r"(?:[0-9a-fA-F]{2}){20,}")
BASE64ISH_RE = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")


def try_charcode_arrays(text):
    found = set()
    for m in CHARCODE_ARRAY_RE.finditer(text):
        nums = [int(x) for x in re.findall(r"\d+", m.group())]
        try:
            s = "".join(chr(n) for n in nums if 0 <= n < 0x110000)
        except Exception:
            continue
        for pm in PASSWORD_RE.finditer(s):
            found.add(pm.group())
    return found


def try_hex_blobs(text):
    found = set()
    for m in HEX_BLOB_RE.finditer(text):
        blob = m.group()
        if len(blob) % 2:
            blob = blob[:-1]
        try:
            decoded = bytes.fromhex(blob).decode("ascii", errors="ignore")
        except Exception:
            continue
        for pm in PASSWORD_RE.finditer(decoded):
            found.add(pm.group())
    return found


def try_base64_blobs(text):
    found = set()
    for m in BASE64ISH_RE.finditer(text):
        blob = m.group()
        for candidate in (blob, blob + "=" * (-len(blob) % 4)):
            try:
                decoded = base64.b64decode(candidate, validate=False)
            except Exception:
                continue
            for enc in ("ascii", "utf-8", "utf-16-le", "utf-16-be"):
                try:
                    s = decoded.decode(enc, errors="ignore")
                except Exception:
                    continue
                for pm in PASSWORD_RE.finditer(s):
                    found.add(pm.group())
    return found


def try_rot13(text):
    found = set()
    decoded = codecs.encode(text, "rot_13")
    for pm in PASSWORD_RE.finditer(decoded):
        found.add(pm.group())
    return found


def try_reversed(text):
    found = set()
    rev = text[::-1]
    for pm in PASSWORD_RE.finditer(rev):
        found.add(pm.group())
    return found


def try_urldecode(text):
    found = set()
    try:
        decoded = unquote(text)
    except Exception:
        return found
    for pm in PASSWORD_RE.finditer(decoded):
        found.add(pm.group())
    return found


def dump_all_exif(data, url):
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS
        img = Image.open(io.BytesIO(data))
        exif = img.getexif()
        info = {"format": img.format, "size": img.size, "info": img.info}
        tags = {}
        for k, v in exif.items():
            tags[TAGS.get(k, k)] = v
        for ifd_id in (0x8769, 0x8825, 0xA005):
            try:
                ifd = exif.get_ifd(ifd_id)
                for k, v in ifd.items():
                    tags[f"ifd{ifd_id}.{TAGS.get(k, k)}"] = v
            except Exception:
                pass
        if tags or info["info"]:
            print(f"    [EXIF] {url}")
            print(f"           info={info['info']}")
            for k, v in tags.items():
                print(f"           {k} = {v!r}")
    except Exception as e:
        pass


def main():
    with open("urls_discovered.txt", encoding="utf-8") as f:
        urls = [line.strip() for line in f if line.strip()]

    session = requests.Session()
    session.auth = AUTH

    all_found = {}
    already_known = set()
    try:
        with open("passwords.json", encoding="utf-8") as f:
            already_known = set(json.load(f).keys())
    except Exception:
        pass

    for i, url in enumerate(urls):
        try:
            resp = session.get(url, timeout=TIMEOUT)
        except requests.RequestException as e:
            print(f"[ERR] {url} -> {e}")
            continue
        data = resp.content
        ctype = resp.headers.get("Content-Type", "")
        path = urlparse(url).path.lower()

        is_image = ctype.startswith("image/") or path.endswith((".jpg", ".jpeg", ".png", ".gif", ".webp", ".ico"))

        if is_image:
            dump_all_exif(data, url)
            continue

        # decode as text for the string-based heuristics
        try:
            text = data.decode("utf-8", errors="ignore")
        except Exception:
            text = data.decode("latin-1", errors="ignore")

        found = set()
        found |= {m.group() for m in PASSWORD_RE.finditer(text)}
        found |= try_charcode_arrays(text)
        found |= try_hex_blobs(text)
        found |= try_base64_blobs(text)
        found |= try_rot13(text)
        found |= try_reversed(text)
        found |= try_urldecode(text)
        found -= EXCLUDE

        new = found - already_known
        if new:
            print(f"[HIT] {url}")
            for pw in new:
                print(f"      -> {pw}")
            all_found[url] = sorted(new)

        if (i + 1) % 100 == 0:
            print(f"...{i+1}/{len(urls)} scanned")

    print("\n" + "=" * 60)
    if all_found:
        print("New passwords found in deep scan:")
        for url, pws in all_found.items():
            for pw in pws:
                print(f"  {pw}  <- {url}")
    else:
        print("No NEW passwords found beyond the first pass.")


if __name__ == "__main__":
    main()
