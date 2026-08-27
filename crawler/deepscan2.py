"""
Fourth pass: exhaustive decoder sweep for the last password.

Adds encodings deepscan.py didn't cover:
  - HTML numeric entities  &#86;&#73;...  and  &#x56;&#x49;...
  - JS string escapes  \\x56\\x49...  \\u0056...  and octal \\126...
  - base32, ascii85/base85
  - Set-Cookie header values
  - data: URIs (decoded, bytes scanned)
  - trailing-whitespace steganography (spaces/tabs after line content -> bits)
  - decimal byte sequences separated by non-digits (e.g. "86 73 83" or "86.73.83")
Everything is checked for the flag format after decode.
"""
import base64
import codecs
import html
import re
from urllib.parse import unquote

import requests

import os  # noqa: E402
# Credentials read from environment; never hardcode/commit them.
AUTH = (os.environ.get("VP_USER", ""), os.environ.get("VP_PASS", ""))
if not AUTH[0] or not AUTH[1]:
    raise SystemExit("Set VP_USER and VP_PASS env vars (challenge HTTP Basic Auth credentials).")
TIMEOUT = 20
FLAG_PREFIX = os.environ.get("FLAG_PREFIX", "FLAG")
PW = re.compile(re.escape(FLAG_PREFIX) + r"\{[0-9a-fA-F]{16}\}")
# Public worked-example from the challenge homepage (not a recovered answer).
EXCLUDE = {FLAG_PREFIX + "{0000deadbeef0000}"}
import json  # noqa: E402
# Already-known values are loaded at runtime from passwords.json (gitignored),
# so no answers are committed to source control. Empty if the file is absent.
KNOWN = set()
try:
    with open("passwords.json", encoding="utf-8") as _f:
        KNOWN = set(json.load(_f).keys())
except Exception:
    pass


def hits(s):
    return {m.group() for m in PW.finditer(s)} - EXCLUDE


def dec_html_entities(text):
    out = set()
    out |= hits(html.unescape(text))
    # also manual numeric-entity join in case they're not standard-terminated
    for run in re.findall(r"(?:&#x?[0-9a-fA-F]+;?){10,}", text):
        chars = []
        for m in re.finditer(r"&#(x?)([0-9a-fA-F]+);?", run):
            base = 16 if m.group(1) else 10
            try:
                chars.append(chr(int(m.group(2), base)))
            except Exception:
                pass
        out |= hits("".join(chars))
    return out


def dec_js_escapes(text):
    out = set()
    for pat, base in ((r"(?:\\x[0-9a-fA-F]{2}){10,}", 16),
                      (r"(?:\\u[0-9a-fA-F]{4}){10,}", 16),
                      (r"(?:\\[0-3]?[0-7]{1,2}){10,}", 8)):
        for run in re.findall(pat, text):
            nums = re.findall(r"\\u?x?([0-9a-fA-F]+)", run)
            try:
                out |= hits("".join(chr(int(n, base)) for n in nums))
            except Exception:
                pass
    return out


def dec_decimal_runs(text):
    out = set()
    for run in re.findall(r"(?:\d{1,3}[\s,.\-;:|]+){10,}\d{1,3}", text):
        nums = [int(x) for x in re.findall(r"\d{1,3}", run)]
        try:
            out |= hits("".join(chr(n) for n in nums if 0 <= n < 0x110000))
        except Exception:
            pass
    return out


def dec_base32_85(text):
    out = set()
    for m in re.finditer(r"[A-Z2-7]{24,}={0,6}", text):
        b = m.group()
        try:
            out |= hits(base64.b32decode(b + "=" * (-len(b) % 8)).decode("latin-1", "ignore"))
        except Exception:
            pass
    for m in re.finditer(r"[!-u]{24,}", text):
        try:
            out |= hits(base64.a85decode(m.group()).decode("latin-1", "ignore"))
        except Exception:
            pass
    for m in re.finditer(r"[0-9A-Za-z!#$%&()*+\-;<=>?@^_`{|}~]{24,}", text):
        try:
            out |= hits(base64.b85decode(m.group()).decode("latin-1", "ignore"))
        except Exception:
            pass
    return out


def dec_data_uris(text):
    out = set()
    for m in re.finditer(r"data:[^;,\s]*;base64,([A-Za-z0-9+/=]+)", text):
        try:
            raw = base64.b64decode(m.group(1) + "=" * (-len(m.group(1)) % 4))
            for enc in ("latin-1", "utf-8", "utf-16-le", "utf-16-be"):
                out |= hits(raw.decode(enc, "ignore"))
        except Exception:
            pass
    for m in re.finditer(r"data:[^,\s]*,([^\"')\s]+)", text):
        out |= hits(unquote(m.group(1)))
    return out


def dec_whitespace_stego(text):
    out = set()
    bits = []
    for line in text.split("\n"):
        stripped = line.rstrip("\r")
        trail = len(stripped) - len(stripped.rstrip(" \t"))
        tail = stripped[len(stripped.rstrip(" \t")):]
        for ch in tail:
            bits.append("1" if ch == "\t" else "0")
    if len(bits) >= 8:
        for order in (bits, ):
            by = bytearray()
            for i in range(0, len(order) - 7, 8):
                by.append(int("".join(order[i:i + 8]), 2))
            out |= hits(bytes(by).decode("latin-1", "ignore"))
    return out


def main():
    with open("urls_discovered.txt", encoding="utf-8") as f:
        urls = [l.strip() for l in f if l.strip()]
    # add the now-reachable German status page (target root from env, not source)
    _base = os.environ.get("TARGET_BASE", "").rstrip("/")
    if _base:
        urls.append(_base + "/status/eu-region/")

    s = requests.Session()
    s.auth = AUTH
    found = {}

    for i, url in enumerate(urls):
        try:
            r = s.get(url, timeout=TIMEOUT)
        except requests.RequestException:
            continue

        # cookies
        for k, v in r.headers.items():
            if k.lower() == "set-cookie":
                h = hits(v)
                if h - KNOWN:
                    found.setdefault(url + " [Set-Cookie]", set()).update(h - KNOWN)

        ctype = r.headers.get("Content-Type", "")
        if ctype.startswith("image/"):
            continue
        text = r.content.decode("utf-8", "ignore")

        new = set()
        new |= dec_html_entities(text)
        new |= dec_js_escapes(text)
        new |= dec_decimal_runs(text)
        new |= dec_base32_85(text)
        new |= dec_data_uris(text)
        new |= dec_whitespace_stego(text)
        new -= KNOWN
        if new:
            print(f"[HIT] {url} -> {new}")
            found.setdefault(url, set()).update(new)

        if (i + 1) % 100 == 0:
            print(f"...{i+1}/{len(urls)}")

    print("\n" + "=" * 60)
    if found:
        print("NEW passwords:")
        for u, pws in found.items():
            for pw in pws:
                print(f"  {pw}  <- {u}")
    else:
        print("No new passwords from the extended decoder sweep.")


if __name__ == "__main__":
    main()
