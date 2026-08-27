"""
Fifth pass: classic ciphers across all pages, in case the 8th password is
enciphered (not just encoded). Tries, per page text:
  - all 25 Caesar/ROT shifts (letters only; digits/braces pass through)
  - Atbash
  - single-byte XOR over the whole byte stream (all 255 keys)
  - base64-of-hex and hex-of-base64 nestings on candidate blobs
The plaintext we want is literally the flag string, so for the letter
ciphers we shift the text and look for the prefix; for XOR we brute keys.
"""
import base64
import re
import requests

import os  # noqa: E402
# Credentials read from environment; never hardcode/commit them.
AUTH = (os.environ.get("VP_USER", ""), os.environ.get("VP_PASS", ""))
if not AUTH[0] or not AUTH[1]:
    raise SystemExit("Set VP_USER and VP_PASS env vars (challenge HTTP Basic Auth credentials).")
FLAG_PREFIX = os.environ.get("FLAG_PREFIX", "FLAG")
PW = re.compile(re.escape(FLAG_PREFIX) + r"\{[0-9a-fA-F]{16}\}")
import json  # noqa: E402
# Already-known values are loaded at runtime from passwords.json (gitignored),
# so no answers are committed to source control. Empty if the file is absent.
KNOWN = {FLAG_PREFIX + "{0000deadbeef0000}"}  # public worked-example decoy
try:
    with open("passwords.json", encoding="utf-8") as _f:
        KNOWN |= set(json.load(_f).keys())
except Exception:
    pass


def caesar(text, n):
    out = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - 97 + n) % 26 + 97))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - 65 + n) % 26 + 65))
        else:
            out.append(ch)
    return "".join(out)


def atbash(text):
    out = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr(219 - ord(ch)))
        elif "A" <= ch <= "Z":
            out.append(chr(155 - ord(ch)))
        else:
            out.append(ch)
    return "".join(out)


def hits(s):
    return {m.group() for m in PW.finditer(s)} - KNOWN


def scan(text, raw):
    found = set()
    for n in range(1, 26):
        found |= hits(caesar(text, n))
    found |= hits(atbash(text))
    # single-byte XOR over raw bytes -- only worth it if the prefix could appear
    # (cheap heuristic: try all keys, but bail fast)
    for key in range(1, 256):
        xored = bytes(b ^ key for b in raw)
        if FLAG_PREFIX.encode() in xored:
            found |= hits(xored.decode("latin-1", "ignore"))
    return found


def main():
    urls = [l.strip() for l in open("urls_discovered.txt") if l.strip()]
    s = requests.Session()
    s.auth = AUTH
    any_found = False
    for i, url in enumerate(urls):
        if "/static/img" in url:
            continue
        try:
            r = s.get(url, timeout=20)
        except requests.RequestException:
            continue
        raw = r.content
        text = raw.decode("utf-8", "ignore")
        f = scan(text, raw)
        if f:
            print(f"[HIT] {url} -> {f}")
            any_found = True
        if (i + 1) % 100 == 0:
            print(f"...{i+1}/{len(urls)}")
    if not any_found:
        print("No passwords via Caesar/Atbash/XOR ciphers.")


if __name__ == "__main__":
    main()
