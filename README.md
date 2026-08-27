# sift

A crawler I threw together to solve a "find the hidden flags" challenge. You
point it at a site behind basic auth and it walks the whole thing looking for
flags shaped like `FLAG{<16 hex>}`. The catch is they're not just sitting in
the page HTML, they turn up in image EXIF, in JS, one was drawn as text
*inside* a picture, and one only shows up if you hit the server from the right
country.

Nothing site-specific is in here. The target URL, the login, the flag prefix,
and whatever it finds all come from env vars or git-ignored files. This repo is
just the code (under `crawler/`).

## Setup

```
pip install requests beautifulsoup4 pillow

export TARGET_BASE="http://host/"
export VP_USER=...        # basic auth user
export VP_PASS=...        # basic auth pass
export FLAG_PREFIX=...    # the word before the { in a flag
```

PowerShell: `$env:TARGET_BASE="..."`, etc.

## Running

The scripts live in `crawler/`. Start with `crawler.py`, it does the crawl and
drops `passwords.json`, `urls_discovered.txt` and `crawl_log.jsonl` next to
itself. The others are follow-up passes that read those back in:

```
cd crawler
python crawler.py
python deepscan.py      # char-code arrays, base64, hex, rot13, reversed, url-decode
python deepscan2.py     # html entities, \x/\u/octal, base32/85, data-uris, whitespace, cookies
python cipherscan.py    # caesar / atbash / single-byte xor
python anomaly_scan.py  # inline styles, hidden elements, zero-width chars, odd tags
```

## Layout

```
crawler/crawler.py        crawl + first scan
crawler/deepscan*.py      decoder passes
crawler/cipherscan.py     cipher pass
crawler/anomaly_scan.py   structural / css tricks
crawler/*.json *.txt *.jsonl   git-ignored: results + anything that IDs the target
```
