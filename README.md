# sift

A crawler I threw together to solve a "find the hidden flags" challenge. You
point it at a site behind basic auth and it walks the whole thing looking for
flags shaped like `FLAG{<16 hex>}`. The catch is they're not just sitting in
the page HTML — they turn up in image EXIF, in JS, one was drawn as text
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

The scripts live in `crawler/`. Start with `crawler.py` — it does the crawl and
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

## Stuff that bit me (and how it works)

- Don't grep for the flag in UTF-8 only. EXIF UserComment is UTF-16, so a flag
  hidden there is invisible unless you decode the bytes a few different ways.
- Links aren't only `<a href>`. Here the nav was built entirely by inline JS,
  so I pull paths out of `<script>` bodies, `srcset`, `data-*` attrs, css
  `url(...)` and comments as well. Skip that and you miss whole sections.
- Images need more than a byte grep. Read every EXIF/JPEG/PNG chunk *and*
  actually look at the image — one flag was just rendered as text in the
  picture, no metadata involved.
- One endpoint paginated forever (the classic trap), so there's a cap on how
  many query-string variants of a single path it'll follow.
- Headers get scanned but I don't count hits found there. The challenge drops
  throwaway flags in response headers on purpose.

How I knew I was actually finished: the crawl queue drains to empty, and I
cross-check that every path referenced anywhere actually got fetched
(referenced ⊆ crawled). Encoded flags are what deepscan/cipherscan mop up;
anything gated on *where* or *how* you send the request is the header/UA/geo
testing.

## Layout

```
crawler/crawler.py        crawl + first scan
crawler/deepscan*.py      decoder passes
crawler/cipherscan.py     cipher pass
crawler/anomaly_scan.py   structural / css tricks
crawler/*.json *.txt *.jsonl   git-ignored: results + anything that IDs the target
```
