# verifyngo

A bot blocker for simple bots and abusive traffic. Use with your favorite reverse proxy!

Currently has support for Cap (self hosted captcha), HCaptcha and Turnstile. 

It is planned to add ALTCHA. 

For best privacy, use Cap. Data is only processed on your server. However, if you set multiple providers, users can switch between them in case of an issue. 

## Setting it up

You will need to edit config.json: set upstream_url, cookie_secret, and a captcha provider. If you just want blanket protection, that is it. Just add in a few rules inside your JSON itself. However, for custom rule sets, you can use a TXT file or YAML policy file. 

## Plain rule text file

TXT files allow for `allow | challenge | deny` actions, one rule per line:

```
allow     path   ^/api/
deny      ua     python-requests|curl/|Go-http-client
deny      cidr   185.220.0.0/16
challenge path   ^/search
```

See `rules.txt.example`

## Policy file

Set `policy_file` to a YAML policy which supports:

- `networks` entries with `asn`, `cidr`, `prefixes`, `url`, or `file`
- optional `jq-path` or `regex` extraction for URL/file sources
- `conditions` with named reusable groups (`($name)` references)
- `rules` with ordered, first-match-wins behavior

`policy_file` takes priority over `rules_file` and inline `rules`

## ASNS 

- **RADb whois**: ASN entries can be expanded to prefixes at policy load.
- **Optional MaxMind GeoLite2 ASN lookup**: download the DB and it can use it too for ASNs. 

You can run either one alone, or both together.

## Bypassing browser plumbing

Browsers automatically fire requests for favicons or other similar things. 

By default, these are bypassed:

`favicon.ico`, `robots.txt`, `sitemap.xml`, `/.well-known/*`, `manifest.json`/`site.webmanifest`/`*.webmanifest`, `browserconfig.xml`, `apple-touch-icon*.png` and (`.css`, `.js`, `.mjs`, images, fonts, `.wasm`, etc.)

`bypass_paths` always proxies them straight to your upstream. They never count towards the walk-away, ban, or passive budgets. Static assets are bypassed by default because a browser fetches them to render a page rather than navigating to them directly. If `bypass_paths` is omitted from config.json, it defaults to the built-in list above. Still, you can set `"bypass_paths": []` to disable this behavior entirely, or provide your own list of regexes to override the defaults.

## Progressive (passive-first) challenge flow

CAPTCHAs are inherently annoying, so passive mode initially trusts everyone instead of challenging on first sight. When `progressive.enabled = true`, requests to `progressive.passive_paths` (the handful of page/document routes you care about) are served pass-through and get a short-lived passive cookie (`progressive.passive_ttl`).

The first `progressive.max_requests` requests for that cookie within `progressive.request_window` are served without a challenge. Once the budget is used up, the next request escalates to a real CAPTCHA. Solving it issues the long-lived verified cookie, so the user stops getting challenged.

Only paths in `progressive.passive_paths` count against the budget. Static assets and browser plumbing are matched by `bypass_paths` before passive mode runs. For a dynamic site with many changing parts, keep `passive_paths` to the few real navigation routes (e.g. `^/$`).

## Persistence 

Persistence is controlled by the `store` configuration. You can store walkaway counters, blocklist, and reports in memory or Redis.

With Docker, mount `/data` to a volume and set `store.file.path` to `/data/store.json`.

Rules/policy files are hot-reloaded. Parse errors keep the last good rules in memory.
