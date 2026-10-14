# verifyngo

A bot blocker for simple bots and abusive traffic. Use with your favorite reverse proxy!

Currently has support for Cap (self hosted captcha), HCaptcha, Turnstile, and a self-hosted JS-free slider puzzle. 

It is planned to add ALTCHA. 

If you set multiple providers, users can switch between them in case of an issue.

## Setting it up

You will need to edit config.json: set upstream_url, cookie_secret, and a captcha provider. If you just want blanket protection, that is it. Just add in a few rules inside your JSON itself. However, for custom rule sets, you can use a TXT file or YAML policy file. 

## Plain rule text file

TXT files allow for `allow | challenge | deny | tarpit` actions, one rule per line:

```
allow     path   ^/api/
deny      ua     python-requests|curl/|Go-http-client
deny      cidr   185.220.0.0/16
challenge path   ^/search
tarpit    ua    (ClaudeBot|GPTBot|PerplexityBot)
```

See `rules.txt.example`

## Policy file

Set `policy_file` to a YAML policy which supports:

- `networks` entries with `asn`, `cidr`, `prefixes`, `url`, or `file`
- optional `jq-path` or `regex` extraction for URL/file sources
- `conditions` with named reusable groups (`($name)` references)
- `rules` with ordered, first-match-wins behavior

`policy_file` takes priority over `rules_file` and inline `rules`

`.matches()` takes a quoted regular expression, which is compiled when the policy loads. An invalid pattern stops the policy from loading instead of silently never matching.

Conditions can use `path`, `userAgent`, `method`, `ip`, `headers["Name"]` and `browserMismatch`. `browserMismatch` is `"fake"` when the user agent claims Firefox or Safari but sends Chromium client hints, `"no-hints"` when it claims Chromium but sends no client hints over HTTPS, and `""` otherwise:

```yaml
  - name: fake-browser
    conditions:
      - 'browserMismatch == "fake"'
    action: challenge
```

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

A request with a `browserMismatch` never gets the passive pass and goes straight to a challenge.

Each network (/24 for IPv4, /48 for IPv6) can get at most `progressive.max_requests` new passive cookies per `progressive.request_window`. A client that drops its cookie to get a fresh budget is challenged once its network runs out.

## Walk-aways and failed attempts

Every challenge served counts as a walk-away, and `walkaway.threshold` walk-aways ban the client. A failed attempt shows the challenge again right away without counting a walk-away. Failed attempts have their own counter, and three times `walkaway.threshold` failures ban the client. Answers that look automated, like a slider solved too fast or the same answer repeated, still count as walk-aways. Solving a challenge clears both counters.

## Cookies

The verified and passive cookies are signed together with the browser's `User-Agent` and `Accept-Language`. A cookie copied to another client, or kept after the browser's user agent or language changes, stops working and that client is challenged again. When TLS fingerprinting is enabled, they are also bound to the client's cipher list, the part of JA4 that stays the same across resumed connections. A cookie copied from a browser into a script fails even if the script fakes the user agent. A request without a fingerprint header is checked against the user agent and language only, so a connection the proxy cannot fingerprint is not challenged in a loop. Cookies issued before this change are no longer accepted, so every visitor solves one new challenge after upgrading.

## Persistence 

Persistence is controlled by the `store` configuration. You can store walkaway counters, blocklist, and reports in memory or Redis.

With Docker, mount `/data` to a volume and set `store.file.path` to `/data/store.json`.

Rules/policy files are hot-reloaded. Parse errors keep the last good rules in memory.

Rules load in the background at startup, so fetching network lists or ASN prefixes does not hold up the site. Until they are loaded, requests skip the rules and pass through. Bans, the blocklist, and cookies still apply. If the rules fail to load at startup, `default_action` applies to every request until the file is fixed.

If Redis is unreachable, the ban check is skipped instead of blocking everyone, and clients without a cookie are still challenged.

Files in `static_dir` are served under `/__static/`, so they never shadow the upstream application's own `/static/` path.

## TLS fingerprinting

With OpenResty 1.29.2.1 or newer, `lua/ja4_fingerprint.lua` computes two fingerprints from the TLS ClientHello and passes them to verifyngo as headers:

- `X-JA4`: [JA4](https://github.com/FoxIO-LLC/ja4)
- `X-TLSFP`: [TLSFP](https://github.com/ntop/nDPI/blob/dev/fingerprint/nDPI_TLS_Fingerprint.md), which leaves out extensions that change between new and resumed connections, so one browser keeps one value

```nginx
lua_package_path "/path/to/lua/?.lua;;";

server {
    listen 443 ssl;

    ssl_client_hello_by_lua_block {
        require("ja4_fingerprint").compute()
    }

    access_by_lua_block {
        require("ja4_fingerprint").set_headers()
    }

    location / {
        proxy_pass http://127.0.0.1:8080;
    }
}
```

`set_headers()` always overwrites both headers, so a client cannot send its own. In config.json, set `trust_fingerprint_headers` to `true` and list the proxy in `trusted_proxies`. verifyngo ignores the headers otherwise. Only enable it when every request passes through this module.

verifyngo prefers TLSFP and falls back to JA4. Walk-aways are counted per fingerprint within the client's /24 (IPv4) or /48 (IPv6), and the count resets when a challenge is solved. This catches a bot rotating addresses inside one network without banning everyone who uses the same browser.

## Tor

verifyngo recognizes two kinds of Tor traffic:

- **Onion:** requests from an onion circuit address (see below), or with a `.onion` `Host` arriving from a loopback or private address
- **Exit:** requests from an address on the Tor Project's exit list. Set `"tor": {"exit_list": true}` to fetch it, refreshed every `tor.refresh` (default `1h`)

Tor traffic never gets the passive pass, is shown the JS-free slider by default (when `slider.enabled` is set), and is never checked against or reported to AbuseIPDB. Policy conditions can use `tor`, which is `"onion"`, `"exit"`, or `""`:

```yaml
  - name: no-tor-admin
    conditions:
      - 'tor != "" && path.startsWith("/admin")'
    action: deny
```

Exit addresses are shared by many people, so they are never banned. Every request without a cookie gets a challenge instead, failed attempts are not counted against the address, and the slider allows five times as many attempts per minute. A bot behind an exit keeps getting challenges but never reaches the application.

### Onion services with circuit IDs

Without circuit IDs, every onion visitor arrives from the same address and is treated like an exit. With them, each circuit gets its own address, so walk-aways, failed attempts, and bans apply per circuit like any other visitor.

In torrc, under the onion service:

```
HiddenServiceDir /var/lib/tor/verifyngo/
HiddenServicePort 80 127.0.0.1:8081
HiddenServiceExportCircuitID haproxy
```

Tor then opens every connection with a PROXY protocol header, so give the onion its own nginx port, separate from the clearnet one:

```nginx
server {
    listen 127.0.0.1:8081 proxy_protocol;
    server_name youronionaddress.onion;

    location / {
        proxy_set_header X-Forwarded-For $proxy_protocol_addr;
        proxy_pass http://127.0.0.1:8080;
    }
}
```

Both nginx ports proxy to the same verifyngo `listen_addr`. Set `trust_real_ip` to `true` and list nginx in `trusted_proxies`.

## Metrics

Set `metrics_addr` (for example `"127.0.0.1:9100"`) to serve Prometheus metrics at `/metrics` on a separate listener. It is off when empty. The endpoint has no authentication, so bind it to localhost or a private network, never to the public interface. In Docker, bind `0.0.0.0:9100` and only publish it on the network Prometheus uses.

```yaml
scrape_configs:
  - job_name: verifyngo
    static_configs:
      - targets: ["verifyngo:9100"]
```

| Metric | Labels | Meaning |
|---|---|---|
| `verifyngo_decisions_total` | `decision` | Every request and how it was handled |
| `verifyngo_rule_hits_total` | `rule`, `action` | Requests decided by each rule; `default` when none matched |
| `verifyngo_challenges_total` | `provider`, `result` | Challenges `issued`, and verify attempts `passed`, `failed`, `automated`, `throttled`, or `error` |
| `verifyngo_bans_total` | `reason` | Bans by `walk-aways`, `failed attempts`, or `fingerprint` |
| `verifyngo_passive_total` | `result` | Progressive mode outcomes |
| `verifyngo_browser_mismatch_total` | `kind` | User agents that do not match their headers |
| `verifyngo_upstream_responses_total` | `status` | Upstream responses by status class, or `error` |
| `verifyngo_store_errors_total` | `op` | Failed Redis operations |
| `verifyngo_rule_reloads_total` | `result` | Rule loads and reloads |
| `verifyngo_rules_loaded` | | `0` while rules are loading at startup, then `1` |
| `verifyngo_blocklist_entries` | | Entries in the AbuseIPDB blocklist |
| `verifyngo_tor_requests_total` | `kind` | Requests over Tor, `onion` or `exit` |
| `verifyngo_tor_exits` | | Addresses in the Tor exit list |

Go runtime and process metrics (`go_*`, `process_*`) are included. Policy rules are labeled by their `name`, and unnamed rules as `rule-N` by position.
