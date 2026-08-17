# Security

## Supported versions

Security fixes are applied to the latest release. The latest `main` is best-effort.

## Reporting a vulnerability

Please do **not** open a public GitHub issue for a severe security problems.

Report privately to: contact [AT] chocolatemoo53 [DOT] com

Include:

- affected version or commit
- your `config.json` (redact `cookie_secret`, captcha secret keys, API keys)
- steps to reproduce
- expected vs. actual behavior and impact

I'll acknowledge within 48h and work toward a fix and release.
Please give responsible disclosure timeframes (default ~90 days) before going public.

## Scope

In scope:

- Bypassing the challenge/verify flow (`/__verify`, cookie issuance)
- Auth/secret handling: `cookie_secret`, provider secret keys, `trusted_proxies` IP spoofing
- SSRF / misrouting via `upstream_url`, `cap.api_url`, or `cap.verify_url`
- CSP / security-header regressions on the challenge page

Out of scope (not bugs):

- Targeted DoS/DDoS or resource exhaustion
- Vulnerabilities in upstream applications or the captcha provider itself
- Social engineering, or issues requiring a modified/buggy client (the challenge is JS-based; a determined attacker can always pass it manually)

## Process

1. Confirm and assess severity.
2. Fix on a private branch, release, then publish. Coordinated disclosure only.
