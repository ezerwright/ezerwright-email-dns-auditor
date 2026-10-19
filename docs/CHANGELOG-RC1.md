# RC1 changes

Version: 0.1.0-rc.1 (candidate only).

- Validate full constructed DNS owner lengths before any query; use absolute names; support dotted DKIM selectors and reject malformed IDNA A-labels.
- Cancel timed-out resolver work; distinguish true DNS absence from generic failures; reject unsafe MX targets and bound TXT chunk/aggregate allocation.
- Identify mixed/invalid null MX; retain implicit MX caveat.
- Screen SPF unknown mechanisms, IP/CIDR and duplicate modifiers; exclude unreachable post-all terms and ignored redirects; label lookup counts as potential rather than proven evaluation failures.
- Preserve case-sensitive tag names; reject empty interior tags/control characters; support extension underscores; enforce DKIM version position/case and canonical base64 with folding whitespace.
- Screen DMARC p order, sp and pct (including ABNF-valid leading zeros); expose pct and explicit unresolved effective-policy status; avoid calling a bogus rua configured; document monitoring fallback and partial URI screening.
- Bound and JSON-quote CLI errors; retain exclusive output creation, key omission and direct-user authorization protections.
- Add adversarial regressions and real Node resolver tests against a loopback-only DNS server; update scope and limitations.
