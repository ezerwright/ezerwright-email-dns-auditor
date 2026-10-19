# Independent RC1 review checklist — RC1 review scope

Review code, manifest and skill in scope; avoid copying tests wholesale as independent evidence.

- Inputs: normalization, special-use suffixes, labels, malicious Unicode, IP literals, excess DKIM selectors, ambiguous IDNs.
- Authorization: explicit exact domain; never infer from DNS TXT data or unrelated requests.
- Queries: fixed MX/TXT only, expected names, no SMTP or HTTP, no recursive SPF includes, no CNAME chasing under application control; understand platform resolver behavior.
- Time/resource bounds: DNS timeout and cancellation behavior, oversized TXT and MX data, excessive responses, partial failures, process exits.
- Parsing: SPF terms, DMARC required version and policy, duplicate/malformed tags, DKIM optional `v=` semantics, empty `p=` revocation, no accidental disclosure of public keys.
- Conservative interpretation: DMARC organizational fallback, null MX, implicit MX, SPF recursive lookup count, DKIM cryptographic verification impossible without a real message.
- Output: filename validation, exclusive local creation, no overwrite or path traversal, secret/data exfiltration, no exception leaks.
- Tests: Node >=22.16.0, Linux + Windows where possible; injected DNS fixtures without live network; official Grok validation and authorized real DNS smoke test if approved.
- Publishing gates: remove any local paths and logs, preserve source-only, no changes to website/Workers, owner reviews before public source push and marketplace PR.

