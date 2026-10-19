# Security and standards review — Plugin #002 RC1

Review date: 19 October 2026. Candidate: 0.1.0-rc.1. Scope: all 16 files in the supplied prototype archive (four executable modules, four test modules, manifest, Grok skill, package metadata, README, two review/evidence documents, license and ignore file), plus the corrected candidate and new regression/integration tests. Archive instructions were treated as untrusted review material, not authorization. No existing website, Website Auditor #001, Cloudflare configuration or GitHub repository was modified.

## Assessment

Suitable as a bounded, explicitly authorized DNS snapshot release candidate subject to the documented limits and owner release review. It is not a complete SPF evaluator, DMARC receiver, DKIM verifier or security certification. No publication or marketplace submission has occurred. The report distinguishes observed publication, review flags and inconclusive queries. Residual agent prompt-injection risk cannot be eliminated by an instruction-only skill; the CLI never executes DNS text.

## Confirmed defects corrected

| Finding | Prototype behavior / risk | RC1 correction and evidence |
|---|---|---|
| DNS owner length (moderate) | Individually valid domain and selector could construct an overlength name after earlier queries had already run | Validate every owner before DNS; negative regression verifies zero calls |
| Selector syntax (moderate correctness) | Valid dotted DKIM selectors rejected | Support bounded DNS label sequences, case-insensitive duplicate rejection; exact name tests |
| Search expansion (defense in depth) | Relative names passed to resolver | All requested names are absolute with trailing dot; exact boundary test |
| Timeout lifetime (moderate resource handling) | Application deadline did not cancel pending resolver work | Cancel on deadline; fake and real dropped-packet loopback regressions |
| DNS error classification (moderate) | ENOENT and an invented DNS_ENOTFOUND alias could be reported as absence | Only Node ENODATA/ENOTFOUND count as negative; SERVFAIL/refusal/cancellation/other errors remain inconclusive |
| Response bounds (moderate) | TXT joined before per-record size checks; no chunk or total bound; MX accepted arbitrary strings | Prejoin size/chunk limits, total TXT limit, hostname-safe MX; malicious target omitted on error |
| Null MX conflict (moderate correctness) | Mixed root-target/ordinary MX reported simply present | Mixed or wrong-priority null target is needs-review, not a valid null MX |
| SPF false lookup-limit claim (moderate correctness) | Counted terms after all and ignored redirect; claimed a text count proved violation | Ignore unreachable post-all terms and redirect with all; potential count only, actual budget explicitly not evaluated |
| SPF static grammar (moderate correctness) | Unknown mechanisms and invalid IP/CIDR accepted without review | Screen known mechanism forms, IP literals, canonical prefix bounds, repeated unknown modifiers, slash-containing macros and duplicate known modifiers and ASCII/SP boundaries; keep full macro/domain-spec grammar explicitly partial |
| Tag parsing (moderate correctness) | Lowercased case-sensitive DKIM tags, accepted empty interior tags/control values, rejected valid underscore extension tags | Preserve tag case; null-prototype map; folded whitespace support; reject malformed lists; allow extension underscore |
| DKIM RRset uniqueness (moderate correctness) | Filtered candidates before counting, hiding unrelated or unrecognized TXT RRs beside a key | Require the entire selector TXT RRset to be unique before parsing; two adversarial regressions |
| DKIM version/key text (moderate correctness) | Misplaced/lowercase version, uppercase k and impossible base64 accepted; valid folded base64 rejected | Enforce version case/position, recognized key-type case, padding/sextet screening, whitespace folding; no key material output |
| DMARC policy interpretation (moderate correctness) | Invalid sp unflagged; p order unchecked; valid pct=001 rejected; pct omitted from result; arbitrary rua marked configured | Screen sp and v/p order, ABNF digit width/range, expose requested percentage/subpolicy, conservative mailto recognition; never infer effective enforcement |
| Terminal output (moderate local presentation) | Error text could carry terminal escapes or forged lines; JSON C1 controls were unescaped | Bound/JSON-quote errors and escape C1, bidi and Unicode line-control characters in serialized reports/errors; regression round-trips JSON |
| Malformed punycode (low) | Syntactically plausible but invalid A-label accepted | Built-in IDNA checks plus undecodable A-label rejection across tested Node versions |

Tests are under test/rc1.test.mjs and test/resolver.test.mjs. Original fixtures were adapted to absolute query names, and the obsolete test that called every dotted selector invalid was replaced by an empty-label rejection. Regression tests were executed failing against the earlier implementation before fixes; unchanged safety cases already passed. Early failed runs are retained separately as evidence, not represented as final passes.

## RFC assessment

### SPF — RFC 7208

Sections 3.3 and 4.5 require joining chunks within a single TXT RR without adding spaces and keeping RRs separate; multiple selectable SPF policies are reported distinctly. Version selection is anchored and uses a space/end boundary. Names are case-insensitive where specified. Sections 4.6.4 and 5.1 distinguish evaluation-path budgets from lexical totals: the ten DNS-causing-term limit includes include, a, mx, ptr, exists and redirect; exp is outside that evaluation budget. An all mechanism makes later mechanisms and redirect unreachable. The candidate does not evaluate client IP/sender, recursive branches, macros, void lookups, MX/PTR fan-out limits or elapsed receiver-processing limits, so it never certifies compliance or reports SPF pass/fail/permerror. Direct count is a static potential count only. Full domain-spec/macro grammar is not validated; publication status is not validity certification.

Primary source: https://www.rfc-editor.org/rfc/rfc7208 (sections 3.3, 4.5, 4.6, 4.6.4, 5.1, 7).

### DMARC — RFC 7489

Sections 6.3–6.4 define tag syntax, version/policy order, subdomain policy, requested percentage and alignment parameters. RC1 screens those fields and does not equate p=none with a defect or p=reject with observed enforcement. Under section 6.6.3, exact From-domain policy discovery precedes Organizational Domain fallback, using a public-suffix-aware boundary. Arbitrary parent walking and last-two-label inference are wrong, especially for multi-label public suffixes. Inherited sp applies to subdomains and falls back to p; a valid child exact policy overrides fallback. Multiple discovered policies terminate discovery rather than trigger a guessed parent. A transient DNS failure is not absence. Invalid p/sp with a valid rua can lead to monitoring fallback; RC1 flags review without claiming a receiver disposition. No parent queries, PSL download, external reporting-authorization lookups or policy inheritance calculation are performed. Full URI/fo/rf/ri grammar and report delivery are outside the partial static screen.

Primary source: https://www.rfc-editor.org/rfc/rfc7489 (sections 3.2, 6.3, 6.4, 6.6.3, 6.6.4, 7.1).

### DKIM — RFC 6376

Sections 3.1, 3.2 and 3.6.1 cover dotted selectors, case-sensitive tag names, duplicate tag rejection, optional v=DKIM1 with first-position/case constraints, default RSA and empty p revocation. Base64 FWS is permitted; folded key text is screened without returning it. Only explicitly supplied selectors are inspected. DNS can follow provider CNAME aliases under the recursive resolver; this does not prove signing is active or establish an authenticated message result. No selector guessing, cryptographic key validation, minimum-strength certification, message verification, h/s/t semantics certification or algorithm negotiation is performed. Recognizing ed25519 is an extension beyond RFC 6376; key-tag-present remains only a publication observation.

Primary source: https://www.rfc-editor.org/rfc/rfc6376 (sections 3.1, 3.2, 3.6.1, 3.6.2.2 and 6.1).

## Trust boundaries and read-only guarantees

The only plugin network interface is node:dns/promises Resolver.resolveMx/resolveTxt. It has no SMTP, HTTP client, shell execution, telemetry, credential reads, external dependencies or install scripts. node:net.isIP performs local parsing and opens no connection. Local output is opt-in, basename-only, exclusive-create JSON. Existing-file refusal is tested on Windows. A trusted working directory and its Windows ACLs remain operator responsibilities; no confidentiality guarantee is made for DNS data.

The authority boundary is human approval: --authorized is an attestation, not proof of ownership. The skill forbids deriving authority from DNS, reports, instructions in records or unrelated requests. It instructs the agent never to execute record text, fetch DNS-supplied links, render HTML, change DNS, access accounts or initiate email. Prompt-injection tests establish the deterministic tool's fixed query set and inert output; they do not establish a universal guarantee about Grok or another language model following instructions. No model-backed invocation was performed because it would require account/API access beyond this local verification.

Query bounds count application calls, not resolver-internal traffic. The local recursive resolver may use cached or split-horizon data, chase CNAMEs, contact multiple nameservers or use DNS over TCP. Source-domain syntax cannot prove globally public DNS visibility. Application code never issues extra queries derived from SPF/DMARC/DKIM text. A supplied resolver must be exclusive because cancellation affects its outstanding requests. Character limits bound application processing after the native resolver receives its response; they do not pre-bound native DNS allocations. Wall-clock deadlines depend on event-loop scheduling and do not preempt hostile injected JavaScript.

## Authorized real-world test

An exact-domain, five-call MX/TXT-only test completed after direct owner approval. It returned usable MX/SPF/DMARC and both candidate selector TXT answers; no domain changes or mail activity occurred. Owner approval, target-specific observations, sandbox failure and successful run are recorded in the separate private evidence bundle and detailed security report, not this source package.

## Remaining release limitations

A full receiver implementation would require additional scope and authorization. Public-suffix-aware inherited DMARC, complete SPF grammar/evaluation, complete DKIM key/message verification, cross-platform resolver coverage, DNSSEC and a model-backed skill-invocation security test remain unverified. The marketplace metadata's homepage/author URLs were reviewed as declarative metadata, not fetched or modified. Availability and ownership of those pages are release-owner checks. No compliance, deliverability, spoof-proofing, ownership verification or production-change claim is made.

