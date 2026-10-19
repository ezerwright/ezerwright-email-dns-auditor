# Marketplace release checklist — Plugin #002 0.1.0-rc.1

Candidate preparation only. Do not publish or submit without a new owner instruction.

- [x] Review all prototype source, tests, manifest, skill, metadata and documentation.
- [x] Keep source isolated from Website Auditor #001, website, Cloudflare settings and GitHub repositories.
- [x] Keep only bounded MX/TXT application calls; no SMTP, sending, paid API, telemetry, credential reads or DNS writes.
- [x] Add adversarial regression and loopback DNS integration coverage.
- [x] Declare the partial SPF/DMARC/DKIM scope and conservative status semantics.
- [x] Obtain explicit owner authorization before live ezerwright.com MX/TXT testing; treat selector1/selector2 as candidates.
- [x] Confirm final Windows and exact minimum-Node full-suite logs and artifact hashes in the separate evidence bundle.
- [x] Confirm official Grok validator and isolated install/details/help tests against the final ZIP extraction.
- [ ] Owner reviews security report, live results, limitations and final candidate source.
- [ ] Owner chooses release version and confirms author/license/homepage/support information and marketplace-specific submission requirements.
- [ ] If public source hosting is wanted later, owner explicitly authorizes a separate destination; do not reuse or alter existing repositories implicitly.
- [ ] If marketplace submission is wanted later, owner explicitly authorizes submission and reviews the exact listing. No submission has been prepared externally.
- [ ] Consider a separately authorized model-backed skill prompt-injection/authorization test. Current evidence covers deterministic CLI behavior, validation and install discovery only.

Release claims must describe a read-only DNS snapshot, not full RFC compliance, deliverability testing, actual message authentication, active DKIM signing or effective DMARC enforcement. Do not promise a fixed wire-packet budget or globally public DNS visibility from domain syntax.

Artifacts: corrected source ZIP; separate evidence ZIP; SHA256SUMS.txt; SECURITY-REVIEW.md; TEST-EVIDENCE.md. No runtime binaries, local reports, private paths, credentials, installed plugin caches or live-domain data belong in the source ZIP. Keep live results in the separate evidence bundle.

