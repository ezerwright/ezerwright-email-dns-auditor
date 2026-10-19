# RC1 Review Plan

Scope: user request of 19 October 2026; independent review of Plugin #002 only.
Execute inline in an isolated extracted copy. No Git or website changes.

1. Read every archive file; capture baseline suite and inspect RFC 7208, 7489, 6376.
2. Add failing adversarial tests for owner-name lengths, dotted selectors, DNS error/cancellation, TXT allocation bounds, SPF unreachable terms/grammar, tag semantics and CLI escaping.
3. Fix shared trust boundaries and parsers. Preserve a DNS snapshot tool; do not claim full SPF evaluation, effective DMARC inheritance, or DKIM verification.
4. Run full Windows suite on installed Node and exact 22.16.0 if obtainable; inspect syntax and package content. Run official Grok validator and isolated installation smoke test.
5. Prepare owner-approval-gated live DNS protocol without querying a live domain. Produce source ZIP, evidence ZIP, security report and release checklist with honest outstanding gates.

Review focus: private/search-suffix DNS boundary; DNS-generated commands/links; resource exhaustion; false enforcement claims from partial SPF/DMARC; selector-specific DKIM absence.
