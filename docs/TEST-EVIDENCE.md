# RC1 test evidence — 19 October 2026

Windows validation for 0.1.0-rc.1. Baseline archive: 96 tests passed on Node 24.22.0. RC1: 150 tests passed, 0 failed, 0 skipped on Windows with both Node 24.22.0 and the exact minimum Node 22.16.0. The minimum runtime was downloaded from nodejs.org and verified against its published SHA-256. No runtime binary is bundled with the plugin.

The suite contains the original 96 tests (with fixture updates for absolute owner names and valid dotted selectors), 48 independent adversarial regressions, and 6 real Node resolver tests. DNS fixtures bind a UDP socket only on 127.0.0.1 and never forward upstream. Restricted sandbox runs blocked those packets; the complete suite passed with loopback network access. This environmental failure was not hidden or called a plugin absence result.

Commands:

- npm test (Windows Node 24.22.0): 150/150.
- node-v22.16.0.exe --test: 150/150.
- node --check scripts/audit.mjs, scripts/auditor.mjs, scripts/records.mjs, scripts/safety.mjs: success.
- node scripts/audit.mjs --help: success, no DNS.
- grok plugin validate .: final manifest valid, one skill directory, no commands/agents/hooks/MCP components.
- grok plugin install <local extracted candidate> --trust, plugin list/details, installed CLI help and pure-suite smoke: success in a dedicated GROK_HOME, without account access or model invocation.

The separate evidence archive contains raw outputs, exact exit codes, environment metadata, SHA-256, red/green regression runs, the read-only reviewer closure, and the owner-authorized live audit. Earlier failing development runs are historical, not final status. See verification-commands.json and grok-smoke-summary.json for final checks against the actual packaged extraction.

Coverage: authorization before DNS; syntax and constructed-name lengths; explicit selectors/no guessing; fixed MX/TXT names and query counts; TXT chunk joins and record separation; oversized/malformed payloads; NXDOMAIN/ENODATA vs SERVFAIL/refusal; real resolver cancellation; null/implicit MX; SPF path-count false positives and grammar cases; DMARC policy/subpolicy/percentage limits; DKIM tag case/order/folding/revocation/whole-RRset multiplicity; output escaping and exclusive creation.

A fresh read-only reviewer identified four additional correctness issues during review. All were fixed with red/green tests and the reviewer confirmed no remaining actionable issue within scope; its final pure-suite run passed 144/144. The six loopback integration tests are verified in the coordinator's full-suite logs.

Limits: tests do not prove RFC conformance, DNSSEC, actual email delivery, effective inherited DMARC, active DKIM signing, Windows ACL secrecy or model obedience to the skill. No Linux/macOS final run or authenticated Grok agent session was performed. Live audit results are a time-specific configured-resolver snapshot, not an authoritative global consistency check. No publication or infrastructure change was performed.
