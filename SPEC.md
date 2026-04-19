name: scopesift
purpose: Validate ownership of in-scope assets for a bug bounty / pentest engagement by cross-checking DNS, TLS cert SANs, and HTTP fingerprints against a claimed program name.
language: go
why_language: Needs parallel DNS + TLS + HTTP probes across dozens of hosts; single binary install suits the bug-bounty-hunter VPS audience; stdlib covers net/tls/http.
features:
- Resolve A/AAAA for each asset; note CNAME chains
- Pull TLS cert, extract SAN list, issuer, subject-org
- HTTP HEAD probe; capture Server + redirect chain
- Match evidence against a user-supplied program name/keyword list; score confidence HIGH / MEDIUM / LOW / SUSPICIOUS
- Table output (color respects NO_COLOR) + optional JSON export
input_contract: newline-delimited asset file (domains, subdomains, IPs); --program keyword(s) to match
output_contract: stdout table keyed by asset, columns (asset, resolves, cert_san_match, http_fingerprint, confidence); optional JSON at --output
safe_test_target: example.com + hackerone.com + httpbin.org (all IANA/public-BBP; noninvasive DNS+TLS+HEAD only)
synonym_names: bbp-scope, scope-check, scopesanity
source_inspiration_url: github topic gap analysis (bug-bounty + pentesting) — no existing tool packages this workflow
