# scopesift

**Scope Ownership Validator for Bug Bounty & Pentest Engagements**
*"which of these assets actually belong to the program?"*

![Go Version](https://img.shields.io/badge/go-1.21%2B-00ADD8.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-active-success.svg)

## Overview

Bug bounty programs and pentest scopes often list dozens of domains. Some are solid in-scope assets the company owns outright. Some are third-party SaaS (Heroku apps, Netlify sites, Zendesk help centers) that were handed a subdomain and forgotten about. Some are flat-out misconfigured. The third category is where money lives: subdomain takeovers, leaked assets, forgotten staging, off-by-one scope mistakes.

`scopesift` eats a scope file, probes each asset over DNS + TLS + HTTP, and scores how strongly the evidence ties back to a program identity you supply. It ranks SUSPICIOUS first so you see the interesting ones before the obvious HIGHs.

Built for hunters who get handed a scope list and want a one-minute sanity check before diving in.

## Features

- DNS + CNAME, TLS cert (SANs / issuer / subject org), and HTTP HEAD fingerprinting in one pass
- Keyword matching across every evidence source, scored per asset
- Four-tier confidence: HIGH, MEDIUM, LOW, SUSPICIOUS
- Third-party host fingerprint library (Heroku, Netlify, Vercel, GitHub Pages, Azure, S3, Fastly, and more)
- Parallel probing with optional JSON export

## Installation

```bash
git clone https://github.com/daniyalnasir-root/scopesift.git
cd scopesift
go build -o scopesift .
```

Or install straight into `$GOPATH/bin`:

```bash
go install github.com/daniyalnasir-root/scopesift@latest
```

Requires Go 1.21 or newer.

## Usage

Basic scan against a scope file with a program keyword:

```bash
./scopesift -i scope.txt -p 'hackerone,hackerone inc'
```

With JSON export:

```bash
./scopesift -i scope.txt -p 'gitlab' -o results.json
```

Tune concurrency and timeout for a large list:

```bash
./scopesift -i big-scope.txt -p 'shopify' -c 50 -t 15s
```

Pipe-friendly (no color) for CI or further processing:

```bash
./scopesift -i scope.txt -p 'acme' --no-color | grep SUSPICIOUS
```

The scope file is plain text, one asset per line. Blank lines and `#` comments are ignored. URLs get their scheme stripped automatically.

## Command Line Options

```
Required:
  -i <file>        scope file, one asset per line
  -p <kw,kw,...>   program keyword(s) to match against cert/DNS/HTTP evidence

Optional:
  -o <file>        write full JSON output to file
  -c <n>           concurrent workers (default 20)
  -t <duration>    per-probe timeout (default 10s)
  -v               verbose stderr logging
      --no-color   disable color (also honours NO_COLOR env)
  -h               show help
```

## Confidence Scoring

Each keyword contributes up to 3 points per asset:

| evidence type   | points | example |
|-----------------|--------|---------|
| cert SAN match  | +3     | SAN `hackerone.com` matches keyword `hackerone` |
| cert subj org   | +3     | cert subject org "HackerOne Inc." matches `hackerone inc` |
| CNAME match     | +2     | CNAME resolves into program-owned domain |
| HTTP Server     | +1     | `Server` header contains keyword |
| Redirect target | +1     | `Location` header contains keyword |

Tiers:

- **HIGH**: score ≥ 3. Strong ownership evidence.
- **MEDIUM**: score 1–2. Some signal but not conclusive.
- **LOW**: score 0, no third-party fingerprint matched.
- **SUSPICIOUS**: score 0, but the asset resolves into a known third-party host (Heroku, Netlify, Vercel, etc.). These are the ones worth looking at.
- **UNRESOLVED**: DNS failed.

Results sort SUSPICIOUS → HIGH → MEDIUM → LOW → UNRESOLVED so the interesting items float to the top.

## Output Example

```
# ./scopesift -i examples/scope-mixed.txt -p 'hackerone' -o examples/mixed-results.json
ASSET                 CONFIDENCE    SCORE   FINGERPRINT                     EVIDENCE
--------------------  ------------  ------  ------------------------------  --------------------
netlify.app           SUSPICIOUS    0       Netlify                         third-party:netlify.app
hackerone.com         HIGH          3       cloudflare                      cert-san:hackerone.com
www.hackerone.com     HIGH          3       cloudflare                      cert-san:hackerone.com
google.com            LOW           0       gws
github.com            LOW           0       github.com
example.com           LOW           0       cloudflare

summary: 6 assets  |  HIGH=2  MEDIUM=0  LOW=3  SUSPICIOUS=1  UNRESOLVED=0
```

Typical run timing on a 50-asset scope with default concurrency:

```bash
$ time ./scopesift -i scope-50.txt -p 'acme'
...
real    0m6.412s
user    0m0.204s
sys     0m0.088s
```

## How It Works

For each asset:

1. If it's an IP, skip DNS. Otherwise resolve A/AAAA and capture any CNAME.
2. Open a TLS connection to `:443` (skipping verification; we inspect, we don't trust) and read the leaf certificate's SAN list, issuer CN/O, and subject CN/O.
3. Send an HTTP HEAD to `https://` first, falling back to `http://` if that fails. Record the `Server` and `Location` headers.
4. Score each evidence source against every keyword and classify.
5. Render a sorted table and optionally dump raw results as JSON.

All probes run in parallel with a worker pool. The default `20` is a safe floor for most ISPs; bump `-c` for big lists.

## Notes

- The tool does not brute-force subdomains, scan ports, or send anything resembling an exploit payload. It's pure fingerprinting over three standard protocols.
- Cert inspection uses `InsecureSkipVerify` so self-signed or expired certs still surface evidence. This is intentional.
- HEAD is used instead of GET to minimise bandwidth and server load. Some servers reject HEAD; those show up with empty Server values, which is fine for the scoring logic.
- Whois isn't in the default path because registrars rate-limit aggressively and the signal overlaps with cert org. Happy to add it behind a flag if people actually want it.

## Legal Disclaimer

This tool is for authorized security testing and educational use only.
Run it only against systems you own or have explicit written permission to test.
The author accepts no liability for misuse. Unauthorized scanning may violate
local, state, or federal law.

## About the Author

[Daniyal Nasir](https://www.daniyalnasir.com) is a senior **Cybersecurity Consultant**, **Penetration Tester**, and **VAPT (Vulnerability Assessment and Penetration Testing) Consultant** serving clients worldwide. With 10+ years of hands-on **offensive security**, **ethical hacking**, and **bug bounty hunting** experience, he delivers **web application penetration testing**, **API security testing**, **network penetration testing**, **mobile application security assessments**, and **cloud security audits** for Fortune 500 enterprises and high-growth SaaS platforms. Holds **OSCP**, **LPT**, **CPENT**, **CEH**, **CISA**, **CISM**, and **CASP+** certifications.

- LinkedIn: https://www.linkedin.com/in/daniyalnasir
- Website:  https://www.daniyalnasir.com

## License

MIT, see [LICENSE](LICENSE).
