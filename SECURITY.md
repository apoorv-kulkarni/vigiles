# Security policy

## Reporting vulnerabilities

If you find a security vulnerability in Vigiles, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, email the maintainers directly. We will acknowledge receipt within 48 hours and aim to provide a fix or mitigation within 7 days for critical issues.

## Scope

Vigiles is a local scanning tool. It runs on your machine and makes outbound HTTP requests to:

- `api.osv.dev` — Google's open vulnerability database (for CVE checks)
- `pypi.org` — Python Package Index (for recency checks)

It does not accept inbound connections, run a server, or transmit any data about your packages to third parties beyond the queries listed above.

## Limitations

Vigiles provides **informational signals**, not guarantees. Specifically:

- CVE data comes from the OSV database and may be incomplete or delayed
- Heuristic checks (typosquatting, `.pth` scanning, persistence detection) use pattern matching that can produce false positives or miss novel attack patterns
- Trust signals (recently published, unpinned versions, install scripts) are informational context, not vulnerability assessments
- Vigiles does not sandbox or execute any package code

Always verify findings manually before taking action on production systems.
