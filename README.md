# Vigiles

**The night watch for your dependencies.**

Named after the [Vigiles Urbani](https://en.wikipedia.org/wiki/Vigiles), Rome's night watchmen who patrolled for fires and threats before they could spread. Vigiles does the same for your software supply chain.

A single binary that scans your installed packages across **pip, npm, Homebrew, Cargo, and Go modules**, compares dependency files for changes, and surfaces known vulnerabilities alongside behavioral trust signals — things that help you make informed decisions about your dependencies.

## Quickstart

```bash
# Install
go install github.com/apoorv-kulkarni/vigiles@latest

# Or build from source
git clone https://github.com/apoorv-kulkarni/vigiles.git
cd vigiles
go build -o vigiles .

# Scan everything
./vigiles scan

# Compare dependency files
./vigiles diff requirements-old.txt requirements-new.txt
```

## Why this exists

On March 24, 2026, [backdoored versions of LiteLLM were published to PyPI](https://futuresearch.ai/blog/litellm-pypi-supply-chain-attack/). In 3 hours, they harvested SSH keys, cloud credentials, and Kubernetes secrets from an estimated 500,000 installations.

Existing tools like `pip-audit` and `npm audit` check against known CVE databases. That's necessary but insufficient — no advisory existed during the attack window. Vigiles adds heuristic checks and trust signals that surface risk before an advisory is published.

## How Vigiles fits in the landscape

Vigiles doesn't replace existing tools — it fills gaps between them.

| Capability | Existing tools | Vigiles |
|------------|---------------|---------|
| Known CVE scanning (pip, npm) | `pip-audit`, `npm audit`, `osv-scanner` | ✅ via OSV API |
| Homebrew CVE scanning | No OSV ecosystem exists | ❌ Skipped |
| `.pth` file scanning | Nothing packaged | ✅ Detects persistence techniques |
| Dependency diff with risk signals | Nothing packaged | ✅ requirements.txt + package.json |
| npm install script detection | Nothing packaged | ✅ Flags lifecycle hooks |
| Suspicious new npm dependency detection (diff) | Rare in CLI scanners | ✅ High-signal rule for obfuscated install hooks in newly added packages |
| Recently published version check | Nothing packaged | ✅ PyPI versions < 7 days old |
| Unpinned version detection | Various linters | ✅ Flags ranges and missing pins |
| Cross-ecosystem local scan | Run tools separately | ✅ pip + npm + brew |

## Commands

### `vigiles scan`

Scans installed packages for known vulnerabilities, heuristic red flags, and trust signals.

```bash
vigiles scan                              # auto-detect ecosystems
vigiles scan --ecosystems pip,npm         # specific ecosystems
vigiles scan --format json --output report.json
vigiles scan --format sarif --output vigiles.sarif
vigiles scan --format summary
vigiles scan --fail-on vulnerability      # exit 1 only for CVEs
vigiles scan --fail-on vulnerability,heuristic  # CVEs and heuristic red flags
vigiles scan --fail-on none               # always exit 0 (reporting only)
vigiles scan --skip-vuln                  # heuristics only, no network
vigiles scan --skip-recency               # skip PyPI recency check
vigiles scan --provenance --sigstore      # supply-chain metadata checks
vigiles scan --watch --watch-interval 2m --notify
vigiles scan --verbose                    # show per-phase timing
```

#### Provenance example

When you enable `--provenance`, Vigiles checks whether a package version published in a registry maps to a matching GitHub source tag (`1.2.3` or `v1.2.3`).

Example:

```bash
vigiles scan --ecosystems pip --provenance --format summary
```

Possible output line:

```text
ℹ️  samplepkg               1.4.2        pip      VIGILES-PROVENANCE-TAG-MISMATCH
```

Interpretation:
- Vigiles found a GitHub repo reference from registry metadata.
- It could not find a matching source tag for that exact version.
- This is a **trust signal** (informational), not proof of compromise.
- Follow-up: confirm release process, changelog, and signed artifacts before approving in CI.

### `vigiles diff`

Compares two dependency files and shows what changed, annotating new or changed packages with risk signals.

Supported:
- requirements.txt
- package.json
- package-lock.json

```bash
vigiles diff old-requirements.txt new-requirements.txt
vigiles diff --format json old/package.json new/package.json
```

Example:
```
  Diff: old.txt → new.txt (pip)
  ────────────────────────────────────────────────────────────

  NEW DEPENDENCY:
  anthropic ==0.25.0
  Signals:
  • new transitive dependency

  ~ flask                          ==2.3.0 → >=2.3
    ℹ️ VIGILES-UNPINNED: Dependency uses a version range, not an exact pin
  NEW DEPENDENCY:
  plain-crypto-js 4.2.1
  Signals:
  • new transitive dependency
  • new npm dependency has obfuscated lifecycle script (postinstall)

  ~ requests                       ==2.31.0 → ==2.32.0
  - boto3                          ==1.28.0
```


## Project configuration (.vigiles.yaml)

Place a `.vigiles.yaml` file in your project root to set persistent policy and suppress known-safe signals without touching CI flags.

```yaml
version: 1

policy:
  fail-on: vulnerability,heuristic  # default for this repo; --fail-on flag overrides

suppress:
  - id: VIGILES-NPM-INSTALL-SCRIPT
    package: esbuild
    reason: "known safe build tool, install script is benign"
    expires: 2027-01-01

  - id: VIGILES-RECENTLY-PUBLISHED
    package: my-internal-lib
    reason: "internal package, always recently published"
```

**Suppression fields:**

| Field | Required | Description |
| --- | --- | --- |
| `id` | yes | Signal ID to suppress (e.g. `VIGILES-NPM-INSTALL-SCRIPT`) |
| `package` | no | Limit suppression to a specific package name |
| `reason` | no | Human-readable justification (recommended) |
| `expires` | no | `YYYY-MM-DD` date after which the suppression no longer applies |

Expired suppressions emit a warning on stderr and are not applied. The `--fail-on` CLI flag always takes precedence over `policy.fail-on` in the config file.

## Signal types

Vigiles clearly distinguishes what it finds:

| Type | Meaning | Examples |
|------|---------|----------|
| `vulnerability` | Known CVE/GHSA from OSV database | CVE-2024-xxxx, GHSA-xxxx |
| `heuristic` | Package-level behavioral red flag | Typosquatting, version anomaly, suspicious new npm lifecycle script |
| `system-heuristic` | Host-level check, not tied to a specific package | `.pth` files, backdoor artifacts |
| `trust-signal` | Informational — not a vulnerability, but worth knowing | Recently published, unpinned, install scripts |

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Scan/diff completed, no findings matching `--fail-on` policy |
| `1` | Scan/diff completed, findings matching `--fail-on` policy exist |
| `2` | Runtime or usage error |

This makes Vigiles usable as a CI gate.

## GitHub Actions

### Block on CVEs, surface everything else as annotations

The recommended pattern: fail the build on known vulnerabilities, upload a
SARIF report so heuristics and trust signals appear as annotations in the
GitHub Security tab without blocking the build.

```yaml
- name: Install vigiles
  run: go install github.com/apoorv-kulkarni/vigiles@latest

- name: Scan dependencies
  run: vigiles scan --fail-on vulnerability --format sarif --output vigiles.sarif

- name: Upload to GitHub Code Scanning
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: vigiles.sarif
```

### Also block on heuristic red flags

```yaml
- name: Scan dependencies
  run: vigiles scan --fail-on vulnerability,heuristic --format sarif --output vigiles.sarif
```

### Gate on dependency diffs in pull requests

```yaml
- name: Check dependency changes
  run: vigiles diff --fail-on vulnerability,heuristic requirements-baseline.txt requirements.txt
```

### Reporting only (never blocks CI)

```yaml
- name: Scan dependencies
  run: vigiles scan --fail-on none --format sarif --output vigiles.sarif

- name: Upload to GitHub Code Scanning
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: vigiles.sarif
```

## JSON output

The `--format json` output is stable and machine-readable. Progress goes to stderr.

```json
{
  "version": "0.3.6",
  "timestamp": "2026-03-30T12:00:00Z",
  "duration_ms": 1820,
  "ecosystems": ["pip", "npm"],
  "packages": [...],
  "signals": [...],
  "summary": {
    "total": 3,
    "by_severity": {"high": 1, "info": 2},
    "by_type": {"vulnerability": 1, "trust-signal": 2},
    "vulnerabilities": 1,
    "heuristics": 0,
    "trust_signals": 2
  }
}
```

## Limitations

Vigiles provides **informational signals**, not security guarantees.

- **CVE coverage depends on OSV.** The OSV database is comprehensive but not instantaneous — newly disclosed vulnerabilities may take hours to days to appear.
- **Homebrew packages are not checked for CVEs.** No OSV ecosystem mapping exists for Homebrew. Vigiles inventories brew packages but cannot check them for known vulnerabilities.
- **Heuristic checks use pattern matching.** Typosquatting detection (edit distance), `.pth` file scanning, and persistence detection can produce false positives and will miss novel techniques.
- **Trust signals are informational, not conclusive.** A recently published version is not inherently malicious. An npm install script is not inherently dangerous. These signals provide context for human judgment.
- **Diff npm checks may call npm registry.** For newly added npm packages with exact versions, Vigiles may query package metadata to inspect lifecycle scripts.
- **Recency checks make live PyPI API calls.** One HTTP request per pip package (cached per scan). Use `--skip-recency` if this is too slow or you're offline.
- **Popular package lists are hardcoded.** Typosquatting detection compares against a static list of ~40 popular packages per ecosystem. This list will go stale over time.

## Design principles

- **Zero external Go dependencies** — stdlib only, single static binary
- **Honest about limitations** — severity falls back to "unknown" when CVSS data isn't available, Homebrew is skipped from CVE checks, signals are clearly typed
- **CI-friendly** — proper exit codes, clean JSON to stdout, progress to stderr
- **Offline capable** — `--skip-vuln --skip-recency` runs all heuristic checks with no network
- **Deduplication** — packages and signals are deduplicated across sources (e.g., npm local+global overlap)

## Roadmap

### Shipped

- [x] Cross-ecosystem scan (pip, npm, brew, cargo, go mod)
- [x] OSV vulnerability checking
- [x] Heuristic checks (typosquatting, `.pth` files, recency, unpinned versions)
- [x] Dependency diff with risk signals
- [x] Suspicious new npm package detection (obfuscated lifecycle scripts)
- [x] Install script deep inspection (`setup.py`, npm hooks)
- [x] Provenance verification — registry ↔ GitHub source tag matching
- [x] Sigstore attestation verification (PEP 740 metadata)
- [x] SARIF output for GitHub Code Scanning
- [x] Watch mode with desktop notifications
- [x] `--fail-on` CI policy flag (per signal type)
- [x] `.vigiles.yaml` project config (persistent policy + suppressions with expiry)

### v0.4 — signal quality and stateful detection

- [ ] Stateful diff — detect behavioral changes between versions (new lifecycle scripts, maintainer changes, package size delta)
- [ ] Baseline system — `vigiles baseline create` / `vigiles baseline diff` for tracking known state
- [ ] `go.sum` diff support
- [ ] Refresh popular package lists from a versioned JSON source
- [ ] Better signal explanations — human-readable reasoning, not just labels

## See also

- [osv-scanner](https://github.com/google/osv-scanner) — Google's multi-ecosystem CVE scanner
- [pip-audit](https://github.com/pypa/pip-audit) — Python vulnerability scanner
- [npm audit](https://docs.npmjs.com/cli/v10/commands/npm-audit) — built-in npm scanning

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).
Product planning and release goals live in [docs/PRD.md](docs/PRD.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).

---

*Quis custodiet ipsos custodes?* — Who watches the watchmen? The Vigiles do.
