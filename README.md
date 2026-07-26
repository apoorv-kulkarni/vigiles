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
| ---------- | ------------- | ------- |
| Known CVE scanning (pip, npm) | `pip-audit`, `npm audit`, `osv-scanner` | ✅ via OSV API |
| Homebrew CVE scanning | No OSV ecosystem exists | ❌ Skipped |
| `.pth` file scanning | Nothing packaged | ✅ Detects persistence techniques |
| Dependency diff with risk signals | Nothing packaged | ✅ requirements.txt + package.json |
| npm install script detection | Nothing packaged | ✅ Flags lifecycle hooks |
| Suspicious new npm dependency detection (diff) | Rare in CLI scanners | ✅ High-signal rule for obfuscated install hooks in newly added packages |
| Behavioral change across npm versions (diff) | Nothing packaged | ✅ Flags install hooks and publisher changing on an update |
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

```text
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

#### npm update checks

When an npm dependency is **updated** between exact versions, Vigiles compares
registry metadata for both versions and reports what changed about install-time
behavior. Unlike the new-package rule, popular packages are not exempt: a
trusted package that suddenly gains an install hook is exactly the pattern worth
catching.

```text
  ~ axios                          0.19.0 → 1.7.2
    ℹ️ VIGILES-NPM-PUBLISHER-CHANGE: Publisher changed from 'emilyemorehouse' to 'jasonsaayman'
  ~ esbuild                        0.19.0 → 0.21.5
  ~ puppeteer                      1.0.0 → 22.0.0
    🟡 VIGILES-NPM-LIFECYCLE-SCRIPT-CHANGE: Install-time script added (postinstall)
    ℹ️ VIGILES-NPM-PUBLISHER-CHANGE: Publisher changed from 'aslushnikov' to 'google-wombot'
  ~ sharp                          0.28.0 → 0.33.0
    🟡 VIGILES-NPM-LIFECYCLE-SCRIPT-CHANGE: Install-time script modified (install)
```

| Signal | Type | Severity |
| ------ | ---- | -------- |
| `VIGILES-NPM-LIFECYCLE-SCRIPT-CHANGE` | `heuristic` | `high` if the new command looks obfuscated, otherwise `medium` |
| `VIGILES-NPM-PUBLISHER-CHANGE` | `trust-signal` | `info` |

A publisher change is common for projects with several maintainers or automated
releases, so it is context rather than evidence of compromise. Both checks are
best-effort: version ranges are skipped because they don't identify a single
release, and a registry failure produces no signals rather than an error.

Only `preinstall`, `install`, and `postinstall` are compared. `prepare` is
excluded because it does not run for consumers installing from the registry, so
changes to it are noise in a dependency diff.

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
| ---- | ------- | -------- |
| `vulnerability` | Known CVE/GHSA from OSV database | CVE-2024-xxxx, GHSA-xxxx |
| `heuristic` | Package-level behavioral red flag | Typosquatting, version anomaly, suspicious new npm lifecycle script |
| `system-heuristic` | Host-level check, not tied to a specific package | `.pth` files, backdoor artifacts |
| `trust-signal` | Informational — not a vulnerability, but worth knowing | Recently published, unpinned, install scripts |

## Exit codes

| Code | Meaning |
| ---- | ------- |
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
- **CVE lookups take two round trips.** OSV's `/v1/querybatch` returns only advisory IDs, so Vigiles fetches each distinct advisory from `/v1/vulns/{id}` to get its summary, severity, aliases, and fixed versions. Lookups are deduplicated across packages and run concurrently. If a detail fetch fails the finding is still reported, with `unknown` severity.
- **Severity is derived, not always published.** Vigiles scores the CVSS v3.x vector when one is present and otherwise uses the advisory's own qualitative rating. CVSS v4-only advisories without a qualitative rating fall back to `unknown` rather than being guessed at.
- **Homebrew packages are not checked for CVEs.** No OSV ecosystem mapping exists for Homebrew. Vigiles inventories brew packages but cannot check them for known vulnerabilities.
- **Heuristic checks use pattern matching.** Typosquatting detection (edit distance), `.pth` file scanning, and persistence detection can produce false positives and will miss novel techniques.
- **`.pth` scanning follows the interpreters it can find.** Vigiles checks the active virtualenv, a project-local `.venv`/`venv`/`env`, and `python3` on `PATH`, covering both the shared and per-user site directories of each. A virtualenv in some other location is not scanned. If Python packages were inventoried but no interpreter could be queried, Vigiles emits `VIGILES-PTH-SCAN-SKIPPED` rather than reporting a clean result.
- **Trust signals are informational, not conclusive.** A recently published version is not inherently malicious. An npm install script is not inherently dangerous. These signals provide context for human judgment.
- **Diff npm checks may call npm registry.** For npm packages pinned to exact versions, Vigiles queries package metadata to inspect lifecycle scripts: one request for a newly added package, and two for an update (the old and the new version). Metadata is not cached across packages.
- **Recency checks make live PyPI API calls.** One HTTP request per pip package (cached per scan). Use `--skip-recency` if this is too slow or you're offline.
- **Popular package lists are hardcoded.** Typosquatting detection compares against a static list of ~40 popular packages per ecosystem. This list will go stale over time.

## Design principles

- **Zero external Go dependencies** — stdlib only, single static binary
- **Honest about limitations** — severity falls back to "unknown" when no CVSS vector or qualitative rating is available, Homebrew is skipped from CVE checks, signals are clearly typed
- **Checks that can't run say so** — a security check that silently skips is worse than one that fails loudly
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

This release prioritizes depth on the ecosystems where install-time attacks
actually land over breadth across new ecosystems.

- [x] Stateful npm diff: compare registry metadata across versions on update, not only on first install
  - [x] Lifecycle script added or changed between the old and new version
  - [x] Publisher (`_npmUser`) change between the old and new version
- [ ] `go.sum` diff support
- [ ] Refresh popular package lists from a versioned JSON source
- [ ] Remediation coverage: give every `VIGILES-*` signal an actionable fix hint (today only OSV findings and suspicious new npm packages have one)

Deferred, with reasons:

- **CVSS v4.0 base-score calculator**: v4 scoring needs a 270-entry MacroVector
  lookup table plus interpolation. Across a 268-advisory sample only 19 carried
  v4 without v3, and 18 of those already published a qualitative rating that
  Vigiles now uses, so the table would change essentially no verdicts today.
  Revisit when v4-only advisories without a qualitative rating become common.
- **Baseline command** (`vigiles baseline create` / `vigiles baseline diff`): the
  stateful diff above needs no persisted state, so a state file, schema, and
  staleness handling buy little right now.
- **Stateful pip diff**: the PyPI JSON API exposes no per-release publisher
  identity, and `info.maintainer` is frequently absent, so publisher-change
  detection is not implementable there. Artifact size and upload time stay
  open as narrower follow-ups.
- **Package size delta**: needs false-positive calibration against real update
  history before it earns a signal.
- **New ecosystem scanners** (composer, gem, nuget): revisit once the stateful
  signals above are calibrated.

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
