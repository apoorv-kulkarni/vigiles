# Vigiles PRD

## Document status
- Version: v0.2
- Date: 2026-04-11
- Owner: Vigiles maintainers
- Horizon: Next 2 releases (v0.3.x to v0.4.x)
- Story evidence policy: User stories in this document are planning hypotheses unless marked validated.

## 1. Problem statement
Software supply chain attacks often land before CVEs are published. Teams need a fast, CI-friendly dependency risk check that combines known vulnerabilities with early trust signals and behavior-focused heuristics across ecosystems.

## 2. Target users
- Security-conscious individual developers.
- Platform and DevSecOps teams maintaining CI pipelines.
- OSS maintainers who want pre-advisory risk signals during dependency updates.

## 3. Product goals
1. Detect actionable dependency risk quickly in local dev and CI.
2. Provide clear, honest output that distinguishes known vulnerabilities from heuristics and trust context.
3. Support cross-ecosystem workflows from a single binary with stable machine-readable output.

## 4. Non-goals
- Guaranteed malware detection.
- Full SBOM lifecycle management.
- Replacing specialized ecosystem-native tooling.

## 5. User stories (hypotheses unless validated)

These stories are product planning inputs, not claims about confirmed user research.

| ID | Story | Confidence | Evidence | Validation plan |
|----|-------|------------|----------|-----------------|
| US-1 | As a developer, I want to scan installed dependencies and fail CI when findings are present. | Observed | Current CLI supports CI-style exit codes and JSON usage in README examples. | Collect 5+ issue/comments from CI users confirming gating usage. |
| US-2 | As a reviewer, I want a dependency diff annotated with risk signals before merging. | Observed | Existing diff command and fixture coverage indicate this workflow is expected. | Validate with maintainer feedback from real PR review flows. |
| US-3 | As a security engineer, I want SARIF output for GitHub Code Scanning. | Hypothesis | SARIF feature added; no adoption baseline tracked yet. | Track first 3 public repos adopting SARIF output in CI. |
| US-4 | As a maintainer, I want provenance and attestation signals to triage suspicious releases. | Hypothesis | Provenance and attestation checks are implemented, but usage evidence is limited. | Gather user reports on signal usefulness and false positive rate. |

Confidence legend:
- Validated: backed by direct interviews, telemetry, or repeated user evidence.
- Observed: inferred from issues/usage patterns, but not formally validated.
- Hypothesis: plausible need to test before prioritizing further expansion.

## 6. Functional requirements

### FR-1: Cross-ecosystem scan
- Inputs: local package state.
- Ecosystems: pip, npm, brew, cargo, go modules.
- Output: table, summary, JSON, SARIF.
- Acceptance criteria:
  - `vigiles scan --ecosystems pip,npm,cargo,gomod` succeeds when tools are available.
  - Unsupported ecosystems are rejected with exit code 2.

### FR-2: Finding taxonomy
- Every finding must include: type, severity, ID, summary, ecosystem, package/version context.
- Allowed types: vulnerability, heuristic, system-heuristic, trust-signal.
- Acceptance criteria:
  - JSON output includes typed findings and summary counts by type and severity.

### FR-3: Diff risk annotation
- Compare dependency manifests and annotate added/updated packages with signals.
- Acceptance criteria:
  - Added dependencies include a new-dependency trust signal.
  - Unpinned specs produce an unpinned trust signal.

### FR-4: Supply chain trust checks
- Provenance check: registry package metadata to GitHub tag match.
- Attestation check: PyPI release metadata inspection for PEP 740-style fields.
- Acceptance criteria:
  - `--provenance` emits informational signal when tag match is missing.
  - `--sigstore` emits trust signals for attested or missing-attestation cases.

### FR-5: Deep install script inspection
- Inspect setup.py and npm lifecycle hooks for suspicious install-time behavior.
- Acceptance criteria:
  - Suspicious patterns emit high-severity heuristic signals.

### FR-6: Watch mode for continuous checks
- Re-run scan periodically with optional desktop notifications.
- Acceptance criteria:
  - `--watch --watch-interval 2m` loops until interrupted.
  - `--notify` emits host notification on newly observed findings.

## 7. Non-functional requirements
- Single static binary, stdlib-only Go implementation.
- CI-safe behavior:
  - exit code 0: no findings
  - exit code 1: findings present
  - exit code 2: usage/runtime error
- Stable JSON contract for automation.
- Clear stderr/stdout separation for machine output modes.

## 8. Success metrics
- Adoption:
  - Number of weekly scans in CI (proxy from user feedback/issues).
  - Number of repositories using JSON or SARIF output.
- Detection utility:
  - Count of true-positive user-reported findings from heuristic/trust signals.
  - Reduction in time-to-review for dependency update PRs (qualitative feedback).
- Reliability:
  - Test pass rate remains green on default branch.
  - No breaking JSON schema changes without release note.

## 9. Release plan

### Release A (v0.3.x stabilization)
- Harden new supply chain checks (provenance, attestation, deep inspection).
- Improve signal wording to reduce false-positive confusion.
- Add fixtures and integration tests for trust-signal edge cases.

### Release B (v0.4.x expansion)
- Add at least one additional ecosystem scanner (candidate: composer or gem).
- Improve SARIF richness (rule metadata, remediation guidance).
- Add optional policy profile for CI gating thresholds.

## 10. Risks and mitigations
1. False positives from heuristic checks.
- Mitigation: keep labels explicit, severity conservative, and details explainable.

2. External API variability (PyPI/npm/GitHub).
- Mitigation: timeouts, best-effort behavior, and non-fatal trust checks.

3. Scope creep across ecosystems.
- Mitigation: prioritize signal quality and tests over breadth.

## 11. Open questions
1. Should provenance mismatches be configurable as warning vs fail in CI?
2. Should trust-signal severity be policy-tunable per organization?
3. What minimum SARIF fields are required for best GitHub Code Scanning UX?
4. Which ecosystem should be prioritized next: composer, gem, or nuget?

## 12. Assumptions to validate
1. Teams want trust signals in CI even when they are non-blocking.
2. Provenance and attestation checks provide enough value despite external API variability.
3. Summary and SARIF formats cover the most common automation use cases.
4. Cross-ecosystem breadth is more valuable than deeper single-ecosystem analysis for current users.

## 13. Decision log
- 2026-04-11: Adopt lightweight PRD format and keep roadmap aligned to measurable acceptance criteria.
- 2026-04-11: Mark user stories as evidence-scoped hypotheses to avoid conflating assumptions with validated user needs.
