# Contributing to Vigiles

Thank you for your interest in contributing.

## Getting started

```bash
git clone https://github.com/apoorv-kulkarni/vigiles.git
cd vigiles
go build -o vigiles .
go test ./... -v -count=1
```

Vigiles requires Go 1.22+ and has **zero external dependencies** — stdlib only. Please keep it that way.

## What to work on

Priority areas (highest impact first):

1. **New heuristic checks** — this is where Vigiles is most differentiated. If you've seen a supply chain attack technique that Vigiles doesn't detect, open an issue or PR.
2. **Provenance verification** — PyPI/npm registry → GitHub source tag matching.
3. **New ecosystem scanners** — `cargo`, `go mod`, `composer`, `gem`. Implement the `Scanner` interface in `internal/scanner/`.
4. **Test coverage** — especially fixture-based tests in `testdata/`.

## Guidelines

- Keep PRs small and focused. One feature or fix per PR.
- Add tests for new signals and parsers. Use `testdata/` for fixture files.
- Run `go vet ./...` and `go test ./... -count=1` before submitting.
- Don't add external Go dependencies without discussion.
- Be honest in signal descriptions. Don't overclaim detection certainty. A heuristic that says "possible typosquat" is better than one that says "malicious package detected."

## Signal types

When adding new checks, use the correct signal type:

| Type | When to use |
|------|-------------|
| `vulnerability` | Known CVE/GHSA from a vulnerability database |
| `heuristic` | Package-level behavioral red flag (typosquat, version anomaly) |
| `system-heuristic` | Host-level check not attributable to a specific package (.pth files, backdoor artifacts) |
| `trust-signal` | Informational context (recently published, unpinned, install scripts) |

## Code structure

```
internal/signal/       Core Signal model — all checkers produce []signal.Signal
internal/scanner/      Package inventory per ecosystem (Scanner interface)
internal/checker/      Risk analysis (OSV, heuristics, recency, pinning, npm scripts)
internal/diff/         Dependency file comparison
internal/reporter/     Output formatting (table, JSON, summary)
cmd/                   CLI entry point
testdata/              Test fixtures
```

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
