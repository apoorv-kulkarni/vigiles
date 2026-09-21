# Enforcing checks for agent-generated changes

Vigiles has two enforcement entry points:

- `vigiles gate --base <full-commit-id> --head <full-commit-id>` audits committed
  dependency changes with policy from the base commit. It emits JSON only.
- `vigiles diff --strict old/requirements.txt new/requirements.txt` checks local
  file snapshots and returns exit 2 when the comparison cannot be completed.

The repository includes a composite GitHub Action in `action.yml`. Consumers
must pin the reviewed commit containing that file. Adding it to this repository
does not publish a Marketplace release or configure consumer branch protection.

## Verdicts and scope

The gate returns `pass` (exit 0), `blocked` (exit 1), or `incomplete` (exit 2).
An incomplete result always blocks, including when the base policy says
`fail-on: none`. Suppressions apply to findings, never coverage failures.

The gate performs dependency **diff** checks: pinning, typosquats, npm lifecycle
and publisher changes, and recency for new pinned PyPI dependencies. It does
not perform a CVE scan, execute packages, sandbox an agent, or inspect arbitrary
source code. Use a separate vulnerability check when that is required.

The report records the exact base/head commit IDs, policy SHA-256, every selected
manifest's Git blob IDs, and the SHA-256 of its inspected content. These identify
what was checked; they are not signatures or permission to execute later-changed
content. The caller must bind approval to these inputs and rerun on changes.

## Policy and input selection

The gate reads `.vigiles.yaml` from the **base commit**, not the working tree or
PR head. Missing base policy defaults to `fail-on: all`. Proposed policy changes
are indicated by `policy_changed` and take effect only after they enter the
trusted base. A protected policy could contain:

```yaml
version: 1
policy:
  fail-on: vulnerability,heuristic,system-heuristic
```

Including `vulnerability` does not add CVE checks to the diff gate. Trust signals
remain visible under this example policy without blocking on their own.

Inputs are discovered recursively from both Git trees, including added and
deleted manifests. The gate offers no file-list, suppression-file, skip-check,
or `--fail-on` override. It reads Git objects without checkout filters or hooks,
ignores Git replacement objects, rejects symlink manifests and submodules, and
limits individual Git command output to 8 MiB. Both commits must already be
available locally; unavailable objects fail the gate.

Recognized names are `package.json`, `package-lock.json`, `requirements.txt`,
`requirements-*.txt`, `requirements_*.txt`, and `constraints.txt`, at any depth.
There are no implicit vendor-directory exclusions. Changes to recognized
unsupported manifests (for example `uv.lock`, `pyproject.toml`, `pnpm-lock.yaml`,
`go.mod`, or `.mcp.json`) produce an incomplete verdict. No supported manifests
also produces an incomplete verdict. This is not discovery of every possible
dependency source: custom filenames, generated inputs and installation commands
in source or workflow files require separate controls.

Strict parsing deliberately refuses syntax it cannot faithfully compare:

- Requirements includes, editable installs, options, URLs, environment markers
  and duplicate normalized package names. Includes are reported as incomplete;
  they are not silently skipped or automatically followed.
- npm lockfile v1, linked packages, multiple versions of the same name, missing
  versions, non-public-registry artifact URLs, ambiguous JSON, and package
  overrides or bundled dependency declarations.
- Added or updated npm dependencies without exact registry versions. The gate
  currently compares each manifest independently; a neighboring lockfile does
  not resolve ranges in `package.json`.
- Changed unpinned pip dependencies, unavailable npm metadata, and unavailable
  recency data for new PyPI releases.

These restrictions can block legitimate projects. Expand parser coverage with
fixtures rather than suppressing incomplete checks. Unchanged dependencies are
not fetched again. Same-version changes to npm lockfile artifact locations or
integrity emit `VIGILES-NPM-ARTIFACT-CHANGE` for review.

## GitHub Actions integration

Use a fresh Linux runner in a dedicated job. This initial Action supports only
`pull_request` events; merge queues and other events are not yet supported.
Replace the placeholder below with a reviewed full commit SHA after the Action
is committed and available remotely:

```yaml
name: Dependency gate
on: [pull_request]
permissions:
  contents: read
jobs:
  vigiles:
    name: Vigiles dependency gate
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8 # v5.0.0
        with:
          fetch-depth: 0
          persist-credentials: false
      - name: Gate dependency changes
        id: vigiles
        uses: apoorv-kulkarni/vigiles@<REVIEWED_FULL_COMMIT_SHA>
```

The Action obtains the expected commits from the PR event, builds its own pinned
source with the pinned setup-go Action and Go 1.26.4, and uses a fresh build
cache. It does not build or install target-project code. `outputs.report` points
to the full JSON report in the runner's temporary directory, including blocked
or incomplete runs; `outputs.verdict` contains the verdict when one is produced.
The job summary contains only validated hashes and counts. An upload step may
preserve the JSON using `if: always()` and an independently pinned artifact Action.

Required repository controls are outside the CLI:

1. Require the gate for merging and restrict bypass permissions and direct pushes.
2. Protect the workflow, any scripts it invokes, `.vigiles.yaml`, and `CODEOWNERS`
   itself through required maintainer review. Where available, require a centrally
   managed workflow through organization rulesets.
3. Restrict the expected status-check source and do not give the agent credentials
   that can alter repository rules or forge the trusted gate's result. Selecting
   the GitHub Actions App alone does not identify a particular workflow.
4. Do not conditionally skip the gate, use `continue-on-error`, or execute
   PR-controlled scripts in its job. A skipped GitHub job can count as successful.
5. Require a check on the current candidate revision. Never treat an old JSON
   artifact or an agent's statement that checks passed as a fresh verdict.

Do not use `pull_request_target` to execute PR code with privileged credentials.
Agent-created PR approval/trigger settings must also be configured on GitHub;
an Action cannot guarantee it gets scheduled.

## Local agents

A local agent can consume `diff --strict --format json` immediately. An external
launcher must choose the inputs and trusted policy and enforce the exit code.
The ordinary `diff` command still reads local `.vigiles.yaml`, so an agent that
can modify that policy can change which findings block it. For committed work,
use `gate` with base/head selected by the trusted launcher; it ignores local policy.

`scan --strict` additionally turns known inventory, OSV, recency and reported
Python `.pth` coverage failures into exit 2, preserves partial findings, and
rejects skip flags. Empty inventory is incomplete. Homebrew has no OSV coverage.
Strict scan does not support the best-effort provenance/attestation options.
The normal scan remains reporting-compatible, with `status`, `incomplete`, and
`skipped` fields explaining known coverage limits; it no longer prints a clean
banner when a known check failed. This records known failures, not a proof that
every heuristic covered every installed file.

No agent-specific runtime hook or MCP configuration parser ships in this change.
Installing a hook later must cover alternative execution routes and keep its
policy, executable and credentials outside the agent's writable environment.
With unrestricted access as the same OS user, an agent can bypass a local CLI.
Treat package names, descriptions and remediation text as untrusted evidence,
not executable instructions.

## Validation and references

`make test` includes fixtures for policy tampering, immutable Git inputs, duplicate
keys, includes, symlinks, missing coverage and registry failures. The wrapper
preserves the process exit code and validates that a passing report refers to the
expected commits and inspected inputs.

- [GitHub status checks](https://docs.github.com/en/pull-requests/reference/status-checks)
- [GitHub Actions security guidance](https://docs.github.com/en/actions/reference/security/secure-use)
- [Repository rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets)
