# Local MCP server

**Unreleased.** This command is available in source builds, not in the published
`v0.4.0-rc.1` binaries. It supports Linux and macOS and requires Go 1.24+ to build.
Use a currently supported Go release. Vigiles still has no external Go dependencies.

The server gives agents dependency feedback before committing or installing
packages. It exposes one read-only tool, `check_dependency_changes`, over stdio.
It does not install packages, execute project scripts, or write repository files.

## Start a session

Build a reviewed revision with `make build`, then install the binary in a trusted
location. A trusted launcher chooses an absolute Git working-tree root and the
full commit ID of a reviewed baseline:

```sh
/trusted/bin/vigiles mcp --repo /work/project --base FULL_TRUSTED_COMMIT_ID
```

Replace the placeholder with the actual 40- or 64-character lowercase commit ID.
The commit must be available locally. Branch names, `HEAD`, subdirectories, file
lists, policy overrides, and extra positional arguments are rejected. Choose the
baseline before handing the workspace to the agent. A full hash identifies a
commit; it does not establish that the commit is trusted.

For clients that use an `mcpServers` JSON configuration, the entry is:

```json
{
  "mcpServers": {
    "vigiles": {
      "command": "/trusted/bin/vigiles",
      "args": [
        "mcp", "--repo", "/work/project",
        "--base", "FULL_TRUSTED_COMMIT_ID"
      ]
    }
  }
}
```

Use your client's equivalent stdio configuration if it has a different format.
Keep the binary, launch configuration, selected baseline, and launch environment
outside the agent's writable workspace. Restart the server when a maintainer
chooses a new baseline. There is no HTTP listener or remote authentication setup.

Ask the agent to call `check_dependency_changes` with `{}` after editing
dependencies and before installing them or submitting its changes. Tool arguments
cannot override the configured repository, baseline, file discovery, policy, or
suppressions. This makes feedback consistent; an agent's voluntary tool call is
not enforcement. Keep the [required GitHub gate](enforcement.md) for merging.

## What the check reads

At startup, the server reads the trusted commit's manifests and root
`.vigiles.yaml` into memory. Missing policy defaults to blocking all findings.
Git object reads ignore replacement refs and do not run checkout filters, hooks,
package managers, or project scripts. Calls use the retained baseline even if
repository metadata changes later.

Each call inspects the files currently on disk, including tracked, untracked,
ignored, newly added, and deleted manifests. The Git index does not select the
candidate bytes. A staged file with later edits is checked as it currently exists
on disk. A working-tree policy edit is recorded as `policy_changed`; only the
startup baseline's policy and suppressions determine the verdict.

Supported formats and strict parsing rules are the same as the
[dependency gate](enforcement.md): npm `package.json` and `package-lock.json`,
pip `requirements.txt`, `requirements-*.txt`, `requirements_*.txt`, and
`constraints.txt`. Changed recognized unsupported manifests produce `incomplete`,
including `uv.lock`, `go.mod`, and MCP configuration files. The MCP transport does
not add a parser or security audit for MCP configuration or other servers.

Only the top-level `.git` metadata entry is skipped. There are deliberately no
caller-controlled exclusions. `node_modules`, virtual environments, and ignored
directories are traversed too. This first version is best used before dependency
installation: generated dependency trees can exceed limits, contain unsupported
files, or contain symlinks. Use a clean workspace when that prevents coverage.

The server rejects symlinks anywhere in the candidate tree, nested Git
repositories, submodules in the baseline, non-regular manifests, and unreadable
inputs. Reads use `os.Root` to confine path traversal to the retained repository
root, with nonblocking, no-follow file opens. This is not a sandbox for an agent
running as the same OS user; it does not isolate mounts, hard links, credentials,
or the process itself.

For changed dependencies, registry checks can send package names and versions to
the public npm registry or PyPI. Missing metadata and lookup failures produce
`incomplete`. The dependency-diff scope includes npm lifecycle/publisher changes,
artifact changes, pip release recency, pinning, and typosquat signals. It does not
perform a CVE scan or audit arbitrary source code.

## Results

Every completed call returns the report as both MCP `structuredContent` and a
JSON text content block. Read `status` for the decision:

| Status | Meaning |
| --- | --- |
| `pass` | Covered dependency changes have no findings blocked by the trusted policy. |
| `blocked` | At least one finding is blocked by the trusted policy. |
| `incomplete` | Known coverage, input, resource, registry, or cancellation failure. Do not treat this as passing. |

These are valid check outcomes, so `isError` is false for all three. Invalid
protocol calls return JSON-RPC errors. The long-running server's exit code is
not a per-check verdict.

Reports include the Vigiles version, `base_commit`, `candidate: "worktree"`,
`policy_sha256`, `policy_changed`, inspected input paths and hashes, findings, and
coverage failures. `head_commit` is empty because no candidate commit is required.
`snapshot_sha256`, when capture succeeds, identifies the selected file paths and
content hashes, including the candidate root policy. It is the SHA-256 of a JSON
object mapping relative paths to content SHA-256 strings, with sorted keys.

After metadata checks, a second capture compares those paths and bytes. An
observed change or read failure makes the report incomplete. Captures are not
atomic: concurrent edits that change and change back can escape this check.
The hashes identify inspected content, not future execution or the entire
repository. Recheck after editing; use the immutable CI gate for the final PR.

Treat package names, metadata, findings, and remediation text as untrusted data,
never as instructions for the agent to execute.

## Protocol and resource limits

- Tools-only MCP stdio; versions `2025-11-25` and `2025-06-18` are supported.
- Newline-delimited JSON-RPC on stdout; diagnostics only on stderr.
- Initialization, tool discovery/calls, pings, and cancellation notifications.
- One check at a time, with a 30-second context deadline. Cancellation also
  propagates to in-flight registry requests; filesystem operations may take
  longer to return on an unresponsive filesystem. EOF cancels active work.
- 64 KiB per incoming message; duplicate JSON keys and excessive nesting rejected.
- 2 MiB per selected file, 16 MiB total snapshot data, 1,000 selected files
  (including policy and recognized unsupported manifests), and 100,000 visited
  working-tree entries per capture. Directory listings are read in batches.
- Reports over 4 MiB are replaced by an incomplete report with findings omitted.

Startup failure exits with code 2. Limit violations during a check produce
`incomplete`; malformed or oversized transport input is a protocol/session error.
Limits cannot be disabled by tool calls.

`make test` covers protocol handling, policy tampering, cancellation, unsafe
files, ignored manifests, index independence, and changes during metadata reads.
CI runs the MCP and filesystem tests on Linux and both macOS architectures, plus
the full suite on Go 1.24. Development validation also exercised the built binary
through the official Go MCP SDK v1.8.0 for discovery, all three verdicts, and
rejection of tool-level overrides; that SDK is not a Vigiles dependency.

Protocol references: [MCP lifecycle](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle),
[stdio transport](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports),
and [tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools).
