# Release artifacts

Starting with the next release after v0.3.8, the release workflow builds:

| Platform | Binary | Provenance |
| --- | --- | --- |
| Linux AMD64 | `vigiles` | `vigiles.intoto.jsonl` |
| macOS Intel | `vigiles-darwin-amd64` | `vigiles-darwin-amd64.intoto.jsonl` |
| macOS Apple Silicon | `vigiles-darwin-arm64` | `vigiles-darwin-arm64.intoto.jsonl` |

Each target uses its own SLSA Go builder invocation. The Linux filename is kept
for existing consumers. All three builds must succeed before the workflow
creates the GitHub release and uploads all six assets.

Download the binary for your machine from the
[release page](https://github.com/apoorv-kulkarni/vigiles/releases), make it
executable with `chmod +x <binary>`, and run `<path-to-binary> version`.
The macOS binaries are not Apple-signed or notarized.

## Version reporting

- Release binaries embed the triggering tag, including prerelease suffixes.
- The composite Action embeds its own ref: a tag or full commit ID. Consumers
  should pin a reviewed full commit ID. Local Action usage embeds the checkout
  revision as `git-<commit>`.
- `go install ...@<version>` reports the module version recorded by Go.
- Source builds use Go's recorded module version when available (which can be a
  pseudo-version with a dirty suffix), otherwise the Git revision with `-dirty`
  for modified checkouts. Builds without version metadata report `dev`.

There is no hardcoded previous release number to update. An explicit linker
override of `cmd.Version` takes precedence over Go build metadata.

## Validation and publication

CI executes the binary on Linux AMD64, macOS AMD64 and macOS ARM64, checking the
platform, version override and CLI startup. It also exercises the real composite
Action's pass, blocked and incomplete paths on a Linux GitHub-hosted runner.
These smoke tests do not generate SLSA provenance; the tag-triggered release
workflow performs those builds and signs provenance.

After merging the release changes, pushing a signed `v*` tag triggers publication.
A tag containing a prerelease suffix, such as `v0.4.0-rc.1`, creates a prerelease
and is not marked as the latest stable release. Creating the release is separate
from publishing the Action's Marketplace listing. The Action is usable directly
from its reviewed repository commit before a Marketplace listing exists.
