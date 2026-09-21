#!/usr/bin/env bash
set -euo pipefail

if [[ "${RUNNER_OS:-}" != Linux || "${GITHUB_EVENT_NAME:-}" != pull_request ]]; then
  echo 'Vigiles currently requires a Linux runner and a pull_request event.' >&2
  exit 2
fi

base_sha=$(jq -er '.pull_request.base.sha' "$GITHUB_EVENT_PATH")
head_sha=$(jq -er '.pull_request.head.sha' "$GITHUB_EVENT_PATH")
if [[ ! "$base_sha" =~ ^[a-f0-9]{40}$ || ! "$head_sha" =~ ^[a-f0-9]{40}$ || "$base_sha" == "$head_sha" ]]; then
  echo 'Vigiles requires distinct full base and head commit IDs from the PR event.' >&2
  exit 2
fi

gate_dir=$(mktemp -d "$RUNNER_TEMP/vigiles.XXXXXXXX")
report="$gate_dir/report.json"
printf 'report=%s\n' "$report" >> "$GITHUB_OUTPUT"

# Build only the pinned Action's source. Never use the target's Go workspace,
# compiler flags, dependencies, build cache or executable named "vigiles".
cd "$VIGILES_ACTION_PATH"
version=${VIGILES_ACTION_REF:-}
if [[ -z "$version" ]]; then
  version="git-$(git rev-parse HEAD)"
fi
if [[ ! "$version" =~ ^[a-zA-Z0-9._/+~-]+$ ]]; then
  echo 'Vigiles received an invalid Action ref.' >&2
  exit 2
fi
GOWORK=off GOENV=off GOFLAGS='' GOTOOLCHAIN=local CGO_ENABLED=0 \
  GOPROXY=off GOPATH="$gate_dir/go" GOCACHE="$gate_dir/cache" \
  go build -mod=readonly -trimpath -buildvcs=false \
    -ldflags "-X github.com/apoorv-kulkarni/vigiles/cmd.Version=$version" \
    -o "$gate_dir/vigiles" .

status=0
"$gate_dir/vigiles" gate --repo "$GITHUB_WORKSPACE" --base "$base_sha" --head "$head_sha" > "$report" || status=$?

verdict=$(jq -er '.status' "$report")
case "$status:$verdict" in
  0:pass)
    jq -e --arg base "$base_sha" --arg head "$head_sha" \
      '.base_commit == $base and .head_commit == $head and (.inputs | length) > 0 and (.incomplete | length) == 0' \
      "$report" > /dev/null
    ;;
  1:blocked|2:incomplete) ;;
  *) echo 'Vigiles did not produce a valid completed verdict.' >&2; exit 2 ;;
esac
printf 'verdict=%s\n' "$verdict" >> "$GITHUB_OUTPUT"

# Render only trusted headings, validated hashes and counts as Markdown.
{
  printf '## Vigiles: %s\n\n' "$verdict"
  printf 'Base: %s\n\nHead: %s\n\n' "$base_sha" "$head_sha"
  jq -r '"Manifests: \((.inputs // []) | length) | Findings: \((.signals // []) | length) | Coverage gaps: \((.incomplete // []) | length)"' "$report"
  printf '\nScope: dependency changes; this gate does not perform a CVE scan.\n'
} >> "$GITHUB_STEP_SUMMARY"

exit "$status"
