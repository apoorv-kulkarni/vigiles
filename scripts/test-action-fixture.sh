#!/usr/bin/env bash
set -euo pipefail

# Synthetic PRs keep the hosted composite tests deterministic and offline.
fixture_dir=$(mktemp -d "$RUNNER_TEMP/vigiles-fixture.XXXXXXXX")
git init -q "$fixture_dir/repo"
cd "$fixture_dir/repo"
export GIT_AUTHOR_NAME=Fixture GIT_COMMITTER_NAME=Fixture
export GIT_AUTHOR_EMAIL=fixture@example.test GIT_COMMITTER_EMAIL=fixture@example.test

cat > package-lock.json <<'JSON'
{"lockfileVersion":3,"packages":{"node_modules/a":{"version":"1.0.0","resolved":"https://registry.npmjs.org/a/-/a-1.0.0.tgz","integrity":"sha512-old"}}}
JSON
git add package-lock.json
base=$(git commit-tree "$(git write-tree)" -m base)
case "$1" in
  pass) ;;
  blocked)
    sed 's/sha512-old/sha512-new/' package-lock.json > next.json
    mv next.json package-lock.json
    ;;
  incomplete) printf '%s\n' '-r hidden.txt' > requirements.txt ;;
  *) echo 'Expected pass, blocked or incomplete fixture.' >&2; exit 2 ;;
esac
git add .
head=$(git commit-tree "$(git write-tree)" -p "$base" -m head)
jq -n --arg base "$base" --arg head "$head" \
  '{pull_request: {base: {sha: $base}, head: {sha: $head}}}' > "$fixture_dir/event.json"

# BASH_ENV supplies the synthetic event only inside the test's Action step.
# No fixture switches or policy bypass inputs are added to the public Action.
{
  printf 'export GITHUB_EVENT_NAME=pull_request\n'
  printf 'export GITHUB_EVENT_PATH=%q\n' "$fixture_dir/event.json"
  printf 'export GITHUB_WORKSPACE=%q\n' "$fixture_dir/repo"
} > "$fixture_dir/env.sh"
{
  printf 'env=%s\n' "$fixture_dir/env.sh"
  printf 'base=%s\nhead=%s\n' "$base" "$head"
} >> "$GITHUB_OUTPUT"
