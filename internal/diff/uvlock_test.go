package diff

import (
	"strings"
	"testing"
)

const uvLockFixture = `version = 1
revision = 3
requires-python = ">=3.8"

[[package]]
name = "demo"
version = "0.1.0"
source = { editable = "." }

[[package]]
name = "anyio"
version = "4.5.2"
source = { registry = "https://pypi.org/simple" }
resolution-markers = [
    "python_full_version < '3.9'",
]

[[package]]
name = "anyio"
version = "4.14.1"
source = { registry = "https://pypi.org/simple" }
resolution-markers = [
    "python_full_version >= '3.10'",
]

[[package]]
name = "certifi"
version = "2026.6.17"
source = { registry = "https://pypi.org/simple" }
`

func TestParseUVLockPreservesMultipleVersions(t *testing.T) {
	deps, err := parseUVLock([]byte(uvLockFixture))
	if err != nil {
		t.Fatalf("parseUVLock: %v", err)
	}
	if len(deps) != 3 {
		t.Fatalf("expected 3 registry package resolutions, got %d: %#v", len(deps), deps)
	}

	seen := map[string]bool{}
	for key, version := range deps {
		seen[dependencyDisplayName(key)+"@"+version] = true
	}
	for _, want := range []string{"anyio@==4.5.2", "anyio@==4.14.1", "certifi@==2026.6.17"} {
		if !seen[want] {
			t.Fatalf("missing %s in %#v", want, seen)
		}
	}
	if strings.Contains(strings.Join(mapKeys(deps), " "), "demo") {
		t.Fatal("editable project package should not be treated as a registry dependency")
	}
}

func TestUVLockDiffDoesNotCollapseMarkerSpecificVersions(t *testing.T) {
	oldDeps, err := parseUVLock([]byte(uvLockFixture))
	if err != nil {
		t.Fatal(err)
	}
	newLock := strings.Replace(uvLockFixture, "4.14.1", "4.15.0", 1)
	newDeps, err := parseUVLock([]byte(newLock))
	if err != nil {
		t.Fatal(err)
	}

	entries := computeDiffWith(oldDeps, newDeps, "pip", noopRecencyChecker{}, noopNpmRiskChecker{})
	if len(entries) != 2 {
		t.Fatalf("expected one added and one removed resolution, got %#v", entries)
	}
	if entries[0].Name != "anyio" || entries[0].Status != Added || entries[0].NewVersion != "==4.15.0" {
		t.Fatalf("unexpected added resolution: %#v", entries[0])
	}
	if entries[1].Name != "anyio" || entries[1].Status != Removed || entries[1].OldVersion != "==4.14.1" {
		t.Fatalf("unexpected removed resolution: %#v", entries[1])
	}
}

func TestParseUVLockRejectsUnsupportedCoverage(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"schema", strings.Replace(uvLockFixture, "version = 1", "version = 2", 1)},
		{"alternate registry", strings.Replace(uvLockFixture, "https://pypi.org/simple", "https://packages.example.com/simple", 1)},
		{"git source", strings.Replace(uvLockFixture, `source = { registry = "https://pypi.org/simple" }`, `source = { git = "https://example.com/repo.git" }`, 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseUVLock([]byte(tc.body)); err == nil {
				t.Fatal("expected unsupported uv.lock input to fail")
			}
		})
	}
}
