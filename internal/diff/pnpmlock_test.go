package diff

import (
	"strings"
	"testing"
)

const pnpmLockFixture = `lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      react:
        specifier: ^19.0.0
        version: 19.1.1

packages:

  react@19.1.1:
    resolution: {integrity: sha512-react}

  'react-dom@19.1.1(react@19.1.1)':
    resolution: {integrity: sha512-react-dom}

  '@scope/widget@1.2.3':
    resolution: {integrity: sha512-widget}

snapshots:

  react@19.1.1: {}

  'react-dom@19.1.1(react@19.1.1)':
    dependencies:
      react: 19.1.1
`

func TestParsePNPMLockCurrentV9(t *testing.T) {
	deps, err := parsePNPMLock([]byte(pnpmLockFixture))
	if err != nil {
		t.Fatalf("parsePNPMLock: %v", err)
	}
	if len(deps) != 3 {
		t.Fatalf("expected 3 packages, got %d: %#v", len(deps), deps)
	}
	seen := map[string]bool{}
	for key, version := range deps {
		seen[dependencyDisplayName(key)+"@"+version] = true
	}
	for _, want := range []string{"react@19.1.1", "react-dom@19.1.1", "@scope/widget@1.2.3"} {
		if !seen[want] {
			t.Fatalf("missing %s in %#v", want, seen)
		}
	}
}

func TestPNPMLockCollapsesPeerContextsButPreservesVersions(t *testing.T) {
	body := `lockfileVersion: '9.0'

packages:
  'react-dom@19.1.1(react@19.1.1)':
    resolution: {integrity: sha512-one}
  'react-dom@19.1.1(react@19.0.0)':
    resolution: {integrity: sha512-one}
  react-dom@18.3.1:
    resolution: {integrity: sha512-old}
`
	deps, err := parsePNPMLock([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 2 {
		t.Fatalf("expected peer contexts to collapse to 2 package versions, got %#v", deps)
	}
}

func TestPNPMLockDiffPreservesMultipleVersions(t *testing.T) {
	oldDeps, err := parsePNPMLock([]byte(pnpmLockFixture))
	if err != nil {
		t.Fatal(err)
	}
	newLock := strings.Replace(pnpmLockFixture, "react@19.1.1:", "react@19.2.0:", 1)
	newLock = strings.Replace(newLock, "sha512-react}", "sha512-react-new}", 1)
	newDeps, err := parsePNPMLock([]byte(newLock))
	if err != nil {
		t.Fatal(err)
	}

	entries := computeDiffWith(oldDeps, newDeps, "npm", noopRecencyChecker{}, noopNpmRiskChecker{})
	if len(entries) != 2 {
		t.Fatalf("expected added and removed package resolution, got %#v", entries)
	}
	if entries[0].Name != "react" || entries[0].Status != Added || entries[0].NewVersion != "19.2.0" {
		t.Fatalf("unexpected addition: %#v", entries[0])
	}
	if entries[1].Name != "react" || entries[1].Status != Removed || entries[1].OldVersion != "19.1.1" {
		t.Fatalf("unexpected removal: %#v", entries[1])
	}
}

func TestPNPMLockArtifactIntegrityChangeWithoutVersionChange(t *testing.T) {
	oldDeps, err := parsePNPMLock([]byte(pnpmLockFixture))
	if err != nil {
		t.Fatal(err)
	}
	newLock := strings.Replace(pnpmLockFixture, "sha512-react}", "sha512-react-new}", 1)
	newDeps, err := parsePNPMLock([]byte(newLock))
	if err != nil {
		t.Fatal(err)
	}

	entries := computeDiffWith(oldDeps, newDeps, "npm", noopRecencyChecker{}, noopNpmRiskChecker{})
	if len(entries) != 1 || entries[0].Status != Updated || entries[0].Name != "react" {
		t.Fatalf("artifact integrity change was missed: %#v", entries)
	}
	if len(entries[0].Signals) != 1 || entries[0].Signals[0].ID != "VIGILES-NPM-ARTIFACT-CHANGE" {
		t.Fatalf("wrong artifact signal: %#v", entries[0].Signals)
	}
}

func TestParsePNPMLockRejectsUnsupportedCoverage(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"old lockfile version", strings.Replace(pnpmLockFixture, "'9.0'", "'6.0'", 1)},
		{"tarball source", strings.Replace(pnpmLockFixture, "{integrity: sha512-react}", "{integrity: sha512-react, tarball: https://example.test/react.tgz}", 1)},
		{"git source", strings.Replace(pnpmLockFixture, "{integrity: sha512-react}", "{type: git, repo: https://example.test/react.git, commit: abc}", 1)},
		{"missing integrity", strings.Replace(pnpmLockFixture, "resolution: {integrity: sha512-react}", "resolution: {}", 1)},
		{"patched dependencies", strings.Replace(pnpmLockFixture, "importers:", "patchedDependencies:\n  react@19.1.1: deadbeef\n\nimporters:", 1)},
		{"pnpmfile hook", strings.Replace(pnpmLockFixture, "importers:", "pnpmfileChecksum: sha256-deadbeef\n\nimporters:", 1)},
		{"inline packages map", "lockfileVersion: '9.0'\npackages: {react@19.1.1: {resolution: {integrity: sha512-react}}}\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parsePNPMLock([]byte(tc.body)); err == nil {
				t.Fatal("expected unsupported pnpm lockfile input to fail")
			}
		})
	}
}

func TestParsePNPMLockRejectsConflictingResolutionForSameVersion(t *testing.T) {
	body := `lockfileVersion: '9.0'

packages:
  'react-dom@19.1.1(react@19.1.1)':
    resolution: {integrity: sha512-one}
  'react-dom@19.1.1(react@19.0.0)':
    resolution: {integrity: sha512-two}
`
	if _, err := parsePNPMLock([]byte(body)); err == nil {
		t.Fatal("expected conflicting resolution metadata to fail")
	}
}

func TestParsePNPMLockMultilineResolution(t *testing.T) {
	body := `lockfileVersion: '9.0'

packages:
  react@19.1.1:
    resolution:
      integrity: sha512-react
`
	deps, err := parsePNPMLock([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 {
		t.Fatalf("unexpected dependencies: %#v", deps)
	}
}
