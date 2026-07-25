package checker

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writePackageJSON creates dir and writes a package.json containing body.
func writePackageJSON(t *testing.T, dir, body string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "package.json")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCheckNpmInstallScriptsFromFile(t *testing.T) {
	path := writePackageJSON(t, t.TempDir(),
		`{"name": "demo", "version": "1.2.3", "scripts": {"postinstall": "node setup.js", "test": "jest"}}`)

	sigs := CheckNpmInstallScripts(path)
	if len(sigs) != 1 {
		t.Fatalf("expected 1 signal for postinstall, got %d: %+v", len(sigs), sigs)
	}
	if sigs[0].ID != "VIGILES-NPM-INSTALL-SCRIPT" {
		t.Errorf("unexpected ID: %s", sigs[0].ID)
	}
	if sigs[0].Package != "demo" || sigs[0].Version != "1.2.3" {
		t.Errorf("expected package context from the manifest, got %+v", sigs[0])
	}
	if !strings.Contains(sigs[0].Details, "node setup.js") {
		t.Errorf("expected the script command in details, got %q", sigs[0].Details)
	}
}

func TestCheckNpmInstallScriptsMissingOrInvalid(t *testing.T) {
	dir := t.TempDir()

	if sigs := CheckNpmInstallScripts(filepath.Join(dir, "absent.json")); sigs != nil {
		t.Errorf("expected nil for a missing file, got %+v", sigs)
	}

	malformed := writePackageJSON(t, filepath.Join(dir, "bad"), `{"scripts": `)
	if sigs := CheckNpmInstallScripts(malformed); sigs != nil {
		t.Errorf("expected nil for malformed JSON, got %+v", sigs)
	}

	noScripts := writePackageJSON(t, filepath.Join(dir, "plain"), `{"name": "plain", "version": "1.0.0"}`)
	if sigs := CheckNpmInstallScripts(noScripts); sigs != nil {
		t.Errorf("expected nil when there are no scripts, got %+v", sigs)
	}
}

func TestCheckNpmInstallScriptsInNodeModules(t *testing.T) {
	root := t.TempDir()
	nodeModules := filepath.Join(root, "node_modules")

	// A plain package with an install hook.
	writePackageJSON(t, filepath.Join(nodeModules, "hooked"),
		`{"name": "hooked", "version": "1.0.0", "scripts": {"install": "node build.js"}}`)

	// A scoped package with an install hook.
	writePackageJSON(t, filepath.Join(nodeModules, "@scope", "inner"),
		`{"name": "@scope/inner", "version": "2.0.0", "scripts": {"preinstall": "node pre.js"}}`)

	// A package without hooks contributes nothing.
	writePackageJSON(t, filepath.Join(nodeModules, "quiet"),
		`{"name": "quiet", "version": "1.0.0", "scripts": {"test": "jest"}}`)

	// Hidden directories such as .bin and .package-lock.json are skipped.
	writePackageJSON(t, filepath.Join(nodeModules, ".cache"),
		`{"name": "cached", "version": "1.0.0", "scripts": {"postinstall": "node nope.js"}}`)

	// A stray file at the top level is not a package directory.
	if err := os.WriteFile(filepath.Join(nodeModules, ".package-lock.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	sigs := CheckNpmInstallScriptsInNodeModules(nodeModules)
	if len(sigs) != 2 {
		t.Fatalf("expected 2 signals (plain + scoped), got %d: %+v", len(sigs), sigs)
	}

	found := map[string]bool{}
	for _, s := range sigs {
		found[s.Package] = true
	}
	for _, want := range []string{"hooked", "@scope/inner"} {
		if !found[want] {
			t.Errorf("expected a signal for %s, got %v", want, found)
		}
	}
	if found["cached"] {
		t.Error("expected hidden directories to be skipped")
	}
}

func TestCheckNpmInstallScriptsInNodeModulesMissingDir(t *testing.T) {
	sigs := CheckNpmInstallScriptsInNodeModules(filepath.Join(t.TempDir(), "absent"))
	if sigs != nil {
		t.Errorf("expected nil for a missing node_modules, got %+v", sigs)
	}
}

func TestTruncateScript(t *testing.T) {
	if got := truncateScript("  node build.js  ", 120); got != "node build.js" {
		t.Errorf("expected surrounding whitespace trimmed, got %q", got)
	}

	long := strings.Repeat("a", 30)
	got := truncateScript(long, 10)
	if got != strings.Repeat("a", 10)+"..." {
		t.Errorf("expected truncation with an ellipsis, got %q", got)
	}
}
