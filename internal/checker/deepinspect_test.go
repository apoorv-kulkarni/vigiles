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

func TestLooksSuspiciousScript(t *testing.T) {
	if !looksSuspiciousScript("node -e \"eval(Buffer.from(p,'base64').toString())\"") {
		t.Fatal("expected obfuscated inline execution to be suspicious")
	}
	if looksSuspiciousScript("node-gyp rebuild") {
		t.Fatal("did not expect benign build script to be suspicious")
	}
}
