package cmd

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/apoorv-kulkarni/vigiles/internal/config"
	"github.com/apoorv-kulkarni/vigiles/internal/diff"
	"github.com/apoorv-kulkarni/vigiles/internal/scanner"
	"github.com/apoorv-kulkarni/vigiles/internal/signal"
)

// fakeScanner stands in for a real package manager so the scan pipeline can be
// exercised offline and deterministically.
type fakeScanner struct {
	name string
	pkgs []scanner.Package
	err  error
}

func (f *fakeScanner) Name() string    { return f.name }
func (f *fakeScanner) Available() bool { return true }
func (f *fakeScanner) Scan() ([]scanner.Package, error) {
	return f.pkgs, f.err
}

// useFakeScanner swaps the registered scanner for name and restores the real
// one afterwards. The registry is process-global, so these tests are not
// parallel-safe.
func useFakeScanner(t *testing.T, name string, pkgs []scanner.Package, err error) {
	t.Helper()
	orig := scanner.Get(name)
	scanner.Register(&fakeScanner{name: name, pkgs: pkgs, err: err})
	t.Cleanup(func() {
		if orig != nil {
			scanner.Register(orig)
		}
	})
}

// scanToFile runs a scan writing to a temp file and returns its contents.
func scanToFile(t *testing.T, format string, opts scanOptions) (string, int) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "report."+format)
	code := runScanWithOptions([]string{"pip"}, format, out,
		true, true, true, false, io.Discard, opts)

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("reading report: %v", err)
	}
	return string(data), code
}

func TestRunScanWritesEachFormat(t *testing.T) {
	useFakeScanner(t, "pip", []scanner.Package{
		{Name: "requests", Version: "2.32.0", Ecosystem: "pip", Direct: true},
		{Name: "urllib3", Version: "2.2.1", Ecosystem: "pip"},
	}, nil)

	t.Run("json", func(t *testing.T) {
		body, code := scanToFile(t, "json", scanOptions{})
		if code != ExitClean {
			t.Errorf("expected exit %d, got %d", ExitClean, code)
		}
		var decoded map[string]any
		if err := json.Unmarshal([]byte(body), &decoded); err != nil {
			t.Fatalf("output is not valid JSON: %v", err)
		}
		pkgs, _ := decoded["packages"].([]any)
		if len(pkgs) != 2 {
			t.Errorf("expected 2 packages in the report, got %d", len(pkgs))
		}
	})

	t.Run("sarif", func(t *testing.T) {
		body, _ := scanToFile(t, "sarif", scanOptions{})
		var decoded map[string]any
		if err := json.Unmarshal([]byte(body), &decoded); err != nil {
			t.Fatalf("output is not valid JSON: %v", err)
		}
		if _, ok := decoded["runs"]; !ok {
			t.Errorf("expected a SARIF runs key, got keys %v", decoded)
		}
	})

	t.Run("summary", func(t *testing.T) {
		body, _ := scanToFile(t, "summary", scanOptions{})
		if !strings.Contains(body, "Clean: 2 packages") {
			t.Errorf("expected a clean summary, got:\n%s", body)
		}
	})

	t.Run("table", func(t *testing.T) {
		body, _ := scanToFile(t, "table", scanOptions{})
		if !strings.Contains(body, "No issues found across 2 packages") {
			t.Errorf("expected the clean table output, got:\n%s", body)
		}
	})
}

func TestRunScanDeduplicatesAcrossScanners(t *testing.T) {
	// The same package reported twice collapses to one entry.
	useFakeScanner(t, "pip", []scanner.Package{
		{Name: "requests", Version: "2.32.0", Ecosystem: "pip", Location: "global"},
		{Name: "requests", Version: "2.32.0", Ecosystem: "pip", Location: "local"},
	}, nil)

	body, _ := scanToFile(t, "json", scanOptions{})

	var decoded struct {
		Packages []scanner.Package `json:"packages"`
	}
	if err := json.Unmarshal([]byte(body), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if len(decoded.Packages) != 1 {
		t.Fatalf("expected deduplication to leave 1 package, got %d", len(decoded.Packages))
	}
	if decoded.Packages[0].Location != "global" {
		t.Errorf("expected the first occurrence kept, got %q", decoded.Packages[0].Location)
	}
}

func TestRunScanFailsOnHeuristicFinding(t *testing.T) {
	// "reqests" is a typosquat of "requests", so the heuristic checker fires
	// without any network access.
	useFakeScanner(t, "pip", []scanner.Package{
		{Name: "reqests", Version: "2.32.0", Ecosystem: "pip", Direct: true},
	}, nil)

	failOn, err := parseFailOn("heuristic")
	if err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(t.TempDir(), "report.json")
	code := runScanWithOptions([]string{"pip"}, "json", out,
		true, false, true, false, io.Discard, scanOptions{FailOn: failOn})
	if code != ExitFindings {
		t.Fatalf("expected exit %d for a heuristic finding, got %d", ExitFindings, code)
	}

	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "VIGILES-TYPOSQUAT") {
		t.Errorf("expected a typosquat signal in the report, got:\n%s", body)
	}
}

func TestRunScanSuppressionsClearFindings(t *testing.T) {
	useFakeScanner(t, "pip", []scanner.Package{
		{Name: "reqests", Version: "2.32.0", Ecosystem: "pip", Direct: true},
	}, nil)

	failOn, _ := parseFailOn("heuristic")
	code := runScanWithOptions([]string{"pip"}, "json", filepath.Join(t.TempDir(), "r.json"),
		true, false, true, false, io.Discard, scanOptions{
			FailOn: failOn,
			Suppressions: []config.Suppression{
				{ID: "VIGILES-TYPOSQUAT", Package: "reqests", Reason: "known internal name"},
			},
		})
	if code != ExitClean {
		t.Errorf("expected a suppressed finding not to fail the scan, got exit %d", code)
	}
}

func TestRunScanNoPackagesIsClean(t *testing.T) {
	useFakeScanner(t, "pip", nil, nil)

	code := runScanWithOptions([]string{"pip"}, "table", "",
		true, true, true, true, io.Discard, scanOptions{})
	if code != ExitClean {
		t.Errorf("expected exit %d when no packages are found, got %d", ExitClean, code)
	}
}

func TestRunScanScannerErrorIsNonFatal(t *testing.T) {
	useFakeScanner(t, "pip", nil, errors.New("pip exploded"))

	code := runScanWithOptions([]string{"pip"}, "table", "",
		true, true, true, false, io.Discard, scanOptions{})
	if code != ExitClean {
		t.Errorf("expected a scanner failure to be non-fatal, got exit %d", code)
	}
}

func TestRunScanUnwritableOutputIsAnError(t *testing.T) {
	useFakeScanner(t, "pip", []scanner.Package{
		{Name: "requests", Version: "2.32.0", Ecosystem: "pip"},
	}, nil)

	bad := filepath.Join(t.TempDir(), "missing-dir", "report.json")
	code := runScanWithOptions([]string{"pip"}, "json", bad,
		true, true, true, false, io.Discard, scanOptions{})
	if code != ExitError {
		t.Errorf("expected exit %d when the output file cannot be created, got %d", ExitError, code)
	}
}

func TestRunScanUnknownEcosystemIsSkipped(t *testing.T) {
	// scanner.Get returns nil for an unregistered name, which the loop skips.
	code := runScanWithOptions([]string{"composer"}, "table", "",
		true, true, true, false, io.Discard, scanOptions{})
	if code != ExitClean {
		t.Errorf("expected exit %d, got %d", ExitClean, code)
	}
}

func TestRunScanNoEcosystems(t *testing.T) {
	if code := runScan(nil, "table", "", true, true, true, false, io.Discard); code != ExitClean {
		t.Errorf("expected exit %d with no ecosystems, got %d", ExitClean, code)
	}
}

func TestRunScanInspectsManifestsInWorkingDir(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "package.json"),
		`{"name": "demo", "version": "1.0.0", "scripts": {"postinstall": "node -e \"eval(atob(x))\""}}`)
	writeFile(t, filepath.Join(dir, "node_modules", "hooked", "package.json"),
		`{"name": "hooked", "version": "1.0.0", "scripts": {"install": "node build.js"}}`)
	writeFile(t, filepath.Join(dir, "setup.py"),
		"import base64\nexec(base64.b64decode('eA=='))\n")

	restore := chdir(t, dir)
	defer restore()

	useFakeScanner(t, "npm", []scanner.Package{
		{Name: "demo", Version: "1.0.0", Ecosystem: "npm", Direct: true},
	}, nil)
	useFakeScanner(t, "pip", []scanner.Package{
		{Name: "demo-py", Version: "1.0.0", Ecosystem: "pip", Direct: true},
	}, nil)

	out := filepath.Join(t.TempDir(), "report.json")
	runScanWithOptions([]string{"npm", "pip"}, "json", out,
		true, false, true, false, io.Discard, scanOptions{})

	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"VIGILES-NPM-HOOK-SUSPICIOUS", // package.json deep inspection
		"VIGILES-NPM-INSTALL-SCRIPT",  // node_modules traversal
		"VIGILES-SETUPPY-SUSPICIOUS",  // setup.py deep inspection
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("expected %s in the report, got:\n%s", want, body)
		}
	}
}

// --- helpers ---

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// chdir switches to dir and returns a function restoring the previous
// directory. Tests using it must not run in parallel.
func chdir(t *testing.T, dir string) func() {
	t.Helper()
	prev, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	return func() {
		if err := os.Chdir(prev); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRunScanVerboseAndTrustChecks(t *testing.T) {
	// Transitive packages with no direct flag are skipped by the provenance and
	// sigstore checkers before any request is made, so both branches run offline.
	useFakeScanner(t, "pip", []scanner.Package{
		{Name: "urllib3", Version: "2.2.1", Ecosystem: "pip"},
		{Name: "urllib3", Version: "2.2.1", Ecosystem: "pip"}, // duplicate, triggers the verbose dedup line
	}, nil)

	var progress strings.Builder
	code := runScanWithOptions([]string{"pip"}, "table", filepath.Join(t.TempDir(), "r.txt"),
		true, true, true, true, &progress, scanOptions{
			EnableProvenance: true,
			EnableSigstore:   true,
		})
	if code != ExitClean {
		t.Errorf("expected exit %d, got %d", ExitClean, code)
	}

	out := progress.String()
	for _, want := range []string{"Deduplicated 2", "provenance", "attestations"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in verbose progress, got:\n%s", want, out)
		}
	}
}

func TestParseEcosystemsAuto(t *testing.T) {
	useFakeScanner(t, "pip", nil, nil) // Available() reports true

	ecos, err := parseEcosystems("auto", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasEcosystem(ecos, "pip") {
		t.Errorf("expected auto-detection to include the available pip scanner, got %v", ecos)
	}
	for _, e := range ecos {
		if !validEcosystems[e] {
			t.Errorf("auto-detection returned an unknown ecosystem %q", e)
		}
	}
}

func TestParseFailOnSkipsEmptySegments(t *testing.T) {
	got, err := parseFailOn("vulnerability,,heuristic, ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 || !got["vulnerability"] || !got["heuristic"] {
		t.Errorf("expected empty segments ignored, got %v", got)
	}
}

func TestPrintDiffTableStatuses(t *testing.T) {
	var buf strings.Builder
	printDiffTable(&buf, &diff.Result{
		OldFile: "old.txt", NewFile: "new.txt", Ecosystem: "pip",
		Entries: []diff.Entry{
			{Name: "flask", Ecosystem: "pip", Status: diff.Updated,
				OldVersion: "2.3.0", NewVersion: "3.0.0",
				Signals: []signal.Signal{{
					ID: "VIGILES-UNPINNED", Severity: "info", Summary: "uses a range",
				}}},
			{Name: "boto3", Ecosystem: "pip", Status: diff.Removed, OldVersion: "1.28.0"},
		},
	})

	out := buf.String()
	if !strings.Contains(out, "~ flask") || !strings.Contains(out, "2.3.0 → 3.0.0") {
		t.Errorf("expected an updated row, got:\n%s", out)
	}
	if !strings.Contains(out, "- boto3") || !strings.Contains(out, "1.28.0") {
		t.Errorf("expected a removed row, got:\n%s", out)
	}
	if !strings.Contains(out, "VIGILES-UNPINNED: uses a range") {
		t.Errorf("expected the signal line, got:\n%s", out)
	}
}

func TestPrintDiffTableNoChanges(t *testing.T) {
	var buf strings.Builder
	printDiffTable(&buf, &diff.Result{OldFile: "a.txt", NewFile: "b.txt", Ecosystem: "pip"})

	if !strings.Contains(buf.String(), "No changes detected.") {
		t.Errorf("expected the no-changes line, got:\n%s", buf.String())
	}
}

func TestPrintDiffTableDeduplicatesAddedSignals(t *testing.T) {
	var buf strings.Builder
	printDiffTable(&buf, &diff.Result{
		OldFile: "a.json", NewFile: "b.json", Ecosystem: "npm",
		Entries: []diff.Entry{{
			Name: "left-pad", Ecosystem: "npm", Status: diff.Added, NewVersion: "1.0.0",
			Signals: []signal.Signal{
				{ID: "VIGILES-NEW-DEPENDENCY"},
				{ID: "VIGILES-NEW-DEPENDENCY"}, // same humanized text, printed once
			},
		}},
	})

	if got := strings.Count(buf.String(), "• new transitive dependency"); got != 1 {
		t.Errorf("expected the repeated signal collapsed to one line, got %d", got)
	}
}

func TestHasEcosystem(t *testing.T) {
	list := []string{"pip", "npm"}
	if !hasEcosystem(list, "npm") {
		t.Error("expected npm to be found")
	}
	if hasEcosystem(list, "cargo") {
		t.Error("did not expect cargo to be found")
	}
	if hasEcosystem(nil, "pip") {
		t.Error("did not expect a match in an empty list")
	}
}

func TestOpenOutputDefaultsToStdout(t *testing.T) {
	w, cleanup, err := openOutput("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer cleanup()
	if w != os.Stdout {
		t.Error("expected an empty path to select stdout")
	}
}

func TestOpenOutputCreatesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.txt")
	w, cleanup, err := openOutput(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := w.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	cleanup()

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "hello" {
		t.Errorf("expected the written content, got %q", body)
	}
}

func TestOpenOutputUncreatableFile(t *testing.T) {
	_, _, err := openOutput(filepath.Join(t.TempDir(), "no-such-dir", "out.txt"))
	if err == nil {
		t.Fatal("expected an error for an uncreatable path")
	}
}

func TestResolveFailOn(t *testing.T) {
	tests := []struct {
		flag, config, want string
	}{
		{"vulnerability", "heuristic", "vulnerability"}, // flag wins
		{"", "heuristic", "heuristic"},                  // config is the fallback
		{"", "", "all"},                                 // final default
	}
	for _, tt := range tests {
		if got := resolveFailOn(tt.flag, tt.config); got != tt.want {
			t.Errorf("resolveFailOn(%q, %q) = %q, want %q", tt.flag, tt.config, got, tt.want)
		}
	}
}

func TestSeverityIconCmd(t *testing.T) {
	for _, sev := range signal.ValidSeverities {
		if severityIcon(sev) == "" {
			t.Errorf("severity %q has no icon", sev)
		}
	}
	if got := severityIcon("bogus"); got != "⚪" {
		t.Errorf("expected the fallback icon, got %q", got)
	}
}

func TestHumanizeDiffSignal(t *testing.T) {
	tests := []struct {
		sig  signal.Signal
		want string
	}{
		{signal.Signal{ID: "VIGILES-NEW-DEPENDENCY"}, "new transitive dependency"},
		{signal.Signal{ID: "VIGILES-RECENTLY-PUBLISHED", Summary: "Version published 4 hours ago"}, "published today"},
		{signal.Signal{ID: "VIGILES-RECENTLY-PUBLISHED", Summary: "Version published 3 days ago"}, "recently published"},
		{signal.Signal{ID: "VIGILES-UNPINNED", Summary: "Dependency uses a range"}, "dependency uses a range"},
		{signal.Signal{ID: "VIGILES-BARE"}, "VIGILES-BARE"},
	}
	for _, tt := range tests {
		if got := humanizeDiffSignal(tt.sig); got != tt.want {
			t.Errorf("humanizeDiffSignal(%+v) = %q, want %q", tt.sig, got, tt.want)
		}
	}
}

func TestSendNotificationIsBestEffort(t *testing.T) {
	// Reducing PATH keeps osascript unreachable, so no desktop notification is
	// raised while still exercising the call path.
	t.Setenv("PATH", t.TempDir())
	sendNotification("Vigiles", "test message")
}

func TestExecuteHelpAndUsage(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	for _, args := range [][]string{
		{"vigiles", "help"},
		{"vigiles", "-h"},
		{"vigiles", "--help"},
		{"vigiles"}, // no subcommand prints usage too
	} {
		os.Args = args
		if code := Execute(); code != ExitClean {
			t.Errorf("Execute(%v) = %d, want %d", args, code, ExitClean)
		}
	}
}

func TestScanRejectsInvalidFailOn(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = []string{"vigiles", "scan", "--fail-on", "bogus"}
	if code := Execute(); code != ExitError {
		t.Errorf("expected exit %d for an invalid --fail-on, got %d", ExitError, code)
	}
}

func TestScanRejectsNonPositiveWatchInterval(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = []string{"vigiles", "scan", "--watch", "--watch-interval", "0s", "--ecosystems", "pip"}
	if code := Execute(); code != ExitError {
		t.Errorf("expected exit %d for a non-positive watch interval, got %d", ExitError, code)
	}
}

func TestScanRejectsUnknownFlag(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = []string{"vigiles", "scan", "--nope"}
	if code := Execute(); code != ExitError {
		t.Errorf("expected exit %d for an unknown flag, got %d", ExitError, code)
	}
}

func TestDiffRejectsInvalidFormatAndFailOn(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	dir := t.TempDir()
	oldFile := filepath.Join(dir, "old.txt")
	newFile := filepath.Join(dir, "new.txt")
	writeFile(t, oldFile, "requests==2.31.0\n")
	writeFile(t, newFile, "requests==2.32.0\n")

	os.Args = []string{"vigiles", "diff", "--format", "yaml", oldFile, newFile}
	if code := Execute(); code != ExitError {
		t.Errorf("expected exit %d for an invalid diff format, got %d", ExitError, code)
	}

	os.Args = []string{"vigiles", "diff", "--fail-on", "bogus", oldFile, newFile}
	if code := Execute(); code != ExitError {
		t.Errorf("expected exit %d for an invalid --fail-on, got %d", ExitError, code)
	}
}

func TestDiffJSONOutputAndNonePolicy(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	dir := t.TempDir()
	oldFile := filepath.Join(dir, "old.txt")
	newFile := filepath.Join(dir, "new.txt")
	writeFile(t, oldFile, "requests==2.31.0\n")
	writeFile(t, newFile, "requests>=2.31\n") // unpinned, so a signal is produced

	// --fail-on none downgrades findings to reporting only.
	os.Args = []string{"vigiles", "diff", "--format", "json", "--fail-on", "none", oldFile, newFile}
	if code := Execute(); code != ExitClean {
		t.Errorf("expected exit %d under --fail-on none, got %d", ExitClean, code)
	}
}

func TestDiffMismatchedFileTypes(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	dir := t.TempDir()
	reqs := filepath.Join(dir, "requirements.txt")
	pkg := filepath.Join(dir, "package.json")
	writeFile(t, reqs, "requests==2.31.0\n")
	writeFile(t, pkg, `{"dependencies": {"axios": "1.7.2"}}`)

	os.Args = []string{"vigiles", "diff", reqs, pkg}
	if code := Execute(); code != ExitError {
		t.Errorf("expected exit %d when file types differ, got %d", ExitError, code)
	}
}
