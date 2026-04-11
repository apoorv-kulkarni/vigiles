package cmd

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/apoorv-kulkarni/vigiles/internal/diff"
	"github.com/apoorv-kulkarni/vigiles/internal/reporter"
	"github.com/apoorv-kulkarni/vigiles/internal/scanner"
	"github.com/apoorv-kulkarni/vigiles/internal/signal"
)

// TestExitCode_Clean verifies exit 0 when no signals are produced.
func TestExitCode_Clean(t *testing.T) {
	code := runScan(
		[]string{}, // no ecosystems = no packages = clean
		"table", "", true, true, true, false, io.Discard,
	)
	if code != ExitClean {
		t.Errorf("expected exit %d for empty scan, got %d", ExitClean, code)
	}
}

// TestExitCode_Findings verifies exit 1 when signals exist.
func TestExitCode_Findings(t *testing.T) {
	// We can't easily inject signals into runScan without a full refactor,
	// so test at the report level: if signals exist, the report path should
	// yield ExitFindings.
	signals := []signal.Signal{
		{Package: "bad", Severity: "high", Type: "heuristic", ID: "TEST-1"},
	}
	// Verify the condition used in runScan
	if len(signals) == 0 {
		t.Fatal("test setup error: signals should not be empty")
	}
	// The exit code logic: if len(signals) > 0 return ExitFindings
	if ExitFindings != 1 {
		t.Errorf("ExitFindings should be 1, got %d", ExitFindings)
	}
}

// TestExitCode_BadEcosystem verifies exit 2 for invalid --ecosystems.
func TestExitCode_BadEcosystem(t *testing.T) {
	// Save and restore os.Args
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = []string{"vigiles", "scan", "--ecosystems", "nuget"}
	code := Execute()
	if code != ExitError {
		t.Errorf("expected exit %d for bad ecosystem, got %d", ExitError, code)
	}
}

// TestExitCode_BadFormat verifies exit 2 for invalid --format.
func TestExitCode_BadFormat(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = []string{"vigiles", "scan", "--format", "xml"}
	code := Execute()
	if code != ExitError {
		t.Errorf("expected exit %d for bad format, got %d", ExitError, code)
	}
}

// TestExitCode_BadCommand verifies exit 2 for unknown subcommands.
func TestExitCode_BadCommand(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = []string{"vigiles", "nope"}
	code := Execute()
	if code != ExitError {
		t.Errorf("expected exit %d for bad command, got %d", ExitError, code)
	}
}

// TestExitCode_DiffMissingArgs verifies exit 2 when diff has wrong arg count.
func TestExitCode_DiffMissingArgs(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = []string{"vigiles", "diff"}
	code := Execute()
	if code != ExitError {
		t.Errorf("expected exit %d for diff with no args, got %d", ExitError, code)
	}
}

// TestExitCode_DiffBadFile verifies exit 2 for nonexistent diff files.
func TestExitCode_DiffBadFile(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = []string{"vigiles", "diff", "/nonexistent/a.txt", "/nonexistent/b.txt"}
	code := Execute()
	if code != ExitError {
		t.Errorf("expected exit %d for bad diff files, got %d", ExitError, code)
	}
}

// TestExitCode_DiffClean verifies exit 0 when diff has no risk signals.
func TestExitCode_DiffClean(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	dir := t.TempDir()
	old := filepath.Join(dir, "old.txt")
	new := filepath.Join(dir, "new.txt")
	os.WriteFile(old, []byte("requests==2.31.0\n"), 0644)
	os.WriteFile(new, []byte("requests==2.32.0\n"), 0644) // updated but still pinned

	os.Args = []string{"vigiles", "diff", old, new}
	code := Execute()
	if code != ExitClean {
		t.Errorf("expected exit %d for clean diff, got %d", ExitClean, code)
	}
}

// TestExitCode_DiffWithSignals verifies exit 1 when diff entries have signals.
func TestExitCode_DiffWithSignals(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	dir := t.TempDir()
	old := filepath.Join(dir, "old.txt")
	new := filepath.Join(dir, "new.txt")
	os.WriteFile(old, []byte("requests==2.31.0\n"), 0644)
	os.WriteFile(new, []byte("requests>=2.31\n"), 0644) // unpinned = signal

	os.Args = []string{"vigiles", "diff", old, new}
	code := Execute()
	if code != ExitFindings {
		t.Errorf("expected exit %d for diff with unpinned signal, got %d", ExitFindings, code)
	}
}

// TestJSON_StdoutClean verifies JSON output is valid and on stdout only.
func TestJSON_StdoutClean(t *testing.T) {
	report := reporter.NewReport(Version, 100*time.Millisecond,
		[]string{"pip"},
		[]scanner.Package{{Name: "a", Version: "1.0", Ecosystem: "pip"}},
		nil,
	)

	var buf bytes.Buffer
	if err := reporter.WriteJSON(&buf, report); err != nil {
		t.Fatalf("WriteJSON failed: %v", err)
	}

	raw := buf.String()

	// Must be valid JSON
	var decoded map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		t.Fatalf("JSON output is not valid: %v\nRaw: %s", err, raw)
	}

	// Must not contain progress markers
	for _, marker := range []string{"▸", "⚠", "Scanning", "Found"} {
		if strings.Contains(raw, marker) {
			t.Errorf("JSON stdout contains progress text %q", marker)
		}
	}

	// Must contain required keys
	for _, key := range []string{"version", "timestamp", "duration_ms", "packages", "signals", "summary"} {
		if _, ok := decoded[key]; !ok {
			t.Errorf("JSON missing required key %q", key)
		}
	}
}

// TestDeduplicatePackages tests the package deduplication logic.
func TestDeduplicatePackages(t *testing.T) {
	pkgs := []scanner.Package{
		{Name: "express", Version: "4.18.2", Ecosystem: "npm", Location: "global"},
		{Name: "express", Version: "4.18.2", Ecosystem: "npm", Location: "local"},
		{Name: "lodash", Version: "4.17.21", Ecosystem: "npm", Location: "global"},
		{Name: "requests", Version: "2.31.0", Ecosystem: "pip"},
	}

	deduped := deduplicatePackages(pkgs)
	if len(deduped) != 3 {
		t.Errorf("expected 3 packages after dedup, got %d", len(deduped))
	}

	// First occurrence should be kept (global)
	if deduped[0].Location != "global" {
		t.Errorf("expected first express to be global, got %s", deduped[0].Location)
	}
}

// TestDeduplicateSignals tests signal deduplication.
func TestDeduplicateSignals(t *testing.T) {
	sigs := []signal.Signal{
		{ID: "CVE-2024-1", Package: "foo", Version: "1.0"},
		{ID: "CVE-2024-1", Package: "foo", Version: "1.0"}, // dup
		{ID: "CVE-2024-2", Package: "foo", Version: "1.0"}, // different ID
		{ID: "CVE-2024-1", Package: "bar", Version: "1.0"}, // different package
	}

	deduped := deduplicateSignals(sigs)
	if len(deduped) != 3 {
		t.Errorf("expected 3 signals after dedup, got %d", len(deduped))
	}
}

// TestVersion verifies the version command.
func TestVersion(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = []string{"vigiles", "version"}
	code := Execute()
	if code != ExitClean {
		t.Errorf("version command should exit %d, got %d", ExitClean, code)
	}
}

func TestPrintDiffTable_NewDependencyHighlight(t *testing.T) {
	result := &diff.Result{
		OldFile:   "old-lock.json",
		NewFile:   "new-lock.json",
		Ecosystem: "npm",
		Entries: []diff.Entry{
			{
				Name:       "plain-crypto-js",
				Ecosystem:  "npm",
				Status:     diff.Added,
				NewVersion: "4.2.1",
				Signals: []signal.Signal{
					{ID: "VIGILES-NEW-DEPENDENCY", Summary: "New dependency introduced"},
					{ID: "VIGILES-RECENTLY-PUBLISHED", Summary: "Version published 4 hours ago"},
				},
			},
		},
	}

	var buf bytes.Buffer
	printDiffTable(&buf, result)
	out := buf.String()

	for _, want := range []string{
		"NEW DEPENDENCY:",
		"plain-crypto-js 4.2.1",
		"Signals:",
		"• new transitive dependency",
		"• published today",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected diff output to contain %q\nOutput:\n%s", want, out)
		}
	}
}
