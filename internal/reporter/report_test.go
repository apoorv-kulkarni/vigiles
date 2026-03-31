package reporter

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/apoorv-kulkarni/vigiles/internal/scanner"
	"github.com/apoorv-kulkarni/vigiles/internal/signal"
)

func TestNewReport_JSONStability(t *testing.T) {
	signals := []signal.Signal{
		{Package: "requests", Version: "2.31.0", Ecosystem: "pip",
			Type: "vulnerability", Severity: "high", ID: "CVE-2024-1234",
			Summary: "Test vuln", Aliases: []string{"GHSA-abcd"}},
		{Package: "system", Version: "", Ecosystem: "system",
			Type: "system-heuristic", Severity: "critical", ID: "VIGILES-TEAMPCP-BACKDOOR",
			Summary: "Backdoor found"},
		{Package: "flask", Version: ">=2.0", Ecosystem: "pip",
			Type: "trust-signal", Severity: "info", ID: "VIGILES-UNPINNED",
			Summary: "Unpinned"},
	}

	report := NewReport("0.2.0", 2*time.Second,
		[]string{"pip"},
		[]scanner.Package{{Name: "requests", Version: "2.31.0", Ecosystem: "pip"}},
		signals,
	)

	// Serialize to JSON
	var buf bytes.Buffer
	if err := WriteJSON(&buf, report); err != nil {
		t.Fatalf("WriteJSON failed: %v", err)
	}

	// Round-trip
	var decoded Report
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("JSON round-trip failed: %v", err)
	}

	// Check required top-level fields
	if decoded.Version != "0.2.0" {
		t.Errorf("Version = %q, want 0.2.0", decoded.Version)
	}
	if len(decoded.Signals) != 3 {
		t.Errorf("Signals count = %d, want 3", len(decoded.Signals))
	}
	if len(decoded.Packages) != 1 {
		t.Errorf("Packages count = %d, want 1", len(decoded.Packages))
	}

	// Check summary
	if decoded.Summary.Total != 3 {
		t.Errorf("Summary.Total = %d, want 3", decoded.Summary.Total)
	}
	if decoded.Summary.Vulnerabilities != 1 {
		t.Errorf("Summary.Vulnerabilities = %d, want 1", decoded.Summary.Vulnerabilities)
	}
	if decoded.Summary.Heuristics != 1 {
		t.Errorf("Summary.Heuristics = %d, want 1", decoded.Summary.Heuristics)
	}
	if decoded.Summary.TrustSignals != 1 {
		t.Errorf("Summary.TrustSignals = %d, want 1", decoded.Summary.TrustSignals)
	}

	// Check signal ordering (critical should be first after sort)
	if decoded.Signals[0].Severity != "critical" {
		t.Errorf("First signal severity = %q, want critical", decoded.Signals[0].Severity)
	}

	// Verify JSON has the summary object
	raw := buf.String()
	if !strings.Contains(raw, `"summary"`) {
		t.Error("JSON output missing 'summary' key")
	}
	if !strings.Contains(raw, `"duration_ms"`) {
		t.Error("JSON output missing 'duration_ms' key")
	}
}

func TestPrintTable_NoFindings(t *testing.T) {
	var buf bytes.Buffer
	report := NewReport("0.2.0", 100*time.Millisecond,
		[]string{"pip"},
		[]scanner.Package{{Name: "requests", Version: "2.31.0", Ecosystem: "pip"}},
		nil,
	)
	PrintTable(&buf, report)

	if !strings.Contains(buf.String(), "No issues found") {
		t.Error("Expected 'No issues found' in empty report output")
	}
}

func TestPrintTable_WithFindings(t *testing.T) {
	var buf bytes.Buffer
	signals := []signal.Signal{
		{Package: "bad", Version: "0.1", Ecosystem: "pip",
			Type: "heuristic", Severity: "high", ID: "VIGILES-TYPOSQUAT",
			Summary: "typosquat"},
		{Package: "bad", Version: "0.1", Ecosystem: "pip",
			Type: "vulnerability", Severity: "medium", ID: "CVE-2024-1234",
			Summary:     "vuln 2",
			Remediation: "Upgrade bad to >=1.0.0."},
		{Package: "old", Version: "1.0", Ecosystem: "pip",
			Type: "vulnerability", Severity: "medium", ID: "CVE-2024-9999",
			Summary: "vuln"},
	}
	report := NewReport("0.2.0", time.Second, []string{"pip"},
		[]scanner.Package{{Name: "bad"}, {Name: "old"}}, signals)
	PrintTable(&buf, report)

	out := buf.String()
	highIdx := strings.Index(out, "HIGH")
	medIdx := strings.Index(out, "MEDIUM")
	if highIdx < 0 || medIdx < 0 {
		t.Error("Expected both HIGH and MEDIUM sections")
	}
	if highIdx > medIdx {
		t.Error("HIGH should appear before MEDIUM")
	}
	if !strings.Contains(out, "Top Packages by Findings") {
		t.Error("Expected package summary block")
	}
	if !strings.Contains(out, "bad") || !strings.Contains(out, "pip") {
		t.Error("Expected package summary row for bad/pip")
	}
	if !strings.Contains(out, "Hint: Upgrade bad to >=1.0.0.") {
		t.Error("Expected remediation hint in package summary")
	}
}

func TestWordWrap(t *testing.T) {
	lines := wordWrap("this is a somewhat longer string that should wrap", 20)
	if len(lines) < 2 {
		t.Errorf("Expected wrapping, got %d lines", len(lines))
	}

	empty := wordWrap("", 80)
	if len(empty) != 0 {
		t.Errorf("Expected 0 lines for empty input, got %d", len(empty))
	}
}
