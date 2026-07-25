package reporter

import (
	"bytes"
	"strings"
	"testing"

	"github.com/apoorv-kulkarni/vigiles/internal/scanner"
	"github.com/apoorv-kulkarni/vigiles/internal/signal"
)

func TestPrintSummaryClean(t *testing.T) {
	var buf bytes.Buffer
	PrintSummary(&buf, Report{
		Packages: []scanner.Package{
			{Name: "requests", Version: "2.32.0", Ecosystem: "pip"},
			{Name: "flask", Version: "3.0.0", Ecosystem: "pip"},
		},
	})

	out := buf.String()
	if !strings.Contains(out, "Clean: 2 packages, 0 findings") {
		t.Errorf("expected a clean summary line, got:\n%s", out)
	}
	// The per-signal table should not be rendered when there is nothing to show.
	if strings.Contains(out, "SEV") {
		t.Errorf("did not expect a findings table for a clean report, got:\n%s", out)
	}
}

func TestPrintSummaryWithFindings(t *testing.T) {
	report := Report{
		Packages: []scanner.Package{
			{Name: "requests", Version: "2.31.0", Ecosystem: "pip"},
			{Name: "axios", Version: "1.7.2", Ecosystem: "npm"},
		},
		Signals: []signal.Signal{
			{Package: "requests", Version: "2.31.0", Ecosystem: "pip",
				Type: "trust-signal", Severity: "info", ID: "VIGILES-UNPINNED"},
			{Package: "axios", Version: "1.7.2", Ecosystem: "npm",
				Type: "vulnerability", Severity: "critical", ID: "CVE-2026-0001"},
		},
		DurationMs: 1820,
	}
	report.Summary = signal.Summarize(report.Signals)

	var buf bytes.Buffer
	PrintSummary(&buf, report)
	out := buf.String()

	for _, want := range []string{"SEV", "PACKAGE", "CVE-2026-0001", "VIGILES-UNPINNED", "1820ms"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in the summary, got:\n%s", want, out)
		}
	}

	// Signals are sorted most severe first, so the critical CVE precedes the info signal.
	if strings.Index(out, "CVE-2026-0001") > strings.Index(out, "VIGILES-UNPINNED") {
		t.Errorf("expected the critical finding listed first, got:\n%s", out)
	}

	if !strings.Contains(out, "1 vuln") || !strings.Contains(out, "1 trust-signal") {
		t.Errorf("expected per-type counts in the stats block, got:\n%s", out)
	}
}

func TestPrintSummaryTruncatesLongFields(t *testing.T) {
	long := strings.Repeat("a", 40)
	report := Report{
		Signals: []signal.Signal{{
			Package: long, Version: strings.Repeat("9", 20), Ecosystem: "pip",
			Type: "heuristic", Severity: "high", ID: "VIGILES-TYPOSQUAT",
		}},
	}
	report.Summary = signal.Summarize(report.Signals)

	var buf bytes.Buffer
	PrintSummary(&buf, report)

	if strings.Contains(buf.String(), long) {
		t.Error("expected an over-long package name to be truncated")
	}
	if !strings.Contains(buf.String(), "…") {
		t.Errorf("expected an ellipsis marker, got:\n%s", buf.String())
	}
}

func TestTruncateStr(t *testing.T) {
	tests := []struct {
		in     string
		maxLen int
		want   string
	}{
		{"short", 10, "short"},
		{"exactly10!", 10, "exactly10!"},
		{"truncate-me", 5, "trun…"},
	}
	for _, tt := range tests {
		if got := truncateStr(tt.in, tt.maxLen); got != tt.want {
			t.Errorf("truncateStr(%q, %d) = %q, want %q", tt.in, tt.maxLen, got, tt.want)
		}
	}
}

func TestSeverityIconCoversAllSeverities(t *testing.T) {
	seen := map[string]string{}
	for _, sev := range signal.ValidSeverities {
		icon := severityIcon(sev)
		if icon == "" {
			t.Errorf("severity %q has no icon", sev)
		}
		if prev, dup := seen[icon]; dup && sev != "unknown" {
			t.Errorf("severity %q reuses the icon for %q", sev, prev)
		}
		seen[icon] = sev
	}

	if got := severityIcon("not-a-severity"); got != "⚪" {
		t.Errorf("expected the fallback icon for an unknown severity, got %q", got)
	}
}

func TestNewReportNormalizesNilSlices(t *testing.T) {
	r := NewReport("0.3.7", 0, []string{"pip"}, nil, nil)

	// JSON consumers should see [] rather than null for these fields.
	if r.Signals == nil {
		t.Error("expected an empty signal slice, got nil")
	}
	if r.Packages == nil {
		t.Error("expected an empty package slice, got nil")
	}
	if r.Summary.Total != 0 {
		t.Errorf("expected an empty summary, got %+v", r.Summary)
	}
}

func TestPrintTableCleanReport(t *testing.T) {
	var buf bytes.Buffer
	PrintTable(&buf, Report{
		Ecosystems: []string{"pip", "npm"},
		Packages:   []scanner.Package{{Name: "requests", Ecosystem: "pip"}},
	})

	out := buf.String()
	if !strings.Contains(out, "No issues found across 1 packages") {
		t.Errorf("expected the clean-report line, got:\n%s", out)
	}
	if !strings.Contains(out, "pip, npm") {
		t.Errorf("expected the scanned ecosystems listed, got:\n%s", out)
	}
}

func TestPrintTableRendersDetailsAndLinks(t *testing.T) {
	report := Report{
		Packages: []scanner.Package{{Name: "requests", Ecosystem: "pip"}},
		Signals: []signal.Signal{
			{
				Package: "requests", Version: "2.31.0", Ecosystem: "pip",
				Type: "vulnerability", Severity: "critical", ID: "CVE-2026-0001",
				Summary:     "remote code execution",
				Details:     "https://osv.dev/vulnerability/CVE-2026-0001",
				Remediation: "Upgrade requests to 2.32.0.",
			},
			{
				Package: "flask", Version: "3.0.0", Ecosystem: "pip",
				Type: "heuristic", Severity: "medium", ID: "VIGILES-TYPOSQUAT",
				Summary: "possible typosquat",
				Details: strings.Repeat("wrap this long detail text ", 6),
			},
		},
	}
	report.Summary = signal.Summarize(report.Signals)

	var buf bytes.Buffer
	PrintTable(&buf, report)
	out := buf.String()

	// A URL detail is rendered as a link rather than word-wrapped prose.
	if !strings.Contains(out, "↗  https://osv.dev/vulnerability/CVE-2026-0001") {
		t.Errorf("expected a link-style detail line, got:\n%s", out)
	}
	for _, want := range []string{"CRITICAL (1)", "MEDIUM (1)", "Top Packages by Findings"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in the table, got:\n%s", want, out)
		}
	}
	// The remediation from the vulnerability becomes the package hint.
	if !strings.Contains(out, "Hint: Upgrade requests to 2.32.0.") {
		t.Errorf("expected the remediation used as the hint, got:\n%s", out)
	}
}

func TestPrintPackageSummaryFallbackHint(t *testing.T) {
	// A vulnerability with no remediation still produces a generic hint.
	sigs := []signal.Signal{{
		Package: "flask", Version: "3.0.0", Ecosystem: "pip",
		Type: "vulnerability", Severity: "high", ID: "CVE-2026-0002",
		Summary: "issue",
	}}

	var buf bytes.Buffer
	printPackageSummary(&buf, sigs)

	if !strings.Contains(buf.String(), "Hint: Upgrade flask to a supported version.") {
		t.Errorf("expected the fallback hint, got:\n%s", buf.String())
	}
}

func TestPrintPackageSummaryRanksAndAggregates(t *testing.T) {
	sigs := []signal.Signal{
		{Package: "busy", Ecosystem: "pip", Type: "heuristic", Severity: "medium", ID: "A"},
		{Package: "busy", Ecosystem: "pip", Type: "trust-signal", Severity: "info", ID: "B"},
		{Package: "busy", Ecosystem: "pip", Type: "vulnerability", Severity: "critical", ID: "C"},
		{Package: "quiet", Ecosystem: "npm", Type: "trust-signal", Severity: "info", ID: "D"},
	}

	var buf bytes.Buffer
	printPackageSummary(&buf, sigs)
	out := buf.String()

	if strings.Index(out, "busy") > strings.Index(out, "quiet") {
		t.Errorf("expected the package with more findings ranked first, got:\n%s", out)
	}
	// Counts are aggregated per package and worst severity wins the icon.
	if !strings.Contains(out, "1 vuln, 1 heuristic, 1 trust") {
		t.Errorf("expected aggregated per-type counts, got:\n%s", out)
	}
	if !strings.Contains(out, severityIcon("critical")) {
		t.Errorf("expected the worst severity icon for the package row, got:\n%s", out)
	}
}

func TestSarifLevel(t *testing.T) {
	tests := []struct {
		severity string
		want     string
	}{
		{"critical", "error"},
		{"high", "error"},
		{"medium", "warning"},
		{"low", "note"},
		{"info", "note"},
		{"unknown", "note"},
		{"nonsense", "note"},
	}
	for _, tt := range tests {
		if got := sarifLevel(tt.severity); got != tt.want {
			t.Errorf("sarifLevel(%q) = %q, want %q", tt.severity, got, tt.want)
		}
		if got := SignalsToSARIFLevel(signal.Signal{Severity: tt.severity}); got != tt.want {
			t.Errorf("SignalsToSARIFLevel(%q) = %q, want %q", tt.severity, got, tt.want)
		}
	}
}
