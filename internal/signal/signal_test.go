package signal

import "testing"

func TestSortSignals(t *testing.T) {
	signals := []Signal{
		{Severity: "low", ID: "low-1"},
		{Severity: "critical", ID: "crit-1"},
		{Severity: "info", ID: "info-1"},
		{Severity: "medium", ID: "med-1"},
		{Severity: "high", ID: "high-1"},
	}

	SortSignals(signals)

	expected := []string{"critical", "high", "medium", "low", "info"}
	for i, s := range signals {
		if s.Severity != expected[i] {
			t.Errorf("Position %d: got %q, want %q", i, s.Severity, expected[i])
		}
	}
}

func TestSummarize(t *testing.T) {
	signals := []Signal{
		{Type: "vulnerability", Severity: "high"},
		{Type: "vulnerability", Severity: "critical"},
		{Type: "heuristic", Severity: "high"},
		{Type: "system-heuristic", Severity: "critical"},
		{Type: "trust-signal", Severity: "info"},
		{Type: "trust-signal", Severity: "info"},
	}

	s := Summarize(signals)

	if s.Total != 6 {
		t.Errorf("Total = %d, want 6", s.Total)
	}
	if s.Vulnerabilities != 2 {
		t.Errorf("Vulnerabilities = %d, want 2", s.Vulnerabilities)
	}
	if s.Heuristics != 2 {
		t.Errorf("Heuristics = %d, want 2", s.Heuristics)
	}
	if s.TrustSignals != 2 {
		t.Errorf("TrustSignals = %d, want 2", s.TrustSignals)
	}
	if s.BySeverity["critical"] != 2 {
		t.Errorf("BySeverity[critical] = %d, want 2", s.BySeverity["critical"])
	}
	if s.BySeverity["info"] != 2 {
		t.Errorf("BySeverity[info] = %d, want 2", s.BySeverity["info"])
	}
}

func TestSummarize_Empty(t *testing.T) {
	s := Summarize(nil)
	if s.Total != 0 {
		t.Errorf("Expected 0 total, got %d", s.Total)
	}
}
