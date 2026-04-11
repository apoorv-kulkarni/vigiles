package cmd

import (
	"testing"

	"github.com/apoorv-kulkarni/vigiles/internal/signal"
)

func TestParseEcosystems_Valid(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"pip", 1},
		{"pip,npm", 2},
		{"pip, npm, brew", 3},
		{"cargo,gomod", 2},
		{" pip , npm ", 2},
	}

	for _, tt := range tests {
		ecos, err := parseEcosystems(tt.input, false)
		if err != nil {
			t.Errorf("parseEcosystems(%q) error: %v", tt.input, err)
			continue
		}
		if len(ecos) != tt.want {
			t.Errorf("parseEcosystems(%q) = %d ecosystems, want %d", tt.input, len(ecos), tt.want)
		}
	}
}

func TestParseEcosystems_Invalid(t *testing.T) {
	tests := []string{
		"pip,nuget",
		"invalid",
		"pip,,invalid",
	}

	for _, input := range tests {
		_, err := parseEcosystems(input, false)
		if err == nil {
			t.Errorf("parseEcosystems(%q) should have returned error", input)
		}
	}
}

func TestParseEcosystems_Empty(t *testing.T) {
	_, err := parseEcosystems(",,,", false)
	if err == nil {
		t.Error("parseEcosystems with only commas should return error")
	}
}

func TestParseEcosystems_TrimsWhitespace(t *testing.T) {
	ecos, err := parseEcosystems("  pip  ,  npm  ", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ecos) != 2 {
		t.Fatalf("expected 2 ecosystems, got %d", len(ecos))
	}
	if ecos[0] != "pip" || ecos[1] != "npm" {
		t.Errorf("expected [pip npm], got %v", ecos)
	}
}

func TestValidFormats(t *testing.T) {
	for _, f := range []string{"table", "json", "summary", "sarif"} {
		if !validFormats[f] {
			t.Errorf("format %q should be valid", f)
		}
	}
	for _, f := range []string{"xml", "csv", "yaml", ""} {
		if validFormats[f] {
			t.Errorf("format %q should be invalid", f)
		}
	}
}

// --- parseFailOn ---

func TestParseFailOn_Valid(t *testing.T) {
	tests := []struct {
		input string
		want  []string // keys expected in the result map
	}{
		{"all", []string{"all"}},
		{"none", []string{"none"}},
		{"vulnerability", []string{"vulnerability"}},
		{"vulnerability,heuristic", []string{"vulnerability", "heuristic"}},
		{"vulnerability, heuristic, trust-signal", []string{"vulnerability", "heuristic", "trust-signal"}},
		{"system-heuristic", []string{"system-heuristic"}},
	}

	for _, tt := range tests {
		got, err := parseFailOn(tt.input)
		if err != nil {
			t.Errorf("parseFailOn(%q) unexpected error: %v", tt.input, err)
			continue
		}
		for _, key := range tt.want {
			if !got[key] {
				t.Errorf("parseFailOn(%q): expected key %q in result", tt.input, key)
			}
		}
	}
}

func TestParseFailOn_Invalid(t *testing.T) {
	for _, input := range []string{"critical", "warn", "vuln", "all,invalid"} {
		_, err := parseFailOn(input)
		if err == nil {
			t.Errorf("parseFailOn(%q) should have returned error", input)
		}
	}
}

// --- hasBlockingSignal ---

func sig(typ string) signal.Signal {
	return signal.Signal{Type: typ, Severity: "info", ID: "TEST"}
}

func TestHasBlockingSignal_AllPolicy(t *testing.T) {
	failOn, _ := parseFailOn("all")
	if hasBlockingSignal(nil, failOn) {
		t.Error("no signals should not block")
	}
	if !hasBlockingSignal([]signal.Signal{sig("trust-signal")}, failOn) {
		t.Error("any signal should block under 'all' policy")
	}
}

func TestHasBlockingSignal_NonePolicy(t *testing.T) {
	failOn, _ := parseFailOn("none")
	sigs := []signal.Signal{sig("vulnerability"), sig("heuristic"), sig("trust-signal")}
	if hasBlockingSignal(sigs, failOn) {
		t.Error("no signals should block under 'none' policy")
	}
}

func TestHasBlockingSignal_VulnerabilityOnly(t *testing.T) {
	failOn, _ := parseFailOn("vulnerability")
	if hasBlockingSignal([]signal.Signal{sig("trust-signal")}, failOn) {
		t.Error("trust-signal should not block under 'vulnerability' policy")
	}
	if hasBlockingSignal([]signal.Signal{sig("heuristic")}, failOn) {
		t.Error("heuristic should not block under 'vulnerability' policy")
	}
	if !hasBlockingSignal([]signal.Signal{sig("vulnerability")}, failOn) {
		t.Error("vulnerability should block under 'vulnerability' policy")
	}
}

func TestHasBlockingSignal_MultipleTypes(t *testing.T) {
	failOn, _ := parseFailOn("vulnerability,heuristic")
	if hasBlockingSignal([]signal.Signal{sig("trust-signal")}, failOn) {
		t.Error("trust-signal should not block under 'vulnerability,heuristic' policy")
	}
	if !hasBlockingSignal([]signal.Signal{sig("heuristic")}, failOn) {
		t.Error("heuristic should block under 'vulnerability,heuristic' policy")
	}
	if !hasBlockingSignal([]signal.Signal{sig("trust-signal"), sig("vulnerability")}, failOn) {
		t.Error("mixed signals with a matching type should block")
	}
}

func TestHasBlockingSignal_NilMapDefaultsToAll(t *testing.T) {
	if hasBlockingSignal(nil, nil) {
		t.Error("no signals should not block even with nil policy")
	}
	if !hasBlockingSignal([]signal.Signal{sig("trust-signal")}, nil) {
		t.Error("nil policy should default to 'all' behaviour")
	}
}
