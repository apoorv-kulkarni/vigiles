package config

import (
	"bytes"
	"strings"
	"testing"

	"github.com/apoorv-kulkarni/vigiles/internal/signal"
)

const fullConfig = `
version: 1

policy:
  fail-on: vulnerability,heuristic

suppress:
  - id: VIGILES-NPM-INSTALL-SCRIPT
    package: esbuild
    reason: "known safe build tool"
    expires: 2099-01-01
  - id: VIGILES-RECENTLY-PUBLISHED
    reason: "internal packages are always recent"
`

func TestParse_Full(t *testing.T) {
	cfg, err := parse([]byte(fullConfig))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Version != 1 {
		t.Errorf("version: got %d, want 1", cfg.Version)
	}
	if cfg.Policy.FailOn != "vulnerability,heuristic" {
		t.Errorf("policy.fail-on: got %q, want %q", cfg.Policy.FailOn, "vulnerability,heuristic")
	}
	if len(cfg.Suppress) != 2 {
		t.Fatalf("suppress: got %d items, want 2", len(cfg.Suppress))
	}
	s0 := cfg.Suppress[0]
	if s0.ID != "VIGILES-NPM-INSTALL-SCRIPT" {
		t.Errorf("suppress[0].id: got %q", s0.ID)
	}
	if s0.Package != "esbuild" {
		t.Errorf("suppress[0].package: got %q", s0.Package)
	}
	if s0.Reason != "known safe build tool" {
		t.Errorf("suppress[0].reason: got %q", s0.Reason)
	}
	if s0.Expires != "2099-01-01" {
		t.Errorf("suppress[0].expires: got %q", s0.Expires)
	}
	if cfg.Suppress[1].Package != "" {
		t.Errorf("suppress[1].package should be empty, got %q", cfg.Suppress[1].Package)
	}
}

func TestParse_MinimalConfig(t *testing.T) {
	cfg, err := parse([]byte("version: 1\n"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Version != 1 {
		t.Errorf("version: got %d", cfg.Version)
	}
	if len(cfg.Suppress) != 0 {
		t.Errorf("expected no suppressions")
	}
}

func TestParse_UnsupportedVersion(t *testing.T) {
	_, err := parse([]byte("version: 2\n"))
	if err == nil {
		t.Fatal("expected error for version 2")
	}
}

func TestParse_UnknownTopLevelKey(t *testing.T) {
	_, err := parse([]byte("version: 1\nfoo: bar\n"))
	if err == nil {
		t.Fatal("expected error for unknown key")
	}
}

func TestParse_MissingSuppressID(t *testing.T) {
	cfg := `version: 1
suppress:
  - package: foo
`
	_, err := parse([]byte(cfg))
	if err == nil {
		t.Fatal("expected error for missing suppress id")
	}
}

func TestParse_InvalidExpiresDate(t *testing.T) {
	cfg := `version: 1
suppress:
  - id: VIGILES-FOO
    expires: 01-01-2099
`
	_, err := parse([]byte(cfg))
	if err == nil {
		t.Fatal("expected error for bad date format")
	}
}

func TestParse_Comments(t *testing.T) {
	cfg := `# top-level comment
version: 1 # inline comment
# another comment
policy:
  fail-on: none # trailing
`
	c, err := parse([]byte(cfg))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Policy.FailOn != "none" {
		t.Errorf("fail-on: got %q", c.Policy.FailOn)
	}
}

// --- ApplySuppressions ---

func sig(id, pkg string) signal.Signal {
	return signal.Signal{ID: id, Package: pkg, Type: "trust-signal", Severity: "info"}
}

func TestApplySuppressions_MatchesIDAndPackage(t *testing.T) {
	sigs := []signal.Signal{
		sig("VIGILES-NPM-INSTALL-SCRIPT", "esbuild"),
		sig("VIGILES-NPM-INSTALL-SCRIPT", "malware"),
		sig("VIGILES-TYPOSQUAT", "esbuild"),
	}
	suppressions := []Suppression{
		{ID: "VIGILES-NPM-INSTALL-SCRIPT", Package: "esbuild"},
	}
	out := ApplySuppressions(sigs, suppressions, &bytes.Buffer{})
	if len(out) != 2 {
		t.Fatalf("expected 2 signals, got %d", len(out))
	}
	for _, s := range out {
		if s.ID == "VIGILES-NPM-INSTALL-SCRIPT" && strings.EqualFold(s.Package, "esbuild") {
			t.Error("suppressed signal should not appear in output")
		}
	}
}

func TestApplySuppressions_MatchesIDWithoutPackage(t *testing.T) {
	sigs := []signal.Signal{
		sig("VIGILES-RECENTLY-PUBLISHED", "pkg-a"),
		sig("VIGILES-RECENTLY-PUBLISHED", "pkg-b"),
		sig("VIGILES-TYPOSQUAT", "pkg-c"),
	}
	suppressions := []Suppression{
		{ID: "VIGILES-RECENTLY-PUBLISHED"},
	}
	out := ApplySuppressions(sigs, suppressions, &bytes.Buffer{})
	if len(out) != 1 {
		t.Fatalf("expected 1 signal, got %d: %+v", len(out), out)
	}
	if out[0].ID != "VIGILES-TYPOSQUAT" {
		t.Errorf("wrong signal survived: %q", out[0].ID)
	}
}

func TestApplySuppressions_ExpiredIsNotApplied(t *testing.T) {
	sigs := []signal.Signal{sig("VIGILES-FOO", "bar")}
	suppressions := []Suppression{
		{ID: "VIGILES-FOO", Expires: "2020-01-01"}, // expired
	}
	var buf bytes.Buffer
	out := ApplySuppressions(sigs, suppressions, &buf)
	if len(out) != 1 {
		t.Fatal("expired suppression should not suppress the signal")
	}
	if !strings.Contains(buf.String(), "expired") {
		t.Error("expected expiry warning on stderr")
	}
}

func TestApplySuppressions_FutureExpiryApplied(t *testing.T) {
	sigs := []signal.Signal{sig("VIGILES-FOO", "bar")}
	suppressions := []Suppression{
		{ID: "VIGILES-FOO", Expires: "2099-01-01"},
	}
	out := ApplySuppressions(sigs, suppressions, &bytes.Buffer{})
	if len(out) != 0 {
		t.Fatal("active suppression should remove the signal")
	}
}

func TestApplySuppressions_Empty(t *testing.T) {
	sigs := []signal.Signal{sig("VIGILES-FOO", "bar")}
	out := ApplySuppressions(sigs, nil, &bytes.Buffer{})
	if len(out) != 1 {
		t.Fatal("no suppressions should return signals unchanged")
	}
}
