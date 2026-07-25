package checker

import (
	"strings"
	"testing"

	"github.com/apoorv-kulkarni/vigiles/internal/scanner"
)

func TestCheckPipHeuristics(t *testing.T) {
	tests := []struct {
		name    string
		pkg     scanner.Package
		wantIDs []string
	}{
		{
			name:    "clean package produces nothing",
			pkg:     scanner.Package{Name: "requests", Version: "2.32.0", Ecosystem: "pip"},
			wantIDs: nil,
		},
		{
			name:    "typosquat of a popular package",
			pkg:     scanner.Package{Name: "reqests", Version: "2.32.0", Ecosystem: "pip"},
			wantIDs: []string{"VIGILES-TYPOSQUAT"},
		},
		{
			name:    "prerelease version is a version anomaly",
			pkg:     scanner.Package{Name: "some-internal-lib", Version: "1.0.0rc1", Ecosystem: "pip"},
			wantIDs: []string{"VIGILES-VERSION-ANOMALY"},
		},
		{
			name:    "typosquat and version anomaly together",
			pkg:     scanner.Package{Name: "reqests", Version: "1.0.0dev", Ecosystem: "pip"},
			wantIDs: []string{"VIGILES-TYPOSQUAT", "VIGILES-VERSION-ANOMALY"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sigs := checkPipHeuristics(tt.pkg)
			if len(sigs) != len(tt.wantIDs) {
				t.Fatalf("expected %v, got %d signals: %+v", tt.wantIDs, len(sigs), sigs)
			}
			for i, want := range tt.wantIDs {
				if sigs[i].ID != want {
					t.Errorf("signal %d: got %s, want %s", i, sigs[i].ID, want)
				}
				if sigs[i].Type != "heuristic" {
					t.Errorf("signal %s: expected heuristic type, got %s", sigs[i].ID, sigs[i].Type)
				}
				if sigs[i].Package != tt.pkg.Name || sigs[i].Ecosystem != "pip" {
					t.Errorf("signal %s: unexpected context %+v", sigs[i].ID, sigs[i])
				}
			}
		})
	}
}

func TestCheckNpmHeuristics(t *testing.T) {
	clean := checkNpmHeuristics(scanner.Package{Name: "express", Version: "4.19.2", Ecosystem: "npm"})
	if len(clean) != 0 {
		t.Errorf("expected no signals for a popular package, got %+v", clean)
	}

	// "expres" is within edit distance 1 of "express".
	typo := checkNpmHeuristics(scanner.Package{Name: "expres", Version: "4.19.2", Ecosystem: "npm"})
	if len(typo) != 1 || typo[0].ID != "VIGILES-TYPOSQUAT" {
		t.Fatalf("expected a typosquat signal, got %+v", typo)
	}
	if !strings.Contains(typo[0].Summary, "express") {
		t.Errorf("expected the summary to name the impersonated package, got %q", typo[0].Summary)
	}

	// npm heuristics deliberately skip the version anomaly rule.
	odd := checkNpmHeuristics(scanner.Package{Name: "some-lib", Version: "1.0.0beta", Ecosystem: "npm"})
	if len(odd) != 0 {
		t.Errorf("expected no npm version anomaly signal, got %+v", odd)
	}
}

func TestHeuristicCheckerRoutesByEcosystem(t *testing.T) {
	c := NewHeuristicChecker()

	tests := []struct {
		ecosystem string
		wantSigs  int
	}{
		{"pip", 1},
		{"npm", 1},
		{"brew", 0},  // no per-package heuristics for brew
		{"cargo", 0}, // nor cargo
	}

	for _, tt := range tests {
		t.Run(tt.ecosystem, func(t *testing.T) {
			// "reqests"/"expres" are typosquats in pip and npm respectively;
			// for the ecosystems without rules the name is irrelevant.
			name := "reqests"
			if tt.ecosystem == "npm" {
				name = "expres"
			}
			got := c.checkPackage(scanner.Package{Name: name, Version: "1.0.0", Ecosystem: tt.ecosystem})
			if len(got) != tt.wantSigs {
				t.Errorf("expected %d signals for %s, got %d: %+v", tt.wantSigs, tt.ecosystem, len(got), got)
			}
		})
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		in     string
		maxLen int
		want   string
	}{
		{"short", 10, "short"},
		{"exactly10!", 10, "exactly10!"},
		{"truncate me please", 8, "truncate..."},
		{"", 5, ""},
	}
	for _, tt := range tests {
		if got := truncate(tt.in, tt.maxLen); got != tt.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", tt.in, tt.maxLen, got, tt.want)
		}
	}
}

func TestExportedPopularListHelpers(t *testing.T) {
	if len(PopularPipPackages()) == 0 {
		t.Error("expected a non-empty popular pip list")
	}
	if len(PopularNpmPackages()) == 0 {
		t.Error("expected a non-empty popular npm list")
	}

	if got := CheckTyposquatExported("reqests", PopularPipPackages()); got != "requests" {
		t.Errorf("CheckTyposquatExported = %q, want requests", got)
	}
	if got := CheckTyposquatExported("requests", PopularPipPackages()); got != "" {
		t.Errorf("expected no typosquat match for an exact name, got %q", got)
	}
}
