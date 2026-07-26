//go:build osvlive

// Contract tests against the real OSV API. Excluded from the default build so
// `go test ./...` stays hermetic and offline-safe. Run with `make test-live`
// when changing the OSV integration.
//
// These exist because mocks cannot catch a response-shape change: an earlier
// version of this checker read summary, severity, aliases, and affected ranges
// straight off the querybatch response, which the real API never populates.

package checker

import (
	"strings"
	"testing"

	"github.com/apoorv-kulkarni/vigiles/internal/scanner"
)

// requests 2.19.0 has carried several advisories for years, so it is a stable
// fixture. If it ever stops returning findings, that is worth knowing too.
var liveFixture = scanner.Package{Name: "requests", Version: "2.19.0", Ecosystem: "pip"}

// TestLiveQueryBatchReturnsAbbreviatedEntries pins the assumption the whole
// hydration step exists for: /v1/querybatch answers with IDs only. Should OSV
// ever start returning full records, this fails and the extra round trips in
// signalsFor can be dropped.
func TestLiveQueryBatchReturnsAbbreviatedEntries(t *testing.T) {
	resp, err := NewOSVChecker().postBatch(osvBatchRequest{Queries: []osvQuery{{
		Package: osvPackage{Name: liveFixture.Name, Ecosystem: mapEcosystem(liveFixture.Ecosystem)},
		Version: liveFixture.Version,
	}}})
	if err != nil {
		t.Fatalf("querybatch failed: %v", err)
	}
	if len(resp.Results) != 1 || len(resp.Results[0].Vulns) == 0 {
		t.Fatalf("expected findings for %s %s, got %+v", liveFixture.Name, liveFixture.Version, resp.Results)
	}

	for _, vuln := range resp.Results[0].Vulns {
		if vuln.ID == "" {
			t.Error("expected every abbreviated entry to carry an ID")
		}
		if vuln.Summary != "" || len(vuln.Severity) > 0 || len(vuln.Affected) > 0 {
			t.Errorf("querybatch now returns full records for %s, so hydration may be "+
				"unnecessary: %+v", vuln.ID, vuln)
		}
	}
}

// TestLiveVulnDetailIsPopulated asserts the fields Vigiles reads are actually
// present on the detail endpoint, and that OSV still encodes CVSS scores as
// vector strings rather than numbers.
func TestLiveVulnDetailIsPopulated(t *testing.T) {
	// A GitHub-reviewed advisory for the fixture above.
	vuln, err := NewOSVChecker().fetchVuln("GHSA-9wx4-h78v-vm56")
	if err != nil {
		t.Fatalf("detail lookup failed: %v", err)
	}

	if strings.TrimSpace(vuln.Summary) == "" {
		t.Error("expected a summary on the detail record")
	}
	if len(vuln.Aliases) == 0 {
		t.Error("expected aliases on the detail record")
	}
	if len(fixedVersions(vuln)) == 0 {
		t.Error("expected at least one fixed version on the detail record")
	}
	if vuln.DatabaseSpecific.Severity == "" {
		t.Error("expected database_specific.severity on a GitHub advisory")
	}

	if len(vuln.Severity) == 0 {
		t.Fatal("expected a severity entry")
	}
	for _, sev := range vuln.Severity {
		if !strings.HasPrefix(sev.Score, "CVSS:") {
			t.Errorf("expected a CVSS vector string, got %q; classifySeverity assumes vectors", sev.Score)
		}
	}
	if got := classifySeverity(vuln); got != "medium" {
		t.Errorf("classifySeverity = %q, want medium (CVSS:3.1 base score 5.6)", got)
	}
}

// TestLiveCheckPopulatesFindings is the end-to-end assertion: real findings
// come back ranked and described, not hollow.
func TestLiveCheckPopulatesFindings(t *testing.T) {
	sigs, err := NewOSVChecker().Check([]scanner.Package{liveFixture})
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if len(sigs) == 0 {
		t.Fatal("expected findings for a known-vulnerable release")
	}

	var ranked, described, withFix int
	for _, s := range sigs {
		if s.Severity != "unknown" {
			ranked++
		}
		if !strings.Contains(s.Summary, "no description available") {
			described++
		}
		if strings.Contains(s.Remediation, "OSV fixed versions") {
			withFix++
		}
		t.Logf("%-9s %-22s %s", s.Severity, s.ID, s.Summary)
	}

	if described != len(sigs) {
		t.Errorf("expected every finding to carry a real description, got %d of %d", described, len(sigs))
	}
	// Not every OSV source publishes severity, so require a majority rather
	// than all of them.
	if ranked*2 <= len(sigs) {
		t.Errorf("expected most findings to be ranked, got %d of %d", ranked, len(sigs))
	}
	if withFix == 0 {
		t.Error("expected at least one finding to name a fixed version")
	}
}
