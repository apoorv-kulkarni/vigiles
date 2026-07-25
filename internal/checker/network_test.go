package checker

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/apoorv-kulkarni/vigiles/internal/scanner"
)

// interceptClient returns a client whose requests are all rewritten to server,
// letting these tests exercise the real request/response paths without changing
// the hardcoded production URLs.
func interceptClient(server *httptest.Server) *http.Client {
	return &http.Client{Transport: &redirectTransport{base: server.URL}}
}

// --- OSV ---

func TestOSVCheckerCheck(t *testing.T) {
	var gotQueries int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req osvBatchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decoding request: %v", err)
		}
		gotQueries = len(req.Queries)

		// One result per query, in order. Only the first carries a vuln.
		resp := osvBatchResponse{Results: make([]osvResult, len(req.Queries))}
		if len(resp.Results) > 0 {
			resp.Results[0].Vulns = []osvVuln{{
				ID:       "GHSA-xxxx",
				Summary:  "test vulnerability",
				Aliases:  []string{"CVE-2026-0001"},
				Severity: []osvSeverity{{Type: "CVSS_V3", Score: "9.8"}},
				Affected: []osvAffected{{Ranges: []osvRange{{Events: []osvEvent{{Fixed: "2.0.0"}}}}}},
			}}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	c := &OSVChecker{client: interceptClient(server)}
	sigs, err := c.Check([]scanner.Package{
		{Name: "requests", Version: "2.31.0", Ecosystem: "pip"},
		{Name: "axios", Version: "1.7.2", Ecosystem: "npm"},
		{Name: "jq", Version: "1.7.1", Ecosystem: "brew"}, // no OSV ecosystem, filtered out
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotQueries != 2 {
		t.Errorf("expected brew to be filtered out, got %d queries", gotQueries)
	}
	if len(sigs) != 1 {
		t.Fatalf("expected 1 signal, got %d: %+v", len(sigs), sigs)
	}

	got := sigs[0]
	if got.ID != "GHSA-xxxx" || got.Type != "vulnerability" {
		t.Errorf("unexpected signal: %+v", got)
	}
	if got.Severity != "critical" {
		t.Errorf("expected severity from the CVSS score, got %q", got.Severity)
	}
	if got.Package != "requests" || got.Ecosystem != "pip" {
		t.Errorf("expected the signal mapped to the first query, got %+v", got)
	}
	if !strings.Contains(got.Remediation, "2.0.0") {
		t.Errorf("expected the fixed version in remediation, got %q", got.Remediation)
	}
	if len(got.Aliases) != 1 || got.Aliases[0] != "CVE-2026-0001" {
		t.Errorf("expected aliases carried through, got %v", got.Aliases)
	}
}

func TestOSVCheckerCheckAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte("rate limited"))
	}))
	defer server.Close()

	c := &OSVChecker{client: interceptClient(server)}
	sigs, err := c.Check([]scanner.Package{{Name: "requests", Version: "2.31.0", Ecosystem: "pip"}})
	if err == nil {
		t.Fatal("expected an error when OSV returns a non-200 status")
	}
	if !strings.Contains(err.Error(), "partial results") {
		t.Errorf("expected the error to flag partial results, got %v", err)
	}
	if len(sigs) != 0 {
		t.Errorf("expected no signals, got %+v", sigs)
	}
}

func TestOSVCheckerCheckResultCountMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Two queries were sent but only one result comes back.
		json.NewEncoder(w).Encode(osvBatchResponse{Results: []osvResult{{}}})
	}))
	defer server.Close()

	c := &OSVChecker{client: interceptClient(server)}
	_, err := c.Check([]scanner.Package{
		{Name: "requests", Version: "2.31.0", Ecosystem: "pip"},
		{Name: "flask", Version: "3.0.0", Ecosystem: "pip"},
	})
	if err == nil {
		t.Fatal("expected an error when the result count does not match the query count")
	}
}

func TestOSVCheckerNoQueryablePackages(t *testing.T) {
	// brew has no OSV ecosystem, so no request should be attempted at all.
	c := &OSVChecker{client: interceptClient(httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			t.Error("did not expect an OSV request for brew-only input")
		})))}

	sigs, err := c.Check([]scanner.Package{{Name: "jq", Version: "1.7.1", Ecosystem: "brew"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sigs) != 0 {
		t.Errorf("expected no signals, got %+v", sigs)
	}
}

func TestNewOSVChecker(t *testing.T) {
	if c := NewOSVChecker(); c == nil || c.client == nil {
		t.Fatal("expected a checker with an initialized client")
	}
}

// --- recency ---

// pypiUploadHandler serves a PyPI version payload with the given upload time.
func pypiUploadHandler(t *testing.T, iso string) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(pypiVersionResponse{
			Urls: []pypiFile{{UploadTimeISO: iso}},
		})
	}
}

func recencyCheckerWithServer(server *httptest.Server, now time.Time) *RecencyChecker {
	return &RecencyChecker{
		client: interceptClient(server),
		Now:    func() time.Time { return now },
		cache:  map[string]*recencyCacheEntry{},
	}
}

func TestRecencyCheckerFlagsRecentRelease(t *testing.T) {
	server := httptest.NewServer(pypiUploadHandler(t, "2026-03-25T10:00:00Z"))
	defer server.Close()

	now := time.Date(2026, 3, 25, 16, 0, 0, 0, time.UTC) // 6 hours after upload
	c := recencyCheckerWithServer(server, now)

	sigs, stats := c.CheckWithStats([]scanner.Package{
		{Name: "litellm", Version: "1.82.8", Ecosystem: "pip"},
		{Name: "axios", Version: "1.7.2", Ecosystem: "npm"}, // skipped, not pip
	})
	if stats.Checked != 1 {
		t.Errorf("expected only the pip package checked, got %d", stats.Checked)
	}
	if len(sigs) != 1 || sigs[0].ID != "VIGILES-RECENTLY-PUBLISHED" {
		t.Fatalf("expected a recency signal, got %+v", sigs)
	}
	if !strings.Contains(sigs[0].Summary, "6 hours") {
		t.Errorf("expected the age in the summary, got %q", sigs[0].Summary)
	}
	if stats.Signals != 1 {
		t.Errorf("expected stats to count the signal, got %+v", stats)
	}
}

func TestRecencyCheckerIgnoresOldRelease(t *testing.T) {
	server := httptest.NewServer(pypiUploadHandler(t, "2026-01-01T10:00:00Z"))
	defer server.Close()

	c := recencyCheckerWithServer(server, time.Date(2026, 3, 26, 10, 0, 0, 0, time.UTC))
	if sigs := c.Check([]scanner.Package{{Name: "requests", Version: "2.31.0", Ecosystem: "pip"}}); len(sigs) != 0 {
		t.Errorf("expected no signal for an old release, got %+v", sigs)
	}
}

func TestRecencyCheckerCheckVersion(t *testing.T) {
	server := httptest.NewServer(pypiUploadHandler(t, "2026-03-25T10:00:00Z"))
	defer server.Close()

	c := recencyCheckerWithServer(server, time.Date(2026, 3, 26, 10, 0, 0, 0, time.UTC))

	if sig := c.CheckVersion("litellm", "1.82.8", "pip"); sig == nil {
		t.Error("expected a signal for a recent pip release")
	}
	if sig := c.CheckVersion("axios", "1.7.2", "npm"); sig != nil {
		t.Errorf("expected non-pip ecosystems to be skipped, got %+v", sig)
	}
}

func TestRecencyCheckerCachesLookups(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		pypiUploadHandler(t, "2026-03-25T10:00:00Z")(w, r)
	}))
	defer server.Close()

	c := recencyCheckerWithServer(server, time.Date(2026, 3, 26, 10, 0, 0, 0, time.UTC))
	for i := 0; i < 3; i++ {
		if sig := c.CheckVersion("litellm", "1.82.8", "pip"); sig == nil {
			t.Fatalf("expected a signal on iteration %d", i)
		}
	}
	if requests != 1 {
		t.Errorf("expected repeated lookups to be cached, got %d requests", requests)
	}
}

func TestRecencyCheckerMissingVersionIsNotAnError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	c := recencyCheckerWithServer(server, time.Now())
	uploadTime, found, err := c.fetchUploadTime("nonexistent", "1.0.0")
	if err != nil {
		t.Fatalf("a 404 should not be an error, got %v", err)
	}
	if found || !uploadTime.IsZero() {
		t.Errorf("expected no upload time, got %v (found=%v)", uploadTime, found)
	}
}

func TestRecencyCheckerMalformedPayload(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("{not json"))
	}))
	defer server.Close()

	c := recencyCheckerWithServer(server, time.Now())
	_, found, err := c.fetchUploadTime("pkg", "1.0.0")
	if err != nil {
		t.Fatalf("malformed payloads are treated as missing data, got %v", err)
	}
	if found {
		t.Error("expected found=false for a malformed payload")
	}
}

// --- sigstore ---

func TestSigstoreCheckerAttested(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"urls": [{"filename": "x.whl", "provenance": "https://pypi.org/integrity/x"}]}`))
	}))
	defer server.Close()

	c := &SigstoreChecker{client: interceptClient(server)}
	sigs := c.Check([]scanner.Package{{Name: "requests", Version: "2.32.0", Ecosystem: "pip", Direct: true}})
	if len(sigs) != 1 || sigs[0].ID != "VIGILES-PEP740-ATTESTED" {
		t.Fatalf("expected an attested signal, got %+v", sigs)
	}
	if sigs[0].Severity != "info" {
		t.Errorf("expected info severity for an attested release, got %q", sigs[0].Severity)
	}
}

func TestSigstoreCheckerNotAttested(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"urls": [{"filename": "x.whl"}]}`))
	}))
	defer server.Close()

	c := &SigstoreChecker{client: interceptClient(server)}
	sigs := c.Check([]scanner.Package{{Name: "requests", Version: "2.32.0", Ecosystem: "pip", Direct: true}})
	if len(sigs) != 1 || sigs[0].ID != "VIGILES-PEP740-NO-ATTESTATION" {
		t.Fatalf("expected a missing-attestation signal, got %+v", sigs)
	}
	if sigs[0].Severity != "low" {
		t.Errorf("expected low severity when attestation is absent, got %q", sigs[0].Severity)
	}
}

func TestSigstoreCheckerSkipsIneligiblePackages(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("did not expect a request for ineligible packages")
	}))
	defer server.Close()

	c := &SigstoreChecker{client: interceptClient(server)}
	sigs := c.Check([]scanner.Package{
		{Name: "axios", Version: "1.7.2", Ecosystem: "npm", Direct: true}, // not pip
		{Name: "urllib3", Version: "2.2.1", Ecosystem: "pip"},             // transitive
		{Name: "certifi", Version: "", Ecosystem: "pip", Direct: true},    // no version
	})
	if len(sigs) != 0 {
		t.Errorf("expected no signals, got %+v", sigs)
	}
}

func TestSigstoreCheckerNilClient(t *testing.T) {
	var c *SigstoreChecker
	if sigs := c.Check(nil); sigs != nil {
		t.Errorf("expected nil for a nil checker, got %+v", sigs)
	}
	if sigs := (&SigstoreChecker{}).Check(nil); sigs != nil {
		t.Errorf("expected nil when the client is unset, got %+v", sigs)
	}
}

func TestNewSigstoreChecker(t *testing.T) {
	if c := NewSigstoreChecker(); c == nil || c.client == nil {
		t.Fatal("expected a checker with an initialized client")
	}
}

// --- provenance ---

func TestProvenanceFindRepoFromPyPI(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"info": {"project_urls": {"Source": "https://github.com/psf/requests"}}}`))
	}))
	defer server.Close()

	c := provenanceCheckerWithServer(server)
	if got := c.findRepoFromPyPI("requests", "2.32.0"); got != "psf/requests" {
		t.Errorf("findRepoFromPyPI = %q, want psf/requests", got)
	}
}

func TestProvenanceFindRepoFromPyPIMissing(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"info": {"project_urls": {"Docs": "https://example.com/docs"}}}`))
	}))
	defer server.Close()

	c := provenanceCheckerWithServer(server)
	if got := c.findRepoFromPyPI("pkg", "1.0.0"); got != "" {
		t.Errorf("expected no repo for non-GitHub URLs, got %q", got)
	}
}

func TestProvenanceFindRepoFromNPM(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"repository": {"url": "git+https://github.com/axios/axios.git"}}`))
	}))
	defer server.Close()

	c := provenanceCheckerWithServer(server)
	if got := c.findRepoFromNPM("axios", "1.7.2"); got != "axios/axios" {
		t.Errorf("findRepoFromNPM = %q, want axios/axios", got)
	}
}

func TestProvenanceCheckTagMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/tags") {
			w.Write(makeTags("v1.0.0")) // the requested 2.32.0 is absent
			return
		}
		w.Write([]byte(`{"info": {"project_urls": {"Source": "https://github.com/psf/requests"}}}`))
	}))
	defer server.Close()

	c := provenanceCheckerWithServer(server)
	sigs := c.Check([]scanner.Package{
		{Name: "requests", Version: "2.32.0", Ecosystem: "pip", Direct: true},
	})
	if len(sigs) != 1 || sigs[0].ID != "VIGILES-PROVENANCE-TAG-MISMATCH" {
		t.Fatalf("expected a tag mismatch signal, got %+v", sigs)
	}
	if sigs[0].Type != "trust-signal" {
		t.Errorf("expected a trust signal, got %q", sigs[0].Type)
	}
}

func TestProvenanceCheckSkipsIneligiblePackages(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("did not expect a request for ineligible packages")
	}))
	defer server.Close()

	c := provenanceCheckerWithServer(server)
	sigs := c.Check([]scanner.Package{
		{Name: "urllib3", Version: "2.2.1", Ecosystem: "pip"},           // transitive
		{Name: "certifi", Version: "", Ecosystem: "pip", Direct: true},  // no version
		{Name: "jq", Version: "1.7.1", Ecosystem: "brew", Direct: true}, // unsupported ecosystem
	})
	if len(sigs) != 0 {
		t.Errorf("expected no signals, got %+v", sigs)
	}
}

func TestNewProvenanceChecker(t *testing.T) {
	if c := NewProvenanceChecker(); c == nil || c.client == nil {
		t.Fatal("expected a checker with an initialized client")
	}
}
