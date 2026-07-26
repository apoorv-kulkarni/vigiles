package checker

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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

// osvServer stands in for the two endpoints Vigiles uses. querybatch answers
// with abbreviated entries carrying only an ID, exactly as the real API does,
// so any test asserting on summary, severity, aliases, or fixed versions is
// necessarily proving that the detail lookup ran.
type osvServer struct {
	mu        sync.Mutex
	batchReqs []osvBatchRequest
	detailIDs []string

	// batch returns the response for the nth querybatch call (1-indexed).
	batch func(call int, req osvBatchRequest) osvBatchResponse
	// detail returns the full record for an ID, or ok=false to serve a 500.
	detail func(id string) (osvVuln, bool)
}

func (s *osvServer) handler(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if id, isDetail := strings.CutPrefix(r.URL.Path, "/v1/vulns/"); isDetail {
			s.mu.Lock()
			s.detailIDs = append(s.detailIDs, id)
			s.mu.Unlock()

			vuln, ok := s.detail(id)
			if !ok {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			json.NewEncoder(w).Encode(vuln)
			return
		}

		var req osvBatchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decoding request: %v", err)
		}
		s.mu.Lock()
		s.batchReqs = append(s.batchReqs, req)
		call := len(s.batchReqs)
		s.mu.Unlock()

		json.NewEncoder(w).Encode(s.batch(call, req))
	}
}

// abbreviated builds the ID-only response shape that querybatch really returns.
func abbreviated(req osvBatchRequest, vulnsByQuery map[int][]string) osvBatchResponse {
	resp := osvBatchResponse{Results: make([]osvResult, len(req.Queries))}
	for i, ids := range vulnsByQuery {
		if i >= len(resp.Results) {
			continue
		}
		for _, id := range ids {
			resp.Results[i].Vulns = append(resp.Results[i].Vulns, osvVuln{ID: id})
		}
	}
	return resp
}

func TestOSVCheckerCheck(t *testing.T) {
	osv := &osvServer{
		batch: func(_ int, req osvBatchRequest) osvBatchResponse {
			return abbreviated(req, map[int][]string{0: {"GHSA-xxxx"}})
		},
		detail: func(id string) (osvVuln, bool) {
			return osvVuln{
				ID:       id,
				Summary:  "test vulnerability",
				Aliases:  []string{"CVE-2026-0001"},
				Severity: []osvSeverity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
				Affected: []osvAffected{{Ranges: []osvRange{{Events: []osvEvent{{Fixed: "2.0.0"}}}}}},
			}, true
		},
	}
	server := httptest.NewServer(osv.handler(t))
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
	if got := len(osv.batchReqs[0].Queries); got != 2 {
		t.Errorf("expected brew to be filtered out, got %d queries", got)
	}
	if len(sigs) != 1 {
		t.Fatalf("expected 1 signal, got %d: %+v", len(sigs), sigs)
	}

	got := sigs[0]
	if got.ID != "GHSA-xxxx" || got.Type != "vulnerability" {
		t.Errorf("unexpected signal: %+v", got)
	}
	if got.Summary != "test vulnerability" {
		t.Errorf("expected the summary from the detail record, got %q", got.Summary)
	}
	if got.Severity != "critical" {
		t.Errorf("expected severity scored from the CVSS vector, got %q", got.Severity)
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

// A failed detail lookup must degrade the finding's metadata, never hide the
// finding. Dropping a real CVE because a follow-up request failed would be the
// worst possible failure mode for a CI gate.
func TestOSVCheckerKeepsFindingWhenDetailLookupFails(t *testing.T) {
	osv := &osvServer{
		batch: func(_ int, req osvBatchRequest) osvBatchResponse {
			return abbreviated(req, map[int][]string{0: {"GHSA-broken"}})
		},
		detail: func(string) (osvVuln, bool) { return osvVuln{}, false },
	}
	server := httptest.NewServer(osv.handler(t))
	defer server.Close()

	c := &OSVChecker{client: interceptClient(server)}
	sigs, err := c.Check([]scanner.Package{{Name: "requests", Version: "2.31.0", Ecosystem: "pip"}})
	if err != nil {
		t.Fatalf("a detail failure should not fail the batch, got %v", err)
	}
	if len(sigs) != 1 {
		t.Fatalf("expected the finding retained, got %+v", sigs)
	}
	if sigs[0].ID != "GHSA-broken" || sigs[0].Severity != "unknown" {
		t.Errorf("expected an unknown-severity finding keyed by ID, got %+v", sigs[0])
	}
	if !strings.Contains(sigs[0].Summary, "GHSA-broken") {
		t.Errorf("expected the summary to name the ID, got %q", sigs[0].Summary)
	}
}

// One advisory commonly affects several installed packages; it should be
// fetched once.
func TestOSVCheckerDeduplicatesDetailLookups(t *testing.T) {
	osv := &osvServer{
		batch: func(_ int, req osvBatchRequest) osvBatchResponse {
			return abbreviated(req, map[int][]string{0: {"GHSA-shared"}, 1: {"GHSA-shared"}})
		},
		detail: func(id string) (osvVuln, bool) {
			return osvVuln{ID: id, Summary: "shared advisory"}, true
		},
	}
	server := httptest.NewServer(osv.handler(t))
	defer server.Close()

	c := &OSVChecker{client: interceptClient(server)}
	sigs, err := c.Check([]scanner.Package{
		{Name: "requests", Version: "2.31.0", Ecosystem: "pip"},
		{Name: "flask", Version: "3.0.0", Ecosystem: "pip"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sigs) != 2 {
		t.Fatalf("expected both packages flagged, got %+v", sigs)
	}
	if len(osv.detailIDs) != 1 {
		t.Errorf("expected the shared advisory fetched once, got %v", osv.detailIDs)
	}
	for _, s := range sigs {
		if s.Summary != "shared advisory" {
			t.Errorf("expected both signals hydrated, got %+v", s)
		}
	}
}

// OSV paginates per query, so only the queries that reported more results are
// replayed, each carrying its own token.
func TestOSVCheckerPaginatesQueryBatch(t *testing.T) {
	osv := &osvServer{
		batch: func(call int, req osvBatchRequest) osvBatchResponse {
			if call == 1 {
				resp := abbreviated(req, map[int][]string{0: {"GHSA-page1"}, 1: {"GHSA-other"}})
				resp.Results[0].NextPageToken = "token-2"
				return resp
			}
			return abbreviated(req, map[int][]string{0: {"GHSA-page2"}})
		},
		detail: func(id string) (osvVuln, bool) { return osvVuln{ID: id, Summary: id}, true },
	}
	server := httptest.NewServer(osv.handler(t))
	defer server.Close()

	c := &OSVChecker{client: interceptClient(server)}
	sigs, err := c.Check([]scanner.Package{
		{Name: "requests", Version: "2.31.0", Ecosystem: "pip"},
		{Name: "flask", Version: "3.0.0", Ecosystem: "pip"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(osv.batchReqs) != 2 {
		t.Fatalf("expected a follow-up request for the paginated query, got %d", len(osv.batchReqs))
	}

	second := osv.batchReqs[1]
	if len(second.Queries) != 1 {
		t.Errorf("expected only the paginated query replayed, got %d", len(second.Queries))
	}
	if second.Queries[0].PageToken != "token-2" {
		t.Errorf("expected the page token echoed back, got %q", second.Queries[0].PageToken)
	}
	if second.Queries[0].Package.Name != "requests" {
		t.Errorf("expected the replay to target the original package, got %q", second.Queries[0].Package.Name)
	}

	owners := map[string]string{}
	for _, s := range sigs {
		owners[s.ID] = s.Package
	}
	if len(owners) != 3 {
		t.Fatalf("expected findings from both pages, got %+v", owners)
	}
	if owners["GHSA-page2"] != "requests" {
		t.Errorf("expected the second page attributed to requests, got %q", owners["GHSA-page2"])
	}
}

// A server that never stops handing back tokens must not loop forever.
func TestOSVCheckerBoundsPagination(t *testing.T) {
	osv := &osvServer{
		batch: func(call int, req osvBatchRequest) osvBatchResponse {
			resp := abbreviated(req, map[int][]string{0: {fmt.Sprintf("GHSA-%d", call)}})
			resp.Results[0].NextPageToken = "always-more"
			return resp
		},
		detail: func(id string) (osvVuln, bool) { return osvVuln{ID: id}, true },
	}
	server := httptest.NewServer(osv.handler(t))
	defer server.Close()

	c := &OSVChecker{client: interceptClient(server)}
	if _, err := c.Check([]scanner.Package{{Name: "requests", Version: "2.31.0", Ecosystem: "pip"}}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(osv.batchReqs) != maxQueryPages {
		t.Errorf("expected pagination capped at %d pages, got %d", maxQueryPages, len(osv.batchReqs))
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
