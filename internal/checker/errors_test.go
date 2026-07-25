package checker

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/apoorv-kulkarni/vigiles/internal/scanner"
)

// failingTransport fails every request, standing in for a network outage or a
// DNS failure without waiting on a real timeout.
type failingTransport struct{}

func (failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("simulated transport failure")
}

func offlineClient() *http.Client {
	return &http.Client{Transport: failingTransport{}}
}

// jsonHandler serves a fixed body for any request.
func jsonHandler(status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}
}

func serve(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(h)
	t.Cleanup(server.Close)
	return server
}

// --- OSV ---

func TestOSVCheckerTransportFailure(t *testing.T) {
	c := &OSVChecker{client: offlineClient()}

	sigs, err := c.Check([]scanner.Package{
		{Name: "requests", Version: "2.31.0", Ecosystem: "pip"},
	})
	if err == nil {
		t.Fatal("expected a transport failure to surface as an error")
	}
	if !strings.Contains(err.Error(), "OSV API request failed") {
		t.Errorf("expected the request failure wrapped, got: %v", err)
	}
	if len(sigs) != 0 {
		t.Errorf("expected no signals on failure, got %d", len(sigs))
	}
}

func TestOSVCheckerMalformedResponse(t *testing.T) {
	server := serve(t, jsonHandler(http.StatusOK, "{not json"))
	c := &OSVChecker{client: interceptClient(server)}

	_, err := c.Check([]scanner.Package{
		{Name: "requests", Version: "2.31.0", Ecosystem: "pip"},
	})
	if err == nil || !strings.Contains(err.Error(), "parsing OSV response") {
		t.Errorf("expected a parse error, got: %v", err)
	}
}

// --- Recency ---

func TestRecencyCheckerCountsTransportFailures(t *testing.T) {
	c := &RecencyChecker{
		client: offlineClient(),
		Now:    time.Now,
		cache:  map[string]*recencyCacheEntry{},
	}

	sigs, stats := c.CheckWithStats([]scanner.Package{
		{Name: "requests", Version: "2.31.0", Ecosystem: "pip"},
		{Name: "flask", Version: "3.0.0", Ecosystem: "pip"},
	})

	if len(sigs) != 0 {
		t.Errorf("expected no signals when PyPI is unreachable, got %d", len(sigs))
	}
	if stats.Checked != 2 || stats.Errors != 2 {
		t.Errorf("expected 2 checked and 2 errors, got %+v", stats)
	}
	// Skipped mirrors Errors so progress output can report unavailable packages.
	if stats.Skipped != stats.Errors {
		t.Errorf("expected Skipped to mirror Errors, got %+v", stats)
	}
}

func TestRecencyCheckVersionTransportFailure(t *testing.T) {
	c := &RecencyChecker{
		client: offlineClient(),
		Now:    time.Now,
		cache:  map[string]*recencyCacheEntry{},
	}

	if sig := c.CheckVersion("requests", "2.31.0", "pip"); sig != nil {
		t.Errorf("expected no signal when the request fails, got %+v", sig)
	}
}

// --- Provenance ---

func provenanceWithServer(server *httptest.Server) *ProvenanceChecker {
	return &ProvenanceChecker{client: interceptClient(server)}
}

func TestProvenanceRegistryLookupFailures(t *testing.T) {
	pkgs := []scanner.Package{
		{Name: "requests", Version: "2.31.0", Ecosystem: "pip", Direct: true},
		{Name: "axios", Version: "1.7.2", Ecosystem: "npm", Direct: true},
	}

	t.Run("transport failure", func(t *testing.T) {
		c := &ProvenanceChecker{client: offlineClient()}
		if sigs := c.Check(pkgs); len(sigs) != 0 {
			t.Errorf("expected no signals when the registry is unreachable, got %d", len(sigs))
		}
	})

	t.Run("not found", func(t *testing.T) {
		c := provenanceWithServer(serve(t, jsonHandler(http.StatusNotFound, `{}`)))
		if sigs := c.Check(pkgs); len(sigs) != 0 {
			t.Errorf("expected no signals for a 404 registry response, got %d", len(sigs))
		}
	})

	t.Run("malformed payload", func(t *testing.T) {
		c := provenanceWithServer(serve(t, jsonHandler(http.StatusOK, "{not json")))
		if sigs := c.Check(pkgs); len(sigs) != 0 {
			t.Errorf("expected no signals for an unparseable payload, got %d", len(sigs))
		}
	})

	t.Run("no github link", func(t *testing.T) {
		c := provenanceWithServer(serve(t, jsonHandler(http.StatusOK,
			`{"info": {"project_urls": {"Docs": "https://example.com/docs"}, "home_page": ""}}`)))
		if sigs := c.Check(pkgs[:1]); len(sigs) != 0 {
			t.Errorf("expected no signals when no repository is discoverable, got %d", len(sigs))
		}
	})
}

func TestProvenanceFallsBackToHomePage(t *testing.T) {
	// project_urls has no GitHub link, so home_page is the fallback source.
	server := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/repos/") {
			fmt.Fprint(w, `[{"name": "v2.31.0"}]`)
			return
		}
		fmt.Fprint(w, `{"info": {"project_urls": {"Docs": "https://example.com"},
			"home_page": "https://github.com/psf/requests"}}`)
	}))

	c := provenanceWithServer(server)
	sigs := c.Check([]scanner.Package{
		{Name: "requests", Version: "2.31.0", Ecosystem: "pip", Direct: true},
	})
	if len(sigs) != 0 {
		t.Errorf("expected a matching tag to produce no signal, got %+v", sigs)
	}
}

func TestProvenanceUnverifiableOnTagFetchFailure(t *testing.T) {
	tests := []struct {
		name    string
		tagsRsp func(w http.ResponseWriter)
	}{
		{"github error status", func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `{"message": "rate limited"}`)
		}},
		{"malformed tag payload", func(w http.ResponseWriter) {
			fmt.Fprint(w, "{not json")
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.Contains(r.URL.Path, "/repos/") {
					tt.tagsRsp(w)
					return
				}
				fmt.Fprint(w, `{"repository": {"url": "git+https://github.com/axios/axios.git"}}`)
			}))

			sigs := provenanceWithServer(server).Check([]scanner.Package{
				{Name: "axios", Version: "1.7.2", Ecosystem: "npm", Direct: true},
			})
			if len(sigs) != 1 {
				t.Fatalf("expected one signal, got %d", len(sigs))
			}
			if sigs[0].ID != "VIGILES-PROVENANCE-UNVERIFIABLE" {
				t.Errorf("expected an unverifiable signal, got %s", sigs[0].ID)
			}
			if sigs[0].Severity != "info" {
				t.Errorf("an unverifiable provenance check should stay informational, got %s", sigs[0].Severity)
			}
		})
	}
}

func TestProvenanceTagPagination(t *testing.T) {
	// The first page is full, so the checker must request a second page to find
	// the matching tag.
	var pagesServed int
	server := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/repos/") {
			fmt.Fprint(w, `{"repository": {"url": "https://github.com/axios/axios"}}`)
			return
		}
		pagesServed++
		if r.URL.Query().Get("page") == "1" {
			names := make([]string, 0, 100)
			for i := 0; i < 100; i++ {
				names = append(names, fmt.Sprintf(`{"name": "v0.%d.0"}`, i))
			}
			fmt.Fprintf(w, "[%s]", strings.Join(names, ","))
			return
		}
		fmt.Fprint(w, `[{"name": "v1.7.2"}]`)
	}))

	sigs := provenanceWithServer(server).Check([]scanner.Package{
		{Name: "axios", Version: "1.7.2", Ecosystem: "npm", Direct: true},
	})
	if len(sigs) != 0 {
		t.Errorf("expected the tag found on page 2 to clear the check, got %+v", sigs)
	}
	if pagesServed != 2 {
		t.Errorf("expected 2 tag pages requested, got %d", pagesServed)
	}
}

func TestProvenanceSkipsUnsupportedEcosystem(t *testing.T) {
	c := provenanceWithServer(serve(t, jsonHandler(http.StatusOK, `{}`)))

	sigs := c.Check([]scanner.Package{
		{Name: "serde", Version: "1.0.0", Ecosystem: "cargo", Direct: true},
		{Name: "brotli", Version: "1.1.0", Ecosystem: "brew", Direct: true},
	})
	if len(sigs) != 0 {
		t.Errorf("expected non-pip/npm packages to be skipped, got %+v", sigs)
	}
}

func TestProvenanceStopsAtCheckLimit(t *testing.T) {
	// Only the first 30 resolvable packages are checked, to bound API usage.
	var tagRequests int
	server := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/repos/") {
			tagRequests++
			fmt.Fprint(w, `[]`) // no tags, so every package mismatches
			return
		}
		fmt.Fprint(w, `{"repository": {"url": "https://github.com/acme/pkg"}}`)
	}))

	pkgs := make([]scanner.Package, 40)
	for i := range pkgs {
		pkgs[i] = scanner.Package{
			Name: fmt.Sprintf("pkg%d", i), Version: "1.0.0", Ecosystem: "npm", Direct: true,
		}
	}

	sigs := provenanceWithServer(server).Check(pkgs)
	if len(sigs) != 30 {
		t.Errorf("expected the check to stop after 30 packages, got %d signals", len(sigs))
	}
	if tagRequests != 30 {
		t.Errorf("expected 30 tag requests, got %d", tagRequests)
	}
}

// --- Sigstore ---

func TestSigstoreTransportFailureReportsNoAttestation(t *testing.T) {
	c := &SigstoreChecker{client: offlineClient()}

	sigs := c.Check([]scanner.Package{
		{Name: "requests", Version: "2.31.0", Ecosystem: "pip", Direct: true},
	})
	if len(sigs) != 1 {
		t.Fatalf("expected one signal, got %d", len(sigs))
	}
	if sigs[0].ID != "VIGILES-PEP740-NO-ATTESTATION" {
		t.Errorf("expected a no-attestation signal, got %s", sigs[0].ID)
	}
}

func TestSigstoreMetadataShapes(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		attested bool
	}{
		{"malformed payload", "{not json", false},
		{"no urls key", `{"info": {}}`, false},
		{"url entry is not an object", `{"urls": ["nope"]}`, false},
		{"attestation key present but null", `{"urls": [{"attestations": null}]}`, false},
		{"unrelated keys only", `{"urls": [{"filename": "x.whl", "size": 1}]}`, false},
		{"provenance present", `{"urls": [{"provenance": "https://pypi.org/prov"}]}`, true},
		{"sigstore key present", `{"urls": [{"Sigstore": {"bundle": "x"}}]}`, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &SigstoreChecker{client: interceptClient(serve(t, jsonHandler(http.StatusOK, tt.body)))}
			if got := c.hasPEP740Metadata("requests", "2.31.0"); got != tt.attested {
				t.Errorf("hasPEP740Metadata = %v, want %v", got, tt.attested)
			}
		})
	}
}

func TestSigstoreNotFoundResponse(t *testing.T) {
	c := &SigstoreChecker{client: interceptClient(serve(t, jsonHandler(http.StatusNotFound, `{}`)))}

	if c.hasPEP740Metadata("requests", "2.31.0") {
		t.Error("expected a 404 to report no attestation metadata")
	}
}
