package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/apoorv-kulkarni/vigiles/internal/config"
	"github.com/apoorv-kulkarni/vigiles/internal/reporter"
	"github.com/apoorv-kulkarni/vigiles/internal/scanner"
)

type enforcementTransport func(*http.Request) (*http.Response, error)

func (f enforcementTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestStrictScanCannotSuppressMissingInventory(t *testing.T) {
	useFakeScanner(t, "pip", nil, errors.New("unavailable"))
	body, code := scanToFile(t, "json", scanOptions{Strict: true, FailOn: map[string]bool{"none": true}})
	var r reporter.Report
	if err := json.Unmarshal([]byte(body), &r); err != nil {
		t.Fatal(err)
	}
	if code != ExitError || r.Status != "incomplete" || len(r.Incomplete) == 0 {
		t.Fatalf("missing inventory passed: code=%d report=%+v", code, r)
	}
}

func TestStrictScanCannotDisableChecks(t *testing.T) {
	useFakeScanner(t, "pip", []scanner.Package{{Name: "requests", Version: "2.32.0", Ecosystem: "pip"}}, nil)
	_, code := scanToFile(t, "json", scanOptions{Strict: true, FailOn: map[string]bool{"none": true}})
	if code != ExitError {
		t.Fatalf("skip flags bypassed strict scan: %d", code)
	}
}

func TestStrictScanReportsOSVFailure(t *testing.T) {
	useFakeScanner(t, "gomod", []scanner.Package{{Name: "example.test/mod", Version: "v1.0.0", Ecosystem: "gomod"}}, nil)
	t.Setenv("PATH", t.TempDir())
	previous := http.DefaultTransport
	http.DefaultTransport = enforcementTransport(func(r *http.Request) (*http.Response, error) { return nil, errors.New("offline") })
	t.Cleanup(func() { http.DefaultTransport = previous })
	out := filepath.Join(t.TempDir(), "report.json")
	code := runScanWithOptions([]string{"gomod"}, "json", out, false, false, false, false, io.Discard,
		scanOptions{Strict: true, FailOn: map[string]bool{"none": true}})
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if code != ExitError || !strings.Contains(string(data), "OSV lookup failed") {
		t.Fatalf("OSV failure passed: %d %s", code, data)
	}
}

func TestReportingModeShowsIncompleteInsteadOfClean(t *testing.T) {
	useFakeScanner(t, "pip", nil, errors.New("unavailable"))
	for _, format := range []string{"summary", "table", "sarif"} {
		body, code := scanToFile(t, format, scanOptions{})
		if code != ExitClean {
			t.Fatalf("reporting compatibility changed: %d", code)
		}
		if strings.Contains(body, "✅") {
			t.Fatalf("incomplete scan claims clean: %s", body)
		}
		if format == "sarif" && !strings.Contains(body, `"executionSuccessful": false`) {
			t.Fatalf("SARIF claims success: %s", body)
		}
	}
}

func TestStrictDiffCoverageCannotBeSuppressed(t *testing.T) {
	dir := t.TempDir()
	old, next := filepath.Join(dir, "old.txt"), filepath.Join(dir, "requirements.txt")
	writeFile(t, old, "")
	writeFile(t, next, "-r hidden.txt\n")
	code := runStrictDiff(old, next, "json", &config.Config{Suppress: []config.Suppression{{ID: "VIGILES-UNPINNED"}}}, map[string]bool{"none": true})
	if code != ExitError {
		t.Fatalf("coverage suppression succeeded: %d", code)
	}
}

func TestGateRejectsPolicyOverridesAndInvalidRefs(t *testing.T) {
	for _, args := range [][]string{{"--fail-on", "none"}, {"--skip-vuln"}, {"--base", "HEAD", "--head", "HEAD"}, {"requirements.txt"}} {
		if code := runGateCmd(args); code != ExitError {
			t.Fatalf("gate accepted %v: %d", args, code)
		}
	}
}

func TestScanPreservesFindingsFromPartialOSVResponse(t *testing.T) {
	var packages []scanner.Package
	for i := 0; i < 101; i++ {
		packages = append(packages, scanner.Package{Name: fmt.Sprintf("example.test/mod%d", i), Version: "v1.0.0", Ecosystem: "gomod"})
	}
	useFakeScanner(t, "gomod", packages, nil)
	previous := http.DefaultTransport
	batch := 0
	http.DefaultTransport = enforcementTransport(func(r *http.Request) (*http.Response, error) {
		body := `{"id":"TEST-VULN","summary":"Fixture vulnerability"}`
		if strings.HasSuffix(r.URL.Path, "querybatch") {
			batch++
			if batch == 2 {
				return nil, errors.New("second batch failed")
			}
			results := make([]map[string]any, 100)
			for i := range results {
				results[i] = map[string]any{}
			}
			results[0]["vulns"] = []map[string]string{{"id": "TEST-VULN"}}
			data, err := json.Marshal(map[string]any{"results": results})
			if err != nil {
				t.Fatal(err)
			}
			body = string(data)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}, nil
	})
	t.Cleanup(func() { http.DefaultTransport = previous })
	out := filepath.Join(t.TempDir(), "report.json")
	code := runScanWithOptions([]string{"gomod"}, "json", out, false, true, true, false, io.Discard, scanOptions{Strict: true})
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var r reporter.Report
	if err := json.Unmarshal(data, &r); err != nil {
		t.Fatal(err)
	}
	if code != ExitError || len(r.Signals) != 1 || r.Signals[0].ID != "TEST-VULN" || r.Status != "incomplete" {
		t.Fatalf("partial finding lost: %d %+v", code, r)
	}
}
