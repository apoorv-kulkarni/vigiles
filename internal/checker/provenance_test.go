package checker

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestExtractGitHubRepo(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"https://github.com/org/repo", "org/repo"},
		{"https://github.com/org/repo.git", "org/repo"},
		{"git+https://github.com/org/repo", "org/repo"},
		{"git@github.com:org/repo.git", "org/repo"},
		{"https://example.com/notgithub", ""},
	}

	for _, tt := range tests {
		if got := extractGitHubRepo(tt.in); got != tt.want {
			t.Fatalf("extractGitHubRepo(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// redirectTransport rewrites all requests to a fixed base URL so tests can
// intercept calls without modifying production URLs.
type redirectTransport struct {
	base string
}

func (r *redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	newURL := r.base + req.URL.Path + "?" + req.URL.RawQuery
	newReq, err := http.NewRequest(req.Method, newURL, req.Body)
	if err != nil {
		return nil, err
	}
	return http.DefaultTransport.RoundTrip(newReq)
}

func provenanceCheckerWithServer(server *httptest.Server) *ProvenanceChecker {
	return &ProvenanceChecker{
		client: &http.Client{Transport: &redirectTransport{base: server.URL}},
	}
}

// makeTags builds a JSON tag list of n entries using the given names.
func makeTags(names ...string) []byte {
	type tag struct {
		Name string `json:"name"`
	}
	tags := make([]tag, len(names))
	for i, n := range names {
		tags[i] = tag{Name: n}
	}
	b, _ := json.Marshal(tags)
	return b
}

// makeTagPage builds a JSON page of n sequential dummy tags (tag-0, tag-1, …).
func makeTagPage(n int) []byte {
	names := make([]string, n)
	for i := range names {
		names[i] = "unrelated-" + strings.Repeat("x", i%10+1)
	}
	return makeTags(names...)
}

func TestRepoHasVersionTag_APIFailure_ReturnsUnverifiable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden) // simulate rate-limit / auth failure
	}))
	defer server.Close()

	c := provenanceCheckerWithServer(server)
	found, err := c.repoHasVersionTag("org/repo", "1.2.3")
	if err == nil {
		t.Fatal("expected error for non-200 response, got nil")
	}
	if found {
		t.Fatal("expected found=false on API failure")
	}
}

func TestRepoHasVersionTag_TagMissing_ReturnsFalseNoError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(makeTags("v1.0.0", "v1.1.0")) // does not include 1.2.3 or v1.2.3
	}))
	defer server.Close()

	c := provenanceCheckerWithServer(server)
	found, err := c.repoHasVersionTag("org/repo", "1.2.3")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found {
		t.Fatal("expected found=false when tag is absent")
	}
}

func TestRepoHasVersionTag_TagOnLaterPage_ReturnsTrue(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		if callCount == 1 {
			// First page: full page of unrelated tags, no match
			w.Write(makeTagPage(100))
		} else {
			// Second page: contains the target tag
			w.Write(makeTags("v1.9.9", "v1.2.3", "v1.0.0"))
		}
	}))
	defer server.Close()

	c := provenanceCheckerWithServer(server)
	found, err := c.repoHasVersionTag("org/repo", "1.2.3")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !found {
		t.Fatal("expected found=true when tag appears on page 2")
	}
	if callCount != 2 {
		t.Fatalf("expected 2 API calls, got %d", callCount)
	}
}
