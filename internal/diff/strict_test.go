package diff

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type strictTransport func(*http.Request) (*http.Response, error)

func (f strictTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func mockStrictHTTP(t *testing.T, f strictTransport) {
	t.Helper()
	previous := http.DefaultTransport
	http.DefaultTransport = f
	t.Cleanup(func() { http.DefaultTransport = previous })
}

func TestStrictParserRejectsCoverageGaps(t *testing.T) {
	for _, tt := range []struct{ name, body string }{
		{"requirements.txt", "-r hidden.txt\n"},
		{"requirements.txt", "--requirement=hidden.txt\n"},
		{"requirements.txt", "-e git+https://example.test/repo\n"},
		{"requirements.txt", "requests==2.0; python_version > '3'\n"},
		{"requirements.txt", "foo_bar==1.0\nfoo-bar==2.0\n"},
		{"package.json", `{"dependencies":{"a":"1.0.0"},"dependencies":{}}`},
		{"package.json", `{"dependencies":{"a":"1.0.0","a":"2.0.0"}}`},
		{"package.json", `{"dependencies":null}`},
		{"package.json", `{"overrides":{"a":"1.0.0"}}`},
		{"package.json", `{} {}`},
		{"package-lock.json", `{"lockfileVersion":1,"dependencies":{}}`},
		{"package-lock.json", `{"lockfileVersion":3,"packages":{"node_modules/a":{}}}`},
		{"package-lock.json", `{"lockfileVersion":3,"packages":{"node_modules/a":{"version":"1.0.0","link":true}}}`},
		{"package-lock.json", `{"lockfileVersion":3,"packages":{"node_modules/a":{"version":"1.0.0"},"node_modules/b/node_modules/a":{"version":"2.0.0"}}}`},
	} {
		t.Run(tt.name+tt.body, func(t *testing.T) {
			r := CompareStrict(tt.name, nil, []byte(tt.body))
			if r.Complete || len(r.Incomplete) == 0 {
				t.Fatalf("unsupported input passed: %+v", r)
			}
		})
	}
}

func TestStrictRegistryFailuresCannotPass(t *testing.T) {
	for _, tc := range []struct {
		name, body     string
		status         int
		transportError bool
	}{
		{"network", "", 0, true}, {"not found", "{}", 404, false},
		{"bad json", "{", 200, false}, {"missing identity", "{}", 200, false},
		{"wrong identity", `{"name":"different","version":"1.0.0"}`, 200, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mockStrictHTTP(t, func(r *http.Request) (*http.Response, error) {
				if tc.transportError {
					return nil, errors.New("offline")
				}
				return &http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(tc.body)), Header: http.Header{}}, nil
			})
			r := CompareStrict("package.json", []byte(`{}`), []byte(`{"dependencies":{"testpkg":"1.0.0"}}`))
			if r.Complete || len(r.Incomplete) == 0 {
				t.Fatalf("registry failure passed: %+v", r)
			}
		})
	}
}

func TestStrictPyPIMissingDataCannotPass(t *testing.T) {
	for _, body := range []string{"{}", "{", `{"urls":[]}`} {
		mockStrictHTTP(t, func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}, nil
		})
		r := CompareStrict("requirements.txt", nil, []byte("example==1.0.0\n"))
		if r.Complete || len(r.Incomplete) == 0 {
			t.Fatalf("missing PyPI data passed: %+v", r)
		}
	}
}

func TestStrictNpmSuccessfulCheckAndHashes(t *testing.T) {
	requests := 0
	mockStrictHTTP(t, func(r *http.Request) (*http.Response, error) {
		requests++
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"name":"testpkg","version":"1.0.0"}`)), Header: http.Header{}}, nil
	})
	r := CompareStrict("package.json", []byte(`{}`), []byte(`{"optionalDependencies":{"testpkg":"1.0.0"}}`))
	if !r.Complete || requests != 1 || len(r.Entries) != 1 || r.OldSHA256 == r.NewSHA256 {
		t.Fatalf("unexpected result: %+v, requests=%d", r, requests)
	}
}

func TestStrictUnchangedAndRemovedDependenciesNeedNoNetwork(t *testing.T) {
	mockStrictHTTP(t, func(r *http.Request) (*http.Response, error) {
		t.Fatal("unexpected network lookup")
		return nil, errors.New("unexpected")
	})
	for _, next := range [][]byte{[]byte("requests==2.32.0\n"), nil} {
		r := CompareStrict("requirements.txt", []byte("requests==2.32.0\n"), next)
		if !r.Complete {
			t.Fatalf("unexpected gaps: %v", r.Incomplete)
		}
	}
}

func TestStrictUnpinnedVersionsCannotPass(t *testing.T) {
	for _, version := range []string{"latest", "^1.0.0", "file:../pkg", "npm:other@1.0.0", "https://example.test/pkg.tgz"} {
		r := CompareStrict("package.json", nil, []byte(`{"dependencies":{"testpkg":"`+version+`"}}`))
		if r.Complete {
			t.Fatalf("version %q passed", version)
		}
	}
	for _, version := range []string{">=1.0", "==1.*", "==1.0,!=1.1"} {
		r := CompareStrict("requirements.txt", nil, []byte("testpkg"+version))
		if r.Complete {
			t.Fatalf("version %q passed", version)
		}
	}
}

func TestStrictLockfileArtifactChangeWithoutVersionChange(t *testing.T) {
	old := []byte(`{"lockfileVersion":3,"packages":{"node_modules/a":{"version":"1.0.0","resolved":"https://registry.npmjs.org/a/-/a-1.0.0.tgz","integrity":"sha512-old"}}}`)
	next := []byte(strings.ReplaceAll(string(old), "sha512-old", "sha512-new"))
	r := CompareStrict("package-lock.json", old, next)
	if !r.Complete || len(r.Entries) != 1 || r.Entries[0].Signals[0].ID != "VIGILES-NPM-ARTIFACT-CHANGE" {
		t.Fatalf("artifact change was missed: %+v", r)
	}
	next = []byte(strings.ReplaceAll(string(old), "https://registry.npmjs.org", "https://example.test"))
	if r := CompareStrict("package-lock.json", old, next); r.Complete {
		t.Fatal("uninspected artifact source passed")
	}
}
