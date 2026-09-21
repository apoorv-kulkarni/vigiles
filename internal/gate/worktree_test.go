package gate

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/apoorv-kulkarni/vigiles/internal/config"
)

const oldLock = `{"lockfileVersion":3,"packages":{"node_modules/a":{"version":"1.0.0","resolved":"https://registry.npmjs.org/a/-/a-1.0.0.tgz","integrity":"sha512-old"}}}`

func writeWorktree(t *testing.T, repo, name, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(filepath.Join(repo, name)), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, name), []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
}

func openWorktree(t *testing.T, repo, base string) *Workspace {
	t.Helper()
	w, err := OpenWorkspace(repo, base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := w.Close(); err != nil {
			t.Error(err)
		}
	})
	return w
}

func TestWorktreeUsesFrozenBaseAndSharesVerdicts(t *testing.T) {
	repo := fixtureRepo(t)
	base := snapshot(t, repo, "", map[string]string{"package-lock.json": oldLock}, "")
	head := snapshot(t, repo, base, map[string]string{"package-lock.json": strings.ReplaceAll(oldLock, "old", "new")}, "")
	w := openWorktree(t, repo, base)
	writeWorktree(t, repo, "package-lock.json", oldLock)
	r := w.Check(context.Background())
	if Decide(r, "test", io.Discard) != 0 || r.SnapshotSHA256 == "" {
		t.Fatalf("clean: %+v", r)
	}
	before := r.SnapshotSHA256
	writeWorktree(t, repo, "package-lock.json", strings.ReplaceAll(oldLock, "old", "new"))
	writeWorktree(t, repo, ".vigiles.yaml", "version: 1\npolicy:\n  fail-on: none\n")
	committed, err := Run(repo, base, head)
	if err != nil {
		t.Fatal(err)
	}
	r = w.Check(context.Background())
	if Decide(r, "test", io.Discard) != Decide(committed, "test", io.Discard) || r.Status != "blocked" || !r.PolicyChanged || r.SnapshotSHA256 == before {
		t.Fatalf("policy bypass or disagreement: %+v", r)
	}
	if r.Signals[0].ID != "VIGILES-NPM-ARTIFACT-CHANGE" {
		t.Fatalf("wrong finding: %+v", r.Signals)
	}
	// The server must not reread policy or blobs from a newly substituted repository.
	fixtureGit(t, repo, "", "replace", base, head)
	writeWorktree(t, repo, "package-lock.json", oldLock)
	r = w.Check(context.Background())
	if Decide(r, "test", io.Discard) != 0 {
		t.Fatalf("baseline changed after startup: %+v", r)
	}
}

func TestWorktreeDiscoversIgnoredUntrackedAndDeletedInputs(t *testing.T) {
	repo := fixtureRepo(t)
	base := snapshot(t, repo, "", map[string]string{"old/requirements.txt": "requests==2.32.0\n", ".vigiles.yaml": "version: 1\npolicy:\n  fail-on: none\n"}, "")
	w := openWorktree(t, repo, base)
	writeWorktree(t, repo, ".gitignore", "hidden/\n")
	writeWorktree(t, repo, "hidden/requirements.txt", "-r secret.txt\n")
	writeWorktree(t, repo, "new/uv.lock", "version = 1\nrevision = 3\n\n[[package]]\nname = \"demo\"\nversion = \"0.1.0\"\nsource = { editable = \".\" }\n")
	writeWorktree(t, repo, "new/pnpm-lock.yaml", "lockfileVersion: '9.0'\n\npackages:\n  react@19.1.1:\n    resolution: {integrity: sha512-react}\n")
	r := w.Check(context.Background())
	if Decide(r, "test", io.Discard) != 2 || len(r.Inputs) != 4 || len(r.Incomplete) < 1 {
		t.Fatalf("missed worktree inputs: %+v", r)
	}
	if r.Inputs[0].Path != "hidden/requirements.txt" || r.Inputs[1].Path != "new/pnpm-lock.yaml" ||
		r.Inputs[2].Path != "new/uv.lock" || r.Inputs[3].Path != "old/requirements.txt" {
		t.Fatalf("wrong paths: %+v", r.Inputs)
	}
}

func TestWorktreeIgnoresIndexAndDoesNotWrite(t *testing.T) {
	repo := fixtureRepo(t)
	base := snapshot(t, repo, "", map[string]string{"package.json": "{}"}, "")
	w := openWorktree(t, repo, base)
	writeWorktree(t, repo, "package.json", "{}")
	fixtureGit(t, repo, "", "add", "package.json")
	indexBefore := fixtureGit(t, repo, "", "write-tree")
	writeWorktree(t, repo, "package.json", `{"dependencies":{"a":"*"}}`)
	r := w.Check(context.Background())
	if Decide(r, "test", io.Discard) != 2 {
		t.Fatalf("scanned staged bytes: %+v", r)
	}
	if indexAfter := fixtureGit(t, repo, "", "write-tree"); indexAfter != indexBefore {
		t.Fatal("modified index")
	}
}

func TestWorktreeRejectsUnsafeOrUncoveredFiles(t *testing.T) {
	for _, kind := range []string{"file symlink", "directory symlink", "directory manifest", "nested repo", "oversized", "empty npm"} {
		t.Run(kind, func(t *testing.T) {
			repo := fixtureRepo(t)
			base := snapshot(t, repo, "", map[string]string{"requirements.txt": ""}, "")
			w := openWorktree(t, repo, base)
			writeWorktree(t, repo, "requirements.txt", "")
			switch kind {
			case "file symlink", "directory symlink":
				name := "package.json"
				if kind == "directory symlink" {
					name = "hidden"
				}
				if err := os.Symlink(t.TempDir(), filepath.Join(repo, name)); err != nil {
					t.Fatal(err)
				}
			case "directory manifest":
				if err := os.Mkdir(filepath.Join(repo, "package.json"), 0700); err != nil {
					t.Fatal(err)
				}
			case "nested repo":
				writeWorktree(t, repo, "nested/.git", "gitdir: /elsewhere")
			case "oversized":
				writeWorktree(t, repo, "package.json", strings.Repeat(" ", maxManifestBytes+1))
			case "empty npm":
				writeWorktree(t, repo, "package.json", "")
			}
			r := w.Check(context.Background())
			if Decide(r, "test", io.Discard) != 2 {
				t.Fatalf("unsafe input passed: %+v", r)
			}
		})
	}
}

type worktreeTransport func(*http.Request) (*http.Response, error)

func (f worktreeTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestWorktreeDetectsChangesDuringMetadataChecks(t *testing.T) {
	repo := fixtureRepo(t)
	base := snapshot(t, repo, "", map[string]string{"package.json": "{}"}, "")
	w := openWorktree(t, repo, base)
	writeWorktree(t, repo, "package.json", `{"dependencies":{"a":"1.0.0"}}`)
	original := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = original })
	http.DefaultTransport = worktreeTransport(func(req *http.Request) (*http.Response, error) {
		writeWorktree(t, repo, "new/requirements.txt", "-r hidden.txt")
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"name":"a","version":"1.0.0"}`)), Header: http.Header{}}, nil
	})
	r := w.Check(context.Background())
	if Decide(r, "test", io.Discard) != 2 || !strings.Contains(strings.Join(r.Incomplete, " "), "worktree changed") {
		t.Fatalf("stale result passed: %+v", r)
	}
}

func TestWorktreeStartupAndVerdictFailures(t *testing.T) {
	repo := fixtureRepo(t)
	base := snapshot(t, repo, "", map[string]string{"requirements.txt": ""}, "")
	for _, ref := range []string{"HEAD", "main", "", strings.Repeat("a", 40)} {
		if w, err := OpenWorkspace(repo, ref); err == nil {
			w.Close()
			t.Fatalf("accepted base %q", ref)
		}
	}
	writeWorktree(t, repo, "child/README.md", "child")
	if w, err := OpenWorkspace(filepath.Join(repo, "child"), base); err == nil {
		w.Close()
		t.Fatal("accepted subdirectory")
	}
	w := openWorktree(t, repo, base)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := w.Check(ctx)
	if Decide(r, "test", io.Discard) != 2 {
		t.Fatalf("canceled check passed: %+v", r)
	}
	r = &Report{Policy: &config.Config{Policy: config.Policy{FailOn: "garbage"}}}
	if Decide(r, "test", io.Discard) != 2 {
		t.Fatal("invalid policy passed")
	}
}

func TestGateDoesNotTreatEmptyNPMFileAsDeleted(t *testing.T) {
	repo := fixtureRepo(t)
	base := snapshot(t, repo, "", map[string]string{"package.json": "{}"}, "")
	head := snapshot(t, repo, base, map[string]string{"package.json": ""}, "")
	r, err := Run(repo, base, head)
	if err != nil {
		t.Fatal(err)
	}
	if Decide(r, "test", io.Discard) != 2 {
		t.Fatalf("empty npm file passed: %+v", r)
	}
}

func TestWorktreeRetainsOpenedRoot(t *testing.T) {
	repo := fixtureRepo(t)
	base := snapshot(t, repo, "", map[string]string{"package-lock.json": oldLock}, "")
	writeWorktree(t, repo, "package-lock.json", oldLock)
	w := openWorktree(t, repo, base)
	if err := os.Rename(repo, filepath.Join(t.TempDir(), "original")); err != nil {
		t.Fatal(err)
	}
	writeWorktree(t, repo, "package-lock.json", "not a manifest")
	r := w.Check(context.Background())
	if Decide(r, "test", io.Discard) != 0 {
		t.Fatalf("read replacement root: %+v", r)
	}
}

func TestWorktreeCancellationReachesRegistries(t *testing.T) {
	for _, name := range []string{"package.json", "requirements.txt"} {
		t.Run(name, func(t *testing.T) {
			repo := fixtureRepo(t)
			old, next := "{}", `{"dependencies":{"a":"1.0.0"}}`
			if name == "requirements.txt" {
				old, next = "", "requests==2.32.0"
			}
			base := snapshot(t, repo, "", map[string]string{name: old}, "")
			w := openWorktree(t, repo, base)
			writeWorktree(t, repo, name, next)
			original := http.DefaultTransport
			t.Cleanup(func() { http.DefaultTransport = original })
			started := make(chan struct{}, 1)
			http.DefaultTransport = worktreeTransport(func(req *http.Request) (*http.Response, error) {
				started <- struct{}{}
				<-req.Context().Done()
				return nil, req.Context().Err()
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan *Report, 1)
			go func() { done <- w.Check(ctx) }()
			select {
			case <-started:
			case <-time.After(2 * time.Second):
				t.Fatal("registry request did not start")
			}
			cancel()
			select {
			case r := <-done:
				if Decide(r, "test", io.Discard) != 2 {
					t.Fatalf("canceled registry call passed: %+v", r)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("cancellation did not reach registry request")
			}
		})
	}
}
