package gate

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func fixtureGit(t *testing.T, repo, stdin string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
	cmd.Stdin = strings.NewReader(stdin)
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=Test", "GIT_AUTHOR_EMAIL=test@example.test", "GIT_COMMITTER_NAME=Test", "GIT_COMMITTER_EMAIL=test@example.test")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// Fixture commits are created as objects without checkout, hooks or user commits.
func snapshot(t *testing.T, repo, parent string, files map[string]string, symlink string) string {
	t.Helper()
	fixtureGit(t, repo, "", "read-tree", "--empty")
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		oid := fixtureGit(t, repo, files[name], "hash-object", "-w", "--stdin")
		mode := "100644"
		if name == symlink {
			mode = "120000"
		}
		fixtureGit(t, repo, "", "update-index", "--add", "--cacheinfo", mode, oid, name)
	}
	tree := fixtureGit(t, repo, "", "write-tree")
	args := []string{"commit-tree", tree}
	if parent != "" {
		args = append(args, "-p", parent)
	}
	return fixtureGit(t, repo, "fixture\n", args...)
}

func fixtureRepo(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	fixtureGit(t, repo, "", "init", "-q")
	return repo
}

func TestGateUsesBasePolicyAndImmutableInputs(t *testing.T) {
	repo := fixtureRepo(t)
	base := snapshot(t, repo, "", map[string]string{"requirements.txt": "requests==2.32.0\n", ".vigiles.yaml": "version: 1\npolicy:\n  fail-on: heuristic\n"}, "")
	head := snapshot(t, repo, base, map[string]string{"requirements.txt": "requests==2.32.0\n", ".vigiles.yaml": "version: 1\npolicy:\n  fail-on: none\n", "README.md": "changed"}, "")
	if err := os.WriteFile(filepath.Join(repo, ".vigiles.yaml"), []byte("invalid worktree config"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "requirements.txt"), []byte("-r ignored-worktree.txt"), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := Run(repo, base, head)
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "complete" || !r.PolicyChanged || r.Policy.Policy.FailOn != "heuristic" || r.Head != head || len(r.Inputs) != 1 || r.PolicySHA256 == "" {
		t.Fatalf("unexpected gate report: %+v", r)
	}
	if r.Inputs[0].BaseBlob == "" || r.Inputs[0].HeadBlob == "" {
		t.Fatal("report is not bound to blobs")
	}
}

func TestGateFindsNestedAndDeletedManifests(t *testing.T) {
	repo := fixtureRepo(t)
	base := snapshot(t, repo, "", map[string]string{"old/requirements.txt": "requests==2.32.0\n"}, "")
	head := snapshot(t, repo, base, map[string]string{"new/package.json": "{}"}, "")
	r, err := Run(repo, base, head)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Inputs) != 2 || r.Status != "complete" {
		t.Fatalf("missed manifests: %+v", r)
	}
}

func TestGateRejectsMissingCoverage(t *testing.T) {
	for _, tc := range []struct {
		name    string
		files   map[string]string
		symlink string
	}{
		{"includes", map[string]string{"requirements.txt": "-r hidden.txt\n", "hidden.txt": "requests==2.32.0\n"}, ""},
		{"symlink", map[string]string{"requirements.txt": "hidden.txt"}, "requirements.txt"},
		{"unsupported", map[string]string{"requirements.txt": "", "go.mod": "module example.test/demo\n"}, ""},
		{"ambiguous json", map[string]string{"package.json": `{"dependencies":{},"dependencies":{}}`}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := fixtureRepo(t)
			base := snapshot(t, repo, "", map[string]string{"requirements.txt": ""}, "")
			head := snapshot(t, repo, base, tc.files, tc.symlink)
			r, err := Run(repo, base, head)
			if err != nil {
				t.Fatal(err)
			}
			if r.Status != "incomplete" || len(r.Incomplete) == 0 {
				t.Fatalf("coverage gap passed: %+v", r)
			}
		})
	}
}

func TestGateSupportsUVLock(t *testing.T) {
	repo := fixtureRepo(t)
	lock := `version = 1
revision = 3

[[package]]
name = "demo"
version = "0.1.0"
source = { editable = "." }

[[package]]
name = "requests"
version = "2.32.0"
source = { registry = "https://pypi.org/simple" }
`
	base := snapshot(t, repo, "", map[string]string{"uv.lock": lock}, "")
	head := snapshot(t, repo, base, map[string]string{"uv.lock": lock, "README.md": "changed"}, "")
	r, err := Run(repo, base, head)
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "complete" || len(r.Inputs) != 1 || r.Inputs[0].Path != "uv.lock" {
		t.Fatalf("uv.lock was not covered: %+v", r)
	}
}

func TestGateRejectsAbsentManifestsAndMutableRefs(t *testing.T) {
	repo := fixtureRepo(t)
	base := snapshot(t, repo, "", map[string]string{"README.md": "a"}, "")
	head := snapshot(t, repo, base, map[string]string{"README.md": "b"}, "")
	r, err := Run(repo, base, head)
	if err != nil || r.Status != "incomplete" {
		t.Fatalf("empty scan passed: %+v %v", r, err)
	}
	for _, refs := range [][2]string{{"main", head}, {base, "HEAD"}, {base, base}, {"--help", head}} {
		if _, err := Run(repo, refs[0], refs[1]); err == nil {
			t.Fatalf("accepted refs: %v", refs)
		}
	}
}

func TestGateDoesNotFollowGitReplacements(t *testing.T) {
	repo := fixtureRepo(t)
	base := snapshot(t, repo, "", map[string]string{"requirements.txt": ""}, "")
	head := snapshot(t, repo, base, map[string]string{"requirements.txt": "-r hidden.txt"}, "")
	clean := snapshot(t, repo, base, map[string]string{"requirements.txt": "# empty"}, "")
	fixtureGit(t, repo, "", "replace", head, clean)
	r, err := Run(repo, base, head)
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "incomplete" {
		t.Fatalf("replacement hid unsupported input: %+v", r)
	}
}

func TestInputSizeLimit(t *testing.T) {
	var b limitedBuffer
	if _, err := b.Write(bytes.Repeat([]byte("x"), 8*1024*1024+1)); err == nil {
		t.Fatal("oversized input accepted")
	}
}
