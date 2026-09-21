// Package gate audits immutable Git inputs using policy from the base commit.
package gate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/apoorv-kulkarni/vigiles/internal/config"
	"github.com/apoorv-kulkarni/vigiles/internal/diff"
	"github.com/apoorv-kulkarni/vigiles/internal/signal"
)

type Report struct {
	Version        string          `json:"version"`
	Status         string          `json:"status"`
	Scope          string          `json:"scope"`
	Base           string          `json:"base_commit"`
	Head           string          `json:"head_commit"`
	Candidate      string          `json:"candidate,omitempty"`
	SnapshotSHA256 string          `json:"snapshot_sha256,omitempty"`
	PolicySHA256   string          `json:"policy_sha256"`
	PolicyChanged  bool            `json:"policy_changed"`
	Inputs         []Input         `json:"inputs"`
	Signals        []signal.Signal `json:"signals"`
	Incomplete     []string        `json:"incomplete"`
	Policy         *config.Config  `json:"-"`
}

type Input struct {
	Path     string             `json:"path"`
	BaseBlob string             `json:"base_blob,omitempty"`
	HeadBlob string             `json:"head_blob,omitempty"`
	Diff     *diff.StrictResult `json:"diff,omitempty"`
}

type blob struct{ mode, kind, oid string }

var commitID = regexp.MustCompile(`^([a-f0-9]{40}|[a-f0-9]{64})$`)

// Run accepts full commit IDs, never caller-selected file lists or worktree policy.
func Run(repo, base, head string) (*Report, error) {
	if !commitID.MatchString(base) || !commitID.MatchString(head) || base == head {
		return nil, fmt.Errorf("base and head must be distinct full commit IDs")
	}
	r := &Report{Status: "incomplete", Scope: "dependency-diff (npm lifecycle/publisher, pip new-release recency, pinning, typosquats; no CVE scan)",
		Base: base, Head: head, Inputs: []Input{}, Signals: []signal.Signal{}, Incomplete: []string{}}
	oldTree, err := readTree(repo, base)
	if err != nil {
		return nil, err
	}
	newTree, err := readTree(repo, head)
	if err != nil {
		return nil, err
	}
	policy, err := readBlob(repo, oldTree[config.DefaultFile])
	if err != nil {
		return nil, fmt.Errorf("base policy: %w", err)
	}
	r.Policy, err = config.Parse(policy)
	if err != nil {
		return nil, fmt.Errorf("base policy: %w", err)
	}
	r.PolicySHA256 = fmt.Sprintf("%x", sha256.Sum256(policy))
	r.PolicyChanged = oldTree[config.DefaultFile] != newTree[config.DefaultFile]
	paths := map[string]bool{}
	for name := range oldTree {
		paths[name] = true
	}
	for name := range newTree {
		paths[name] = true
	}
	names := make([]string, 0, len(paths))
	for name := range paths {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		old, next := oldTree[name], newTree[name]
		if old.kind == "commit" || next.kind == "commit" {
			r.Incomplete = append(r.Incomplete, fmt.Sprintf("submodule %q is outside gate coverage", name))
			continue
		}
		if !supportedManifest(name) {
			if old != next && unsupportedManifest(name) {
				r.Incomplete = append(r.Incomplete, fmt.Sprintf("changed unsupported manifest %q", name))
			}
			continue
		}
		input := Input{Path: name, BaseBlob: old.oid, HeadBlob: next.oid}
		oldData, oldErr := readBlob(repo, old)
		newData, newErr := readBlob(repo, next)
		if oldErr != nil || newErr != nil {
			r.Incomplete = append(r.Incomplete, fmt.Sprintf("cannot read regular manifest %q (base: %v; head: %v)", name, oldErr, newErr))
		} else {
			input.Diff = diff.CompareStrict(path.Base(name), oldData, newData)
			for _, problem := range input.Diff.Incomplete {
				r.Incomplete = append(r.Incomplete, fmt.Sprintf("%q: %s", name, problem))
			}
			for _, entry := range input.Diff.Entries {
				r.Signals = append(r.Signals, entry.Signals...)
			}
		}
		r.Inputs = append(r.Inputs, input)
	}
	if len(r.Inputs) == 0 {
		r.Incomplete = append(r.Incomplete, "no supported manifests found in either commit")
	}
	if len(r.Incomplete) == 0 {
		r.Status = "complete"
	}
	return r, nil
}

func supportedManifest(name string) bool {
	base := strings.ToLower(path.Base(name))
	return base == "package.json" || base == "package-lock.json" || base == "uv.lock" || base == "constraints.txt" ||
		base == "requirements.txt" || (strings.HasSuffix(base, ".txt") &&
		(strings.HasPrefix(base, "requirements-") || strings.HasPrefix(base, "requirements_")))
}

func unsupportedManifest(name string) bool {
	switch strings.ToLower(path.Base(name)) {
	case "pyproject.toml", "setup.py", "setup.cfg", "pipfile", "pipfile.lock", "poetry.lock",
		"yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb", "npm-shrinkwrap.json", "go.mod", "go.sum",
		"cargo.toml", "cargo.lock", "gemfile", "gemfile.lock", "composer.json", "composer.lock",
		".mcp.json", "mcp.json":
		return true
	}
	return false
}

func readTree(repo, commit string) (map[string]blob, error) {
	kind, err := git(repo, "cat-file", "-t", commit)
	if err != nil || strings.TrimSpace(string(kind)) != "commit" {
		return nil, fmt.Errorf("%s is not an available commit", commit)
	}
	data, err := git(repo, "ls-tree", "-r", "-z", "--full-tree", commit)
	if err != nil {
		return nil, err
	}
	result := map[string]blob{}
	for _, record := range bytes.Split(data, []byte{0}) {
		if len(record) == 0 {
			continue
		}
		parts := bytes.SplitN(record, []byte{'\t'}, 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid Git tree record")
		}
		fields := strings.Fields(string(parts[0]))
		if len(fields) != 3 {
			return nil, fmt.Errorf("invalid Git tree metadata")
		}
		result[string(parts[1])] = blob{fields[0], fields[1], fields[2]}
	}
	return result, nil
}

func readBlob(repo string, b blob) ([]byte, error) {
	if b.oid == "" {
		return nil, nil
	}
	if b.kind != "blob" || (b.mode != "100644" && b.mode != "100755") {
		return nil, fmt.Errorf("symlinks and non-regular files are not supported")
	}
	data, err := git(repo, "cat-file", "blob", b.oid)
	// A present empty file must not be mistaken for an absent manifest.
	if err == nil && data == nil {
		data = []byte{}
	}
	return data, err
}

// Git object reads do not run checkout filters, hooks, package managers or PR scripts.
func git(repo string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", append([]string{"--no-replace-objects", "-c", "core.fsmonitor=false", "-C", repo}, args...)...)
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "GIT_") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	cmd.Env = append(cmd.Env, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_NO_LAZY_FETCH=1")
	var stdout limitedBuffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("Git object read failed: %w", err)
	}
	return stdout.Bytes(), nil
}

type limitedBuffer struct{ data bytes.Buffer }

func (b *limitedBuffer) Bytes() []byte { return b.data.Bytes() }

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.data.Len()+len(p) > 8*1024*1024 {
		return 0, fmt.Errorf("Git input exceeds 8 MiB")
	}
	return b.data.Write(p)
}
