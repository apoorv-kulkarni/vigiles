package gate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/apoorv-kulkarni/vigiles/internal/config"
	"github.com/apoorv-kulkarni/vigiles/internal/diff"
	"github.com/apoorv-kulkarni/vigiles/internal/signal"
)

const (
	maxManifestBytes = 2 << 20
	maxSnapshotBytes = 16 << 20
	maxManifests     = 1000
	maxWalkEntries   = 100000
)

type manifest struct {
	Data []byte
	Blob string
}

// Workspace retains the startup baseline and a handle to the configured root.
// Calls cannot select a different repository, policy or baseline.
type Workspace struct {
	root   *os.Root
	base   string
	files  map[string]manifest
	policy *config.Config
}

func OpenWorkspace(repo, base string) (*Workspace, error) {
	if !commitID.MatchString(base) {
		return nil, fmt.Errorf("base must be a full commit ID")
	}
	abs, err := filepath.Abs(repo)
	if err != nil {
		return nil, err
	}
	abs, err = filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, err
	}
	top, err := git(abs, "rev-parse", "--show-toplevel")
	if err != nil || strings.TrimSpace(string(top)) != abs {
		return nil, fmt.Errorf("repo must be the Git working-tree root")
	}
	tree, err := readTree(abs, base)
	if err != nil {
		return nil, err
	}
	w := &Workspace{base: base, files: map[string]manifest{}}
	total := 0
	for name, b := range tree {
		if b.kind == "commit" {
			return nil, fmt.Errorf("base contains an unsupported submodule")
		}
		if !selected(name) {
			continue
		}
		data, err := readBlob(abs, b)
		if err != nil {
			return nil, fmt.Errorf("base manifest %q: %w", name, err)
		}
		total += len(data)
		if len(data) > maxManifestBytes || total > maxSnapshotBytes || len(w.files) >= maxManifests {
			return nil, fmt.Errorf("base exceeds snapshot limits")
		}
		w.files[name] = manifest{Data: data, Blob: b.oid}
	}
	w.policy, err = config.Parse(w.files[config.DefaultFile].Data)
	if err != nil {
		return nil, fmt.Errorf("base policy: %w", err)
	}
	if _, err := config.ParseFailOn(w.policy.Policy.FailOn); err != nil {
		return nil, fmt.Errorf("base policy: %w", err)
	}
	w.root, err = os.OpenRoot(abs)
	if err != nil {
		return nil, err
	}
	return w, nil
}

func (w *Workspace) Close() error { return w.root.Close() }

// Check snapshots files before metadata checks, then detects changes during them.
// The result describes those bytes; it is not an authorization for future edits.
func (w *Workspace) Check(ctx context.Context) *Report {
	r := &Report{Status: "incomplete", Scope: "worktree dependency-diff; no CVE scan or execution authorization",
		Base: w.base, Candidate: "worktree", Policy: w.policy,
		PolicySHA256: digest(w.files[config.DefaultFile].Data),
		Inputs:       []Input{}, Signals: []signal.Signal{}, Incomplete: []string{}}
	next, err := w.capture(ctx)
	if err != nil {
		r.Incomplete = append(r.Incomplete, "cannot snapshot worktree: "+err.Error())
		return r
	}
	r.SnapshotSHA256 = snapshotDigest(next)
	oldPolicy, oldExists := w.files[config.DefaultFile]
	newPolicy, newExists := next[config.DefaultFile]
	r.PolicyChanged = oldExists != newExists || !bytes.Equal(oldPolicy.Data, newPolicy.Data)
	paths := map[string]bool{}
	for name := range w.files {
		paths[name] = true
	}
	for name := range next {
		paths[name] = true
	}
	names := make([]string, 0, len(paths))
	for name := range paths {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			r.Incomplete = append(r.Incomplete, err.Error())
			return r
		}
		old, hadOld := w.files[name]
		current, hasNew := next[name]
		if !supportedManifest(name) {
			if unsupportedManifest(name) && (hadOld != hasNew || !bytes.Equal(old.Data, current.Data)) {
				r.Incomplete = append(r.Incomplete, fmt.Sprintf("changed unsupported manifest %q", name))
			}
			continue
		}
		comparison := diff.CompareStrictContext(ctx, path.Base(name), old.Data, current.Data)
		r.Inputs = append(r.Inputs, Input{Path: name, BaseBlob: old.Blob, Diff: comparison})
		for _, problem := range comparison.Incomplete {
			r.Incomplete = append(r.Incomplete, fmt.Sprintf("%q: %s", name, problem))
		}
		for _, entry := range comparison.Entries {
			r.Signals = append(r.Signals, entry.Signals...)
		}
	}
	if len(r.Inputs) == 0 {
		r.Incomplete = append(r.Incomplete, "no supported manifests found")
	}
	after, err := w.capture(ctx)
	if err != nil || snapshotDigest(after) != r.SnapshotSHA256 {
		r.Incomplete = append(r.Incomplete, "worktree changed or became unreadable during the check; retry")
	}
	return r
}

func selected(name string) bool {
	return name == config.DefaultFile || supportedManifest(name) || unsupportedManifest(name)
}

func (w *Workspace) capture(ctx context.Context) (map[string]manifest, error) {
	files := map[string]manifest{}
	entries, total := 0, 0
	err := w.walk(ctx, func(name string, d fs.DirEntry) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if name == ".git" {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if path.Base(name) == ".git" {
			return fmt.Errorf("nested Git repository %q is outside coverage", path.Dir(name))
		}
		entries++
		if entries > maxWalkEntries {
			return fmt.Errorf("worktree exceeds %d entries", maxWalkEntries)
		}
		// A symlink could hide a directory of manifests, even with an unrelated name.
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink %q is outside worktree coverage", name)
		}
		if !selected(name) {
			return nil
		}
		info, err := w.root.Lstat(name)
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("manifest %q is not a readable regular file", name)
		}
		if len(files) >= maxManifests || info.Size() > maxManifestBytes {
			return fmt.Errorf("worktree exceeds manifest limits")
		}
		f, err := openManifest(w.root, name)
		if err != nil {
			return fmt.Errorf("cannot open manifest %q: %w", name, err)
		}
		defer f.Close()
		opened, err := f.Stat()
		if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
			return fmt.Errorf("manifest %q changed while opening", name)
		}
		data, err := io.ReadAll(io.LimitReader(f, maxManifestBytes+1))
		if err != nil || len(data) > maxManifestBytes {
			return fmt.Errorf("manifest %q cannot be read within limits", name)
		}
		total += len(data)
		if total > maxSnapshotBytes {
			return fmt.Errorf("worktree exceeds snapshot byte limit")
		}
		files[name] = manifest{Data: data}
		return nil
	})
	return files, err
}

// Read directories in batches so the entry limit also bounds directory-list memory.
func (w *Workspace) walk(ctx context.Context, visit func(string, fs.DirEntry) error) error {
	dirs := []string{"."}
	for len(dirs) > 0 {
		dir := dirs[len(dirs)-1]
		dirs = dirs[:len(dirs)-1]
		err := func() error {
			f, err := openManifest(w.root, dir)
			if err != nil {
				return err
			}
			defer f.Close()
			for {
				if err := ctx.Err(); err != nil {
					return err
				}
				batch, err := f.ReadDir(128)
				if err != nil && err != io.EOF {
					return err
				}
				for _, d := range batch {
					name := path.Join(dir, d.Name())
					if err := visit(name, d); err != nil {
						if err == fs.SkipDir && d.IsDir() {
							continue
						}
						return err
					}
					if d.IsDir() {
						dirs = append(dirs, name)
					}
				}
				if err == io.EOF {
					return nil
				}
			}
		}()
		if err != nil {
			return err
		}
	}
	return nil
}

func digest(data []byte) string { return fmt.Sprintf("%x", sha256.Sum256(data)) }

func snapshotDigest(files map[string]manifest) string {
	hashes := map[string]string{}
	for name, f := range files {
		hashes[name] = digest(f.Data)
	}
	// encoding/json sorts string map keys and escapes names unambiguously.
	data, _ := json.Marshal(hashes)
	return digest(data)
}
