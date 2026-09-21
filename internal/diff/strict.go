package diff

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/apoorv-kulkarni/vigiles/internal/checker"
	"github.com/apoorv-kulkarni/vigiles/internal/signal"
)

// StrictResult records coverage separately from suppressible findings.
type StrictResult struct {
	Result
	Complete   bool     `json:"complete"`
	Incomplete []string `json:"incomplete"`
	OldSHA256  string   `json:"old_sha256"`
	NewSHA256  string   `json:"new_sha256"`
}

// RunStrict checks file snapshots and reports unsupported syntax or unavailable checks.
func RunStrict(oldPath, newPath string) (*StrictResult, error) {
	oldData, err := os.ReadFile(oldPath)
	if err != nil {
		return nil, err
	}
	newData, err := os.ReadFile(newPath)
	if err != nil {
		return nil, err
	}
	result := CompareStrict(filepath.Base(newPath), oldData, newData)
	result.OldFile, result.NewFile = oldPath, newPath
	return result, nil
}

// CompareStrict treats nil content as an absent file. Neither input is executed.
// Its scope is dependency changes, not a full vulnerability or source-code audit.
func CompareStrict(name string, oldData, newData []byte) *StrictResult {
	return CompareStrictContext(context.Background(), name, oldData, newData)
}

// CompareStrictContext propagates cancellation through external metadata reads.
func CompareStrictContext(ctx context.Context, name string, oldData, newData []byte) *StrictResult {
	r := &StrictResult{Result: Result{OldFile: name, NewFile: name, Entries: []Entry{}},
		Incomplete: []string{}, OldSHA256: fmt.Sprintf("%x", sha256.Sum256(oldData)),
		NewSHA256: fmt.Sprintf("%x", sha256.Sum256(newData))}
	oldDeps, eco, err := parseStrict(name, oldData)
	if err != nil {
		r.Incomplete = append(r.Incomplete, "base: "+err.Error())
	}
	newDeps, _, err := parseStrict(name, newData)
	if err != nil {
		r.Incomplete = append(r.Incomplete, "head: "+err.Error())
	}
	r.Ecosystem = eco
	if len(r.Incomplete) > 0 {
		return r
	}
	npm := &npmRegistryRiskChecker{client: &http.Client{Timeout: 4 * time.Second}, ctx: ctx}
	recency := &strictRecency{checker: checker.NewRecencyChecker(), ctx: ctx}
	r.Entries = computeDiffWith(oldDeps, newDeps, eco, recency, npm)
	if strings.EqualFold(filepath.Base(name), "package-lock.json") {
		r.Entries = append(r.Entries, artifactChanges(oldData, newData)...)
	}
	if r.Entries == nil {
		r.Entries = []Entry{}
	}
	r.Incomplete = append(r.Incomplete, npm.incomplete...)
	r.Incomplete = append(r.Incomplete, recency.incomplete...)
	for _, e := range r.Entries {
		if e.Status == Removed {
			continue
		}
		if eco == "pip" {
			if _, ok := normalizeVersionForRecency(e.NewVersion, eco); !ok {
				r.Incomplete = append(r.Incomplete, fmt.Sprintf("pip: %s does not have an exact version", e.Name))
			}
		}
	}
	sort.Strings(r.Incomplete)
	r.Complete = len(r.Incomplete) == 0
	return r
}

type strictRecency struct {
	checker    *checker.RecencyChecker
	ctx        context.Context
	incomplete []string
}

func (c *strictRecency) CheckVersion(name, version, ecosystem string) *signal.Signal {
	if ecosystem != "pip" {
		return nil
	}
	sig, err := c.checker.CheckVersionContext(c.ctx, name, version)
	if err != nil {
		c.incomplete = append(c.incomplete, fmt.Sprintf("PyPI recency unavailable for %s@%s", name, version))
	}
	return sig
}

var requirementSyntax = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*(\[[A-Za-z0-9_,.-]+\])?\s*((===|==|~=|!=|>=|<=|>|<)[A-Za-z0-9.*+!_-]+(\s*,\s*(===|==|~=|!=|>=|<=|>|<)[A-Za-z0-9.*+!_-]+)*)?$`)
var requirementNameSeparators = regexp.MustCompile(`[-_.]+`)

func parseStrict(name string, data []byte) (map[string]string, string, error) {
	base := strings.ToLower(filepath.Base(name))
	eco := "pip"
	if base == "package.json" || base == "package-lock.json" {
		eco = "npm"
	}
	if data == nil {
		return map[string]string{}, eco, nil
	}
	if eco == "npm" {
		deps, err := parseStrictNPM(base, data)
		return deps, eco, err
	}
	deps := map[string]string{}
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if idx := strings.Index(line, " #"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if !requirementSyntax.MatchString(line) {
			return nil, eco, fmt.Errorf("line %d: unsupported requirement syntax (includes, options, URLs and markers require review)", i+1)
		}
		for pkg, version := range parseRequirementsTxt(line) {
			canonical := requirementNameSeparators.ReplaceAllString(pkg, "-")
			if _, exists := deps[canonical]; exists {
				return nil, eco, fmt.Errorf("line %d: duplicate requirement %s", i+1, canonical)
			}
			deps[canonical] = version
		}
	}
	return deps, eco, nil
}

func parseStrictNPM(name string, data []byte) (map[string]string, error) {
	// Duplicate JSON keys are ambiguous across parsers and must not hide dependencies.
	if err := rejectDuplicateKeys(json.NewDecoder(strings.NewReader(string(data)))); err != nil {
		return nil, err
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err != nil || obj == nil {
		return nil, fmt.Errorf("expected a JSON object")
	}
	deps := map[string]string{}
	add := func(pkg, version string) error {
		if pkg == "" || version == "" {
			return fmt.Errorf("dependency without name or version")
		}
		if prior, ok := deps[pkg]; ok && prior != version {
			return fmt.Errorf("multiple versions of %s cannot be compared without losing coverage", pkg)
		}
		deps[pkg] = version
		return nil
	}
	if name == "package.json" {
		for _, field := range []string{"dependencies", "devDependencies", "optionalDependencies", "peerDependencies"} {
			var section map[string]string
			if raw, ok := obj[field]; ok {
				if err := json.Unmarshal(raw, &section); err != nil || section == nil {
					return nil, fmt.Errorf("invalid %s", field)
				}
				for pkg, version := range section {
					if err := add(pkg, version); err != nil {
						return nil, err
					}
				}
			}
		}
		for _, field := range []string{"overrides", "resolutions", "bundledDependencies", "bundleDependencies"} {
			if _, ok := obj[field]; ok {
				return nil, fmt.Errorf("%s is not supported by strict comparison", field)
			}
		}
		return deps, nil
	}
	var version int
	if err := json.Unmarshal(obj["lockfileVersion"], &version); err != nil || (version != 2 && version != 3) {
		return nil, fmt.Errorf("only npm lockfile versions 2 and 3 are supported")
	}
	var packages map[string]struct {
		Version  string `json:"version"`
		Link     bool   `json:"link"`
		Resolved string `json:"resolved"`
	}
	if err := json.Unmarshal(obj["packages"], &packages); err != nil || packages == nil {
		return nil, fmt.Errorf("missing or invalid lockfile packages")
	}
	for path, pkg := range packages {
		if path == "" {
			continue
		}
		if pkg.Link {
			return nil, fmt.Errorf("linked packages are not supported by strict comparison")
		}
		if pkg.Resolved != "" {
			u, err := url.Parse(pkg.Resolved)
			if err != nil || u.Scheme != "https" || u.Host != "registry.npmjs.org" || u.User != nil {
				return nil, fmt.Errorf("non-public-registry artifact sources are not covered by npm metadata checks")
			}
		}
		idx := strings.LastIndex(path, "node_modules/")
		if idx < 0 {
			return nil, fmt.Errorf("unsupported lockfile package path")
		}
		if err := add(path[idx+len("node_modules/"):], pkg.Version); err != nil {
			return nil, err
		}
	}
	return deps, nil
}

func artifactChanges(oldData, newData []byte) []Entry {
	type artifact struct {
		Version   string `json:"version"`
		Resolved  string `json:"resolved"`
		Integrity string `json:"integrity"`
	}
	var old, next struct {
		Packages map[string]artifact `json:"packages"`
	}
	if oldData == nil || newData == nil {
		return nil
	}
	if err := json.Unmarshal(oldData, &old); err != nil {
		return nil
	}
	if err := json.Unmarshal(newData, &next); err != nil {
		return nil
	}
	var entries []Entry
	for path, current := range next.Packages {
		previous, exists := old.Packages[path]
		if !exists || path == "" || previous.Version != current.Version || previous == current {
			continue
		}
		entries = append(entries, Entry{Name: path, Ecosystem: "npm", Status: Updated,
			OldVersion: previous.Version, NewVersion: current.Version,
			Signals: []signal.Signal{{Package: path, Version: current.Version, Ecosystem: "npm", Type: "heuristic", Severity: "medium",
				ID: "VIGILES-NPM-ARTIFACT-CHANGE", Summary: "Artifact location or integrity changed without a version change",
				Details:     "The lockfile selects different artifact metadata for the same package version.",
				Remediation: "Review the artifact source and integrity change independently before accepting the lockfile."}}})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	return entries
}

func rejectDuplicateKeys(dec *json.Decoder) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	seen := map[string]bool{}
	for dec.More() {
		if delim == '{' {
			key, err := dec.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return fmt.Errorf("duplicate or invalid JSON key")
			}
			seen[name] = true
		}
		if err := rejectDuplicateKeys(dec); err != nil {
			return err
		}
	}
	_, err = dec.Token()
	return err
}
