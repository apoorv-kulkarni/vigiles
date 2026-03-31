// Package diff compares two dependency manifests and produces a structured
// list of added, removed, and updated packages.
package diff

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/apoorv-kulkarni/vigiles/internal/checker"
	"github.com/apoorv-kulkarni/vigiles/internal/signal"
)

// Status describes what changed for a dependency.
type Status string

const (
	Added   Status = "added"
	Removed Status = "removed"
	Updated Status = "updated"
)

// Entry represents a single dependency change.
type Entry struct {
	Name       string          `json:"name"`
	Ecosystem  string          `json:"ecosystem"`
	Status     Status          `json:"status"`
	OldVersion string          `json:"old_version,omitempty"`
	NewVersion string          `json:"new_version,omitempty"`
	Signals    []signal.Signal `json:"signals,omitempty"`
}

// Result is the full diff output.
type Result struct {
	OldFile   string  `json:"old_file"`
	NewFile   string  `json:"new_file"`
	Ecosystem string  `json:"ecosystem"`
	Entries   []Entry `json:"entries"`
}

// dep is an internal representation of a parsed dependency.
type dep struct {
	name    string
	version string // exact version or specifier
}

// recencyVersionChecker is a small seam to make diff tests deterministic.
type recencyVersionChecker interface {
	CheckVersion(name, version, ecosystem string) *signal.Signal
}

var newRecencyChecker = func() recencyVersionChecker {
	return checker.NewRecencyChecker()
}

// Run compares two dependency files and returns a diff result.
func Run(oldPath, newPath string) (*Result, error) {
	oldDeps, eco1, err := parseFile(oldPath)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", oldPath, err)
	}

	newDeps, eco2, err := parseFile(newPath)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", newPath, err)
	}

	if eco1 != eco2 {
		return nil, fmt.Errorf("file types don't match: %s (%s) vs %s (%s)", oldPath, eco1, newPath, eco2)
	}

	entries := computeDiff(oldDeps, newDeps, eco1)

	return &Result{
		OldFile:   oldPath,
		NewFile:   newPath,
		Ecosystem: eco1,
		Entries:   entries,
	}, nil
}

func computeDiff(oldDeps, newDeps map[string]string, ecosystem string) []Entry {
	var entries []Entry
	recency := newRecencyChecker()

	// Check for added and updated
	for name, newVer := range newDeps {
		oldVer, existed := oldDeps[name]
		if !existed {
			e := Entry{
				Name: name, Ecosystem: ecosystem,
				Status: Added, NewVersion: newVer,
			}
			e.Signals = annotate(name, newVer, ecosystem, true, recency)
			entries = append(entries, e)
		} else if oldVer != newVer {
			e := Entry{
				Name: name, Ecosystem: ecosystem,
				Status: Updated, OldVersion: oldVer, NewVersion: newVer,
			}
			e.Signals = annotate(name, newVer, ecosystem, false, recency)
			entries = append(entries, e)
		}
	}

	// Check for removed
	for name, oldVer := range oldDeps {
		if _, exists := newDeps[name]; !exists {
			entries = append(entries, Entry{
				Name: name, Ecosystem: ecosystem,
				Status: Removed, OldVersion: oldVer,
			})
		}
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Status != entries[j].Status {
			return statusOrder(entries[i].Status) < statusOrder(entries[j].Status)
		}
		return entries[i].Name < entries[j].Name
	})

	return entries
}

func statusOrder(s Status) int {
	switch s {
	case Added:
		return 0
	case Updated:
		return 1
	case Removed:
		return 2
	default:
		return 3
	}
}

// annotate runs applicable risk signals on a changed dependency.
func annotate(name, version, ecosystem string, isNew bool, recency recencyVersionChecker) []signal.Signal {
	var signals []signal.Signal

	// New dependency in the new graph vs old graph.
	if isNew {
		signals = append(signals, signal.Signal{
			Package: name, Version: version, Ecosystem: ecosystem,
			Type: "trust-signal", Severity: "info",
			ID:      "VIGILES-NEW-DEPENDENCY",
			Summary: "New dependency introduced",
			Details: "This package is present in the new dependency graph but not in the previous baseline.",
		})
	}

	// Check for unpinned version
	if sig := checker.CheckUnpinned(name, version, ecosystem); sig != nil {
		signals = append(signals, *sig)
	}

	// Typosquatting check
	var popular []string
	switch ecosystem {
	case "pip":
		popular = checker.PopularPipPackages()
	case "npm":
		popular = checker.PopularNpmPackages()
	}
	if len(popular) > 0 {
		if typo := checker.CheckTyposquatExported(name, popular); typo != "" {
			signals = append(signals, signal.Signal{
				Package: name, Version: version, Ecosystem: ecosystem,
				Type: "heuristic", Severity: "high", ID: "VIGILES-TYPOSQUAT",
				Summary: fmt.Sprintf("Possible typosquat of '%s'", typo),
				Details: "New dependency name is within edit distance 1 of a popular package.",
			})
		}
	}

	// Recency check for newly added, exactly pinned pip versions.
	if isNew && recency != nil {
		if normalized, ok := normalizeVersionForRecency(version, ecosystem); ok {
			if recent := recency.CheckVersion(name, normalized, ecosystem); recent != nil {
				signals = append(signals, *recent)
			}
		}
	}

	return signals
}

func normalizeVersionForRecency(version, ecosystem string) (string, bool) {
	if ecosystem != "pip" {
		return "", false
	}
	v := strings.TrimSpace(version)
	switch {
	case strings.HasPrefix(v, "==="):
		v = strings.TrimSpace(v[3:])
	case strings.HasPrefix(v, "=="):
		v = strings.TrimSpace(v[2:])
	default:
		// For pip, only exact pins should hit recency lookup.
		return "", false
	}
	if v == "" {
		return "", false
	}
	return v, true
}

// --- File parsing ---

func parseFile(path string) (map[string]string, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}

	base := strings.ToLower(filepath.Base(path))

	switch {
	case base == "package.json" || base == "package-lock.json":
		deps, err := parsePackageJSON(data)
		return deps, "npm", err
	case base == "requirements.txt" || strings.HasSuffix(base, ".txt"):
		deps := parseRequirementsTxt(string(data))
		return deps, "pip", nil
	default:
		// Try to auto-detect from content
		if json.Valid(data) {
			deps, err := parsePackageJSON(data)
			if err == nil && len(deps) > 0 {
				return deps, "npm", nil
			}
		}
		deps := parseRequirementsTxt(string(data))
		if len(deps) > 0 {
			return deps, "pip", nil
		}
		return nil, "", fmt.Errorf("cannot determine file type for %s", path)
	}
}

// parseRequirementsTxt parses a pip requirements.txt file.
// Returns a map of package_name → version_specifier.
func parseRequirementsTxt(content string) map[string]string {
	deps := map[string]string{}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		// Remove inline comments
		if idx := strings.Index(line, " #"); idx >= 0 {
			line = line[:idx]
		}
		// Remove environment markers (e.g., ; python_version >= "3.8")
		if idx := strings.Index(line, ";"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		// Remove extras (e.g., requests[security])
		if idx := strings.Index(line, "["); idx >= 0 {
			end := strings.Index(line, "]")
			if end > idx {
				line = line[:idx] + line[end+1:]
			}
		}

		name, version := splitRequirement(line)
		if name != "" {
			deps[strings.ToLower(name)] = version
		}
	}
	return deps
}

// splitRequirement splits "requests==2.31.0" into ("requests", "==2.31.0").
func splitRequirement(line string) (string, string) {
	for _, op := range []string{"===", "~=", "==", "!=", ">=", "<=", ">", "<"} {
		if idx := strings.Index(line, op); idx >= 0 {
			return strings.TrimSpace(line[:idx]), strings.TrimSpace(line[idx:])
		}
	}
	// No operator — just a package name with no version constraint
	return strings.TrimSpace(line), ""
}

// parsePackageJSON parses a package.json or package-lock.json file.
func parsePackageJSON(data []byte) (map[string]string, error) {
	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
		// package-lock.json format
		Packages map[string]struct {
			Version string `json:"version"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, err
	}

	deps := map[string]string{}
	for name, ver := range pkg.Dependencies {
		deps[name] = ver
	}
	for name, ver := range pkg.DevDependencies {
		deps[name] = ver
	}
	// package-lock.json has packages with full paths; extract names
	for path, info := range pkg.Packages {
		if path == "" {
			continue // root package
		}
		name := path
		if idx := strings.LastIndex(path, "node_modules/"); idx >= 0 {
			name = path[idx+len("node_modules/"):]
		}
		if info.Version != "" {
			deps[name] = info.Version
		}
	}

	return deps, nil
}

// ParseRequirementsTxt is exported for testing.
func ParseRequirementsTxt(content string) map[string]string {
	return parseRequirementsTxt(content)
}
