// Package diff compares two dependency manifests and produces a structured
// list of added, removed, and updated packages.
package diff

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

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

type npmRiskChecker interface {
	CheckNewPackage(name, version string) []signal.Signal
	CheckVersionChange(name, oldVersion, newVersion string) []signal.Signal
}

var newNpmRiskChecker = func() npmRiskChecker {
	return &npmRegistryRiskChecker{
		client: &http.Client{Timeout: 4 * time.Second},
	}
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
	npmRisk := newNpmRiskChecker()

	// Check for added and updated
	for name, newVer := range newDeps {
		oldVer, existed := oldDeps[name]
		if !existed {
			e := Entry{
				Name: name, Ecosystem: ecosystem,
				Status: Added, NewVersion: newVer,
			}
			e.Signals = annotate(name, "", newVer, ecosystem, true, recency, npmRisk)
			entries = append(entries, e)
		} else if oldVer != newVer {
			e := Entry{
				Name: name, Ecosystem: ecosystem,
				Status: Updated, OldVersion: oldVer, NewVersion: newVer,
			}
			e.Signals = annotate(name, oldVer, newVer, ecosystem, false, recency, npmRisk)
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
// oldVersion is empty when the dependency is newly added.
func annotate(name, oldVersion, version, ecosystem string, isNew bool, recency recencyVersionChecker, npmRisk npmRiskChecker) []signal.Signal {
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
	if ecosystem == "npm" && npmRisk != nil {
		if isNew {
			signals = append(signals, npmRisk.CheckNewPackage(name, version)...)
		} else {
			signals = append(signals, npmRisk.CheckVersionChange(name, oldVersion, version)...)
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

type npmRegistryRiskChecker struct {
	client *http.Client
}

func (c *npmRegistryRiskChecker) CheckNewPackage(name, version string) []signal.Signal {
	v, ok := exactNpmVersion(version)
	if !ok {
		return nil
	}

	meta, ok := c.fetchPackageVersion(name, v)
	if !ok {
		return nil
	}
	return evaluateNewNpmScriptRisk(meta.Name, meta.Version, meta.Scripts)
}

// CheckVersionChange compares registry metadata for the old and new version of
// an updated dependency, surfacing install-time behavior that changed between
// them. Registry lookups are best-effort: a failure yields no signals.
func (c *npmRegistryRiskChecker) CheckVersionChange(name, oldVersion, newVersion string) []signal.Signal {
	oldV, okOld := exactNpmVersion(oldVersion)
	newV, okNew := exactNpmVersion(newVersion)
	if !okOld || !okNew {
		return nil
	}

	oldMeta, ok := c.fetchPackageVersion(name, oldV)
	if !ok {
		return nil
	}
	newMeta, ok := c.fetchPackageVersion(name, newV)
	if !ok {
		return nil
	}
	return evaluateVersionChangeRisk(oldMeta, newMeta)
}

// exactNpmVersion reports whether a spec is an exact version the registry can
// resolve. Ranges are skipped because they don't identify a single release.
func exactNpmVersion(version string) (string, bool) {
	v := strings.TrimSpace(version)
	if v == "" || strings.ContainsAny(v, "^~<>*| ") {
		return "", false
	}
	return v, true
}

func (c *npmRegistryRiskChecker) fetchPackageVersion(name, version string) (npmVersionMetadata, bool) {
	if c == nil || c.client == nil {
		return npmVersionMetadata{}, false
	}
	u := fmt.Sprintf("https://registry.npmjs.org/%s/%s", url.PathEscape(name), url.PathEscape(version))
	resp, err := c.client.Get(u)
	if err != nil {
		return npmVersionMetadata{}, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return npmVersionMetadata{}, false
	}
	var meta npmVersionMetadata
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return npmVersionMetadata{}, false
	}
	if meta.Name == "" {
		meta.Name = name
	}
	if meta.Version == "" {
		meta.Version = version
	}
	return meta, true
}

type npmVersionMetadata struct {
	Name    string            `json:"name"`
	Version string            `json:"version"`
	Scripts map[string]string `json:"scripts"`

	// NpmUser is the account that published this specific version.
	NpmUser struct {
		Name string `json:"name"`
	} `json:"_npmUser"`
}

// riskScripts are the npm lifecycle hooks that run at install time.
var riskScripts = []string{"preinstall", "install", "postinstall", "prepare"}

// dependencyInstallScripts are the hooks that run when npm installs a package
// as a dependency. "prepare" is excluded: it runs in the package's own
// directory or on a git install, not for consumers installing from the
// registry, so changes to it are noise in a dependency diff.
var dependencyInstallScripts = []string{"preinstall", "install", "postinstall"}

func evaluateNewNpmScriptRisk(name, version string, scripts map[string]string) []signal.Signal {
	if isPopularNpmPackage(name) || len(scripts) == 0 {
		return nil
	}

	var suspicious []string
	var firstCmd string
	for _, scriptName := range riskScripts {
		cmd, ok := scripts[scriptName]
		if !ok || strings.TrimSpace(cmd) == "" {
			continue
		}
		if isObfuscatedInstallerCommand(cmd) {
			suspicious = append(suspicious, scriptName)
			if firstCmd == "" {
				firstCmd = truncateSnippet(strings.TrimSpace(cmd), 100)
			}
		}
	}
	if len(suspicious) == 0 {
		return nil
	}

	return []signal.Signal{{
		Package:   name,
		Version:   version,
		Ecosystem: "npm",
		Type:      "heuristic",
		Severity:  "high",
		ID:        "VIGILES-SUSPICIOUS-NEW-NPM-PACKAGE",
		Summary:   fmt.Sprintf("New npm dependency has obfuscated lifecycle script (%s)", strings.Join(suspicious, ", ")),
		Details: fmt.Sprintf(
			"New package is outside the popular baseline and defines obfuscated install-time behavior. Script snippet: %s",
			firstCmd,
		),
		Remediation: fmt.Sprintf("Pin and review %s@%s before allowing install; consider blocking until provenance is verified.", name, version),
	}}
}

// evaluateVersionChangeRisk reports what changed about a package's install-time
// behavior between two published versions. Unlike the new-package rule, popular
// packages are not exempt: a trusted package gaining an install hook is exactly
// the compromise pattern this is meant to catch.
func evaluateVersionChangeRisk(oldMeta, newMeta npmVersionMetadata) []signal.Signal {
	var signals []signal.Signal

	if sig := lifecycleScriptChangeSignal(oldMeta, newMeta); sig != nil {
		signals = append(signals, *sig)
	}
	if sig := publisherChangeSignal(oldMeta, newMeta); sig != nil {
		signals = append(signals, *sig)
	}

	return signals
}

func lifecycleScriptChangeSignal(oldMeta, newMeta npmVersionMetadata) *signal.Signal {
	var added, changed []string
	var obfuscated bool
	snippet := ""

	for _, scriptName := range dependencyInstallScripts {
		newCmd := strings.TrimSpace(newMeta.Scripts[scriptName])
		oldCmd := strings.TrimSpace(oldMeta.Scripts[scriptName])
		if newCmd == "" || newCmd == oldCmd {
			continue
		}
		if oldCmd == "" {
			added = append(added, scriptName)
		} else {
			changed = append(changed, scriptName)
		}
		if isObfuscatedInstallerCommand(newCmd) {
			obfuscated = true
		}
		if snippet == "" {
			snippet = truncateSnippet(newCmd, 100)
		}
	}

	if len(added) == 0 && len(changed) == 0 {
		return nil
	}

	var parts []string
	if len(added) > 0 {
		parts = append(parts, fmt.Sprintf("added (%s)", strings.Join(added, ", ")))
	}
	if len(changed) > 0 {
		parts = append(parts, fmt.Sprintf("modified (%s)", strings.Join(changed, ", ")))
	}

	severity := "medium"
	details := fmt.Sprintf(
		"Install-time behavior differs between %s and %s. Script snippet: %s",
		oldMeta.Version, newMeta.Version, snippet,
	)
	if obfuscated {
		severity = "high"
		details = fmt.Sprintf(
			"Install-time behavior differs between %s and %s, and the new command looks obfuscated. Script snippet: %s",
			oldMeta.Version, newMeta.Version, snippet,
		)
	}

	return &signal.Signal{
		Package:   newMeta.Name,
		Version:   newMeta.Version,
		Ecosystem: "npm",
		Type:      "heuristic",
		Severity:  severity,
		ID:        "VIGILES-NPM-LIFECYCLE-SCRIPT-CHANGE",
		Summary:   fmt.Sprintf("Install-time script %s", strings.Join(parts, " and ")),
		Details:   details,
		Remediation: fmt.Sprintf(
			"Compare %s@%s against %s@%s and confirm the new install-time script is intentional before upgrading.",
			newMeta.Name, oldMeta.Version, newMeta.Name, newMeta.Version,
		),
	}
}

func publisherChangeSignal(oldMeta, newMeta npmVersionMetadata) *signal.Signal {
	oldUser := strings.TrimSpace(oldMeta.NpmUser.Name)
	newUser := strings.TrimSpace(newMeta.NpmUser.Name)
	if oldUser == "" || newUser == "" || strings.EqualFold(oldUser, newUser) {
		return nil
	}

	return &signal.Signal{
		Package:   newMeta.Name,
		Version:   newMeta.Version,
		Ecosystem: "npm",
		Type:      "trust-signal",
		Severity:  "info",
		ID:        "VIGILES-NPM-PUBLISHER-CHANGE",
		Summary:   fmt.Sprintf("Publisher changed from '%s' to '%s'", oldUser, newUser),
		Details: fmt.Sprintf(
			"Version %s was published by '%s'; version %s was published by '%s'. Projects with several maintainers or automated releases change publisher routinely, so this is context rather than evidence of compromise.",
			oldMeta.Version, oldUser, newMeta.Version, newUser,
		),
		Remediation: "Confirm the new publisher is part of the project's expected release process.",
	}
}

func isPopularNpmPackage(name string) bool {
	for _, p := range checker.PopularNpmPackages() {
		if strings.EqualFold(strings.TrimSpace(p), strings.TrimSpace(name)) {
			return true
		}
	}
	return false
}

func isObfuscatedInstallerCommand(cmd string) bool {
	s := strings.ToLower(cmd)
	obfuscation := []string{"fromcharcode", "atob(", "base64", "eval(", "new function", "buffer.from("}
	execution := []string{"node -e", "execsync", "child_process", "powershell", "cmd /c", "bash -c", "curl ", "wget "}

	hasObf := false
	for _, m := range obfuscation {
		if strings.Contains(s, m) {
			hasObf = true
			break
		}
	}
	if !hasObf {
		return false
	}
	for _, m := range execution {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}

func truncateSnippet(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-1] + "…"
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
	case base == "requirements.txt" || base == "constraints.txt" ||
		(strings.HasSuffix(base, ".txt") && (strings.HasPrefix(base, "requirements-") || strings.HasPrefix(base, "requirements_"))):
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
