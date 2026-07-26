package checker

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/apoorv-kulkarni/vigiles/internal/scanner"
	"github.com/apoorv-kulkarni/vigiles/internal/signal"
)

type HeuristicChecker struct{}

func NewHeuristicChecker() *HeuristicChecker { return &HeuristicChecker{} }

func (c *HeuristicChecker) Check(packages []scanner.Package) []signal.Signal {
	var signals []signal.Signal

	for _, pkg := range packages {
		signals = append(signals, c.checkPackage(pkg)...)
	}

	// System-level checks — labeled as system-heuristic, not attributed
	// to any single package.
	signals = append(signals, c.checkPthFiles(hasPipPackages(packages))...)
	signals = append(signals, c.checkSuspiciousPersistence()...)

	return signals
}

func hasPipPackages(packages []scanner.Package) bool {
	for _, pkg := range packages {
		if pkg.Ecosystem == "pip" {
			return true
		}
	}
	return false
}

func (c *HeuristicChecker) checkPackage(pkg scanner.Package) []signal.Signal {
	var signals []signal.Signal
	switch pkg.Ecosystem {
	case "pip":
		signals = append(signals, checkPipHeuristics(pkg)...)
	case "npm":
		signals = append(signals, checkNpmHeuristics(pkg)...)
	}
	return signals
}

func checkPipHeuristics(pkg scanner.Package) []signal.Signal {
	var signals []signal.Signal

	if typo := checkTyposquat(pkg.Name, popularPipPackages); typo != "" {
		signals = append(signals, signal.Signal{
			Package: pkg.Name, Version: pkg.Version, Ecosystem: pkg.Ecosystem,
			Type: "heuristic", Severity: "high", ID: "VIGILES-TYPOSQUAT",
			Summary: fmt.Sprintf("Possible typosquat of popular package '%s'", typo),
			Details: "This package name is within edit distance 1 of a popular package. Verify it's the one you intended to install.",
		})
	}

	if isSuspiciousVersion(pkg.Version) {
		signals = append(signals, signal.Signal{
			Package: pkg.Name, Version: pkg.Version, Ecosystem: pkg.Ecosystem,
			Type: "heuristic", Severity: "low", ID: "VIGILES-VERSION-ANOMALY",
			Summary: "Unusual version string pattern",
			Details: "Version contains a pre-release suffix or inflated major number not matching calendar versioning.",
		})
	}

	return signals
}

func checkNpmHeuristics(pkg scanner.Package) []signal.Signal {
	var signals []signal.Signal

	if typo := checkTyposquat(pkg.Name, popularNpmPackages); typo != "" {
		signals = append(signals, signal.Signal{
			Package: pkg.Name, Version: pkg.Version, Ecosystem: pkg.Ecosystem,
			Type: "heuristic", Severity: "high", ID: "VIGILES-TYPOSQUAT",
			Summary: fmt.Sprintf("Possible typosquat of popular package '%s'", typo),
			Details: "This package name is within edit distance 1 of a popular npm package.",
		})
	}

	return signals
}

// pythonSiteScript prints every site directory the interpreter imports from,
// including the per-user directory that site.getsitepackages() omits.
const pythonSiteScript = `import site
dirs = list(site.getsitepackages())
try:
    dirs.append(site.getusersitepackages())
except Exception:
    pass
print("\n".join(d for d in dirs if d))`

// pythonInterpreters returns the interpreters whose site directories should be
// scanned, most specific first. Resolving only python3 from PATH misses a
// project virtualenv that isn't activated in the calling shell, which is
// exactly where a compromised package would sit.
func pythonInterpreters() []string {
	var candidates []string
	if venv := os.Getenv("VIRTUAL_ENV"); venv != "" {
		candidates = append(candidates, filepath.Join(venv, "bin", "python3"))
	}
	for _, dir := range []string{".venv", "venv", "env"} {
		candidates = append(candidates, filepath.Join(dir, "bin", "python3"))
	}
	if path, err := exec.LookPath("python3"); err == nil {
		candidates = append(candidates, path)
	}

	seen := map[string]bool{}
	var out []string
	for _, candidate := range candidates {
		// Absolute, not symlink-resolved: a venv's python3 usually links to the
		// base interpreter, and following that link would discard the venv's
		// own site directories.
		resolved, err := filepath.Abs(candidate)
		if err != nil || seen[resolved] {
			continue
		}
		if info, err := os.Stat(resolved); err != nil || info.IsDir() {
			continue
		}
		seen[resolved] = true
		out = append(out, resolved)
	}
	return out
}

// pythonSiteDirs returns the deduplicated site directories across every
// resolvable interpreter, and whether any interpreter answered at all.
func pythonSiteDirs() (dirs []string, queried bool) {
	seen := map[string]bool{}
	for _, python := range pythonInterpreters() {
		out, err := exec.Command(python, "-c", pythonSiteScript).Output()
		if err != nil {
			continue
		}
		queried = true
		for _, dir := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if dir = strings.TrimSpace(dir); dir == "" || seen[dir] {
				continue
			}
			seen[dir] = true
			dirs = append(dirs, dir)
		}
	}
	return dirs, queried
}

// checkPthFiles scans Python site directories for .pth files with executable
// import statements — the technique used in LiteLLM 1.82.8.
// Labeled as system-heuristic since findings aren't tied to a pip-installed
// package name.
//
// pipInScope reports whether the scan inventoried any Python packages. When it
// did and no interpreter can be queried, the check reports that it did not run:
// returning a silent all-clear would hide Vigiles' headline detection.
func (c *HeuristicChecker) checkPthFiles(pipInScope bool) []signal.Signal {
	var signals []signal.Signal

	dirs, queried := pythonSiteDirs()
	if !queried {
		if !pipInScope {
			return nil
		}
		return []signal.Signal{{
			Package: "system", Version: "", Ecosystem: "system",
			Type: "system-heuristic", Severity: "unknown",
			ID:      "VIGILES-PTH-SCAN-SKIPPED",
			Summary: "Could not scan for malicious .pth files: no usable Python interpreter",
			Details: "Python packages were inventoried but no interpreter answered a site " +
				"directory query, so the .pth persistence check never ran. Put python3 on " +
				"PATH, or run Vigiles with the project's virtualenv active.",
		}}
	}

	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".pth") {
				continue
			}
			content, err := os.ReadFile(filepath.Join(dir, entry.Name()))
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(content), "\n") {
				line = strings.TrimSpace(line)
				if (strings.HasPrefix(line, "import ") || strings.HasPrefix(line, "import\t")) &&
					containsSuspiciousImport(line) {
					signals = append(signals, signal.Signal{
						Package: entry.Name(), Version: "", Ecosystem: "system",
						Type: "system-heuristic", Severity: "critical",
						ID:      "VIGILES-MALICIOUS-PTH",
						Summary: fmt.Sprintf("Suspicious .pth file with executable code: %s", entry.Name()),
						Details: fmt.Sprintf(
							"File %s/%s contains import statements that execute on every Python startup. "+
								"This matches the technique used in the LiteLLM supply chain attack. "+
								"Suspicious line: %s", dir, entry.Name(), truncate(line, 100)),
					})
				}
			}
		}
	}
	return signals
}

// checkSuspiciousPersistence checks for known backdoor artifacts from
// the TeamPCP campaign. Labeled as system-heuristic.
func (c *HeuristicChecker) checkSuspiciousPersistence() []signal.Signal {
	var signals []signal.Signal

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return signals
	}

	checks := []struct {
		path, id, summary string
	}{
		{filepath.Join(homeDir, ".config", "sysmon", "sysmon.py"),
			"VIGILES-TEAMPCP-BACKDOOR",
			"TeamPCP sysmon backdoor artifact detected on this host"},
		{filepath.Join(homeDir, ".config", "systemd", "user", "sysmon.service"),
			"VIGILES-TEAMPCP-PERSISTENCE",
			"TeamPCP systemd persistence service detected on this host"},
	}

	for _, c := range checks {
		if _, err := os.Stat(c.path); err == nil {
			signals = append(signals, signal.Signal{
				Package: "system", Version: "", Ecosystem: "system",
				Type: "system-heuristic", Severity: "critical", ID: c.id,
				Summary: c.summary,
				Details: fmt.Sprintf("Found: %s — Rotate all credentials immediately.", c.path),
			})
		}
	}

	tmpDirs := []string{"/tmp"}
	if userTmp := os.Getenv("TMPDIR"); userTmp != "" && userTmp != "/tmp" {
		tmpDirs = append(tmpDirs, userTmp)
	}
	artifactNames := []string{"tpcp.tar.gz", "session.key", "payload.enc", ".pg_state", "pglog"}
	seen := map[string]bool{}
	for _, dir := range tmpDirs {
		for _, name := range artifactNames {
			p := filepath.Join(dir, name)
			if seen[p] {
				continue
			}
			seen[p] = true
			if _, err := os.Stat(p); err == nil {
				signals = append(signals, signal.Signal{
					Package: "system", Version: "", Ecosystem: "system",
					Type: "system-heuristic", Severity: "critical",
					ID:      "VIGILES-EXFIL-ARTIFACT",
					Summary: fmt.Sprintf("Supply chain attack artifact found: %s", p),
					Details: "This file matches known exfiltration artifacts from the TeamPCP campaign.",
				})
			}
		}
	}

	return signals
}

// --- Shared helpers ---

func checkTyposquat(name string, popular []string) string {
	normalized := strings.ToLower(strings.ReplaceAll(name, "-", "_"))
	if _, ok := knownGoodPackages[normalized]; ok {
		return ""
	}
	for _, pop := range popular {
		popNorm := strings.ToLower(strings.ReplaceAll(pop, "-", "_"))
		if normalized == popNorm || len(popNorm) <= 3 {
			continue
		}
		if levenshtein(normalized, popNorm) == 1 {
			return pop
		}
		for _, suffix := range []string{"py", "python", "lib", "dev", "2", "3"} {
			if normalized == popNorm+suffix || normalized == popNorm+"_"+suffix ||
				normalized == popNorm+"-"+suffix {
				return pop
			}
		}
	}
	return ""
}

var knownGoodPackages = map[string]struct{}{
	"pipx": {}, "pip_tools": {}, "pipdeptree": {}, "npx": {}, "node": {},
	"numpydoc": {}, "pandas_stubs": {}, "flask_cors": {}, "flask_login": {},
	"djangorestframework": {}, "boto3_stubs": {}, "httpx": {}, "aiohttp": {},
	"uvicorn": {}, "gunicorn": {}, "pydantic_core": {},
	// Common packages that trigger edit-distance-1 false positives
	"pip_audit": {}, "python_dateutil": {}, "ruff": {}, "uv": {},
	"pytest_asyncio": {}, "black": {}, "mypy": {},
}

func isSuspiciousVersion(version string) bool {
	suspicious := regexp.MustCompile(`(?i)(dev|alpha|beta|rc)\d*$`)
	highVersion := regexp.MustCompile(`^\d{3,}\.`)
	calendarVersion := regexp.MustCompile(`^20\d{2}\.`)

	if suspicious.MatchString(version) {
		return true
	}
	return highVersion.MatchString(version) && !calendarVersion.MatchString(version)
}

func containsSuspiciousImport(line string) bool {
	for _, s := range []string{"subprocess", "os.system", "exec(", "eval(", "base64",
		"urllib", "requests.post", "socket", "Popen", "shutil", "tempfile"} {
		if strings.Contains(line, s) {
			return true
		}
	}
	return false
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func levenshtein(a, b string) int {
	la, lb := len(a), len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	matrix := make([][]int, la+1)
	for i := range matrix {
		matrix[i] = make([]int, lb+1)
		matrix[i][0] = i
	}
	for j := 0; j <= lb; j++ {
		matrix[0][j] = j
	}
	for i := 1; i <= la; i++ {
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			matrix[i][j] = min(matrix[i-1][j]+1, min(matrix[i][j-1]+1, matrix[i-1][j-1]+cost))
		}
	}
	return matrix[la][lb]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

var popularPipPackages = []string{
	"requests", "numpy", "pandas", "flask", "django", "boto3",
	"urllib3", "setuptools", "pip", "wheel", "cryptography",
	"pyyaml", "jinja2", "pytest", "scipy", "pillow",
	"certifi", "click", "aiohttp", "sqlalchemy", "fastapi",
	"pydantic", "httpx", "litellm", "openai", "anthropic",
	"langchain", "transformers", "torch", "tensorflow",
	"celery", "redis", "psycopg2", "pymongo", "docker",
	"kubernetes", "paramiko", "fabric", "ansible",
}

var popularNpmPackages = []string{
	"express", "react", "lodash", "axios", "next",
	"typescript", "webpack", "babel-core", "eslint", "prettier",
	"moment", "chalk", "commander", "inquirer", "debug",
	"dotenv", "uuid", "cors", "jsonwebtoken", "socket.io",
	"mongoose", "pg", "mysql2", "redis", "aws-sdk",
	"firebase", "stripe", "openai", "langchain", "zod",
}
