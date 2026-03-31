package checker

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/apoorv-kulkarni/vigiles/internal/signal"
)

// riskScripts are npm lifecycle scripts that execute automatically during
// install. These are a common attack vector for supply chain attacks.
var riskScripts = []string{"preinstall", "install", "postinstall", "prepare"}

// CheckNpmInstallScripts scans a package.json for lifecycle scripts that
// run during npm install. Returns trust signals (not vulnerabilities).
func CheckNpmInstallScripts(packageJSONPath string) []signal.Signal {
	data, err := os.ReadFile(packageJSONPath)
	if err != nil {
		return nil
	}

	var pkg struct {
		Name    string            `json:"name"`
		Version string            `json:"version"`
		Scripts map[string]string `json:"scripts"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil
	}

	return checkScriptsMap(pkg.Name, pkg.Version, pkg.Scripts)
}

// CheckNpmInstallScriptsInNodeModules scans installed packages in a
// node_modules directory for install scripts.
func CheckNpmInstallScriptsInNodeModules(nodeModulesPath string) []signal.Signal {
	var signals []signal.Signal

	entries, err := os.ReadDir(nodeModulesPath)
	if err != nil {
		return nil
	}

	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}

		// Handle scoped packages (@scope/name)
		if strings.HasPrefix(entry.Name(), "@") {
			scopeDir := filepath.Join(nodeModulesPath, entry.Name())
			scopeEntries, err := os.ReadDir(scopeDir)
			if err != nil {
				continue
			}
			for _, se := range scopeEntries {
				if !se.IsDir() {
					continue
				}
				pkgJSON := filepath.Join(scopeDir, se.Name(), "package.json")
				signals = append(signals, CheckNpmInstallScripts(pkgJSON)...)
			}
			continue
		}

		pkgJSON := filepath.Join(nodeModulesPath, entry.Name(), "package.json")
		signals = append(signals, CheckNpmInstallScripts(pkgJSON)...)
	}

	return signals
}

func checkScriptsMap(name, version string, scripts map[string]string) []signal.Signal {
	if len(scripts) == 0 {
		return nil
	}

	var signals []signal.Signal
	for _, scriptName := range riskScripts {
		cmd, ok := scripts[scriptName]
		if !ok || cmd == "" {
			continue
		}

		signals = append(signals, signal.Signal{
			Package: name, Version: version, Ecosystem: "npm",
			Type: "trust-signal", Severity: "info",
			ID:      "VIGILES-NPM-INSTALL-SCRIPT",
			Summary: fmt.Sprintf("Package defines '%s' lifecycle script", scriptName),
			Details: fmt.Sprintf("Script '%s' runs automatically during npm install: %s", scriptName, truncateScript(cmd, 120)),
		})
	}
	return signals
}

func truncateScript(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
