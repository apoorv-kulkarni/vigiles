// deepinspect.go adds deeper static checks for risky setup.py and npm lifecycle hook behavior.
package checker

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/apoorv-kulkarni/vigiles/internal/signal"
)

// CheckSetupPyDeep inspects setup.py for suspicious install-time behavior.
func CheckSetupPyDeep(setupPyPath string) []signal.Signal {
	data, err := os.ReadFile(setupPyPath)
	if err != nil {
		return nil
	}
	s := strings.ToLower(string(data))

	suspicious := []string{"exec(", "eval(", "subprocess", "os.system", "base64", "urllib", "requests.", "socket"}
	matches := collectMarkers(s, suspicious)
	if len(matches) == 0 {
		return nil
	}

	return []signal.Signal{{
		Package:   "setup.py",
		Version:   "",
		Ecosystem: "pip",
		Type:      "heuristic",
		Severity:  "high",
		ID:        "VIGILES-SETUPPY-SUSPICIOUS",
		Summary:   "setup.py contains suspicious install-time code patterns",
		Details:   fmt.Sprintf("Detected markers in setup.py: %s", strings.Join(matches, ", ")),
	}}
}

// CheckNpmInstallScriptsDeep inspects package.json scripts and highlights
// lifecycle hooks that appear obfuscated or network-executing.
func CheckNpmInstallScriptsDeep(packageJSONPath string) []signal.Signal {
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

	if len(pkg.Scripts) == 0 {
		return nil
	}

	var out []signal.Signal
	for _, hook := range riskScripts {
		cmd := strings.TrimSpace(pkg.Scripts[hook])
		if cmd == "" {
			continue
		}
		if !looksSuspiciousScript(cmd) {
			continue
		}
		out = append(out, signal.Signal{
			Package:   coalesce(pkg.Name, "package.json"),
			Version:   pkg.Version,
			Ecosystem: "npm",
			Type:      "heuristic",
			Severity:  "high",
			ID:        "VIGILES-NPM-HOOK-SUSPICIOUS",
			Summary:   fmt.Sprintf("Suspicious npm lifecycle hook: %s", hook),
			Details:   fmt.Sprintf("Hook command appears obfuscated and/or downloads code: %s", truncateScript(cmd, 120)),
		})
	}
	return out
}

func looksSuspiciousScript(cmd string) bool {
	s := strings.ToLower(cmd)
	hasObfuscation := strings.Contains(s, "base64") || strings.Contains(s, "eval(") || strings.Contains(s, "fromcharcode") || strings.Contains(s, "atob(")
	hasExec := strings.Contains(s, "node -e") || strings.Contains(s, "python -c") || strings.Contains(s, "bash -c") || strings.Contains(s, "powershell")
	hasNetwork := strings.Contains(s, "curl ") || strings.Contains(s, "wget ") || strings.Contains(s, "invoke-webrequest")
	return (hasObfuscation && hasExec) || (hasNetwork && hasExec)
}

func collectMarkers(s string, markers []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range markers {
		if strings.Contains(s, m) && !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	return out
}

func coalesce(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}
