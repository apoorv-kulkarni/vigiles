package scanner

import (
	"encoding/json"
	"fmt"
	"os/exec"
)

// NpmScanner inventories Node.js packages via npm.
type NpmScanner struct{}

func (s *NpmScanner) Name() string { return "npm" }

func (s *NpmScanner) Available() bool {
	_, err := exec.LookPath("npm")
	return err == nil
}

func (s *NpmScanner) Scan() ([]Package, error) {
	packages := make([]Package, 0)

	// Scan global packages
	globalPkgs, err := s.scanScope("--global")
	if err == nil {
		packages = append(packages, globalPkgs...)
	}

	// Scan local packages (if in a project directory)
	localPkgs, err := s.scanScope("")
	if err == nil {
		packages = append(packages, localPkgs...)
	}

	if len(packages) == 0 {
		return packages, fmt.Errorf("no npm packages found")
	}
	return packages, nil
}

func (s *NpmScanner) scanScope(scopeFlag string) ([]Package, error) {
	args := []string{"list", "--json", "--depth=0"}
	if scopeFlag != "" {
		args = append(args, scopeFlag)
	}

	// npm list returns non-zero on missing peer deps etc, but still produces
	// valid JSON. Capture output regardless of exit code.
	cmd := exec.Command("npm", args...)
	out, _ := cmd.Output()
	if len(out) == 0 {
		return nil, fmt.Errorf("npm list produced no output")
	}

	var result npmListOutput
	if err := json.Unmarshal(out, &result); err != nil {
		return nil, fmt.Errorf("parsing npm output: %w", err)
	}

	location := "local"
	if scopeFlag == "--global" {
		location = "global"
	}

	packages := make([]Package, 0, len(result.Dependencies))
	for name, dep := range result.Dependencies {
		packages = append(packages, Package{
			Name:      name,
			Version:   dep.Version,
			Ecosystem: "npm",
			Location:  location,
			Direct:    true, // depth=0 means direct deps
		})
	}
	return packages, nil
}

type npmListOutput struct {
	Dependencies map[string]npmDep `json:"dependencies"`
}

type npmDep struct {
	Version string `json:"version"`
}
