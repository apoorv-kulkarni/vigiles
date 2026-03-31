package scanner

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// PipScanner inventories Python packages via pip.
type PipScanner struct{}

func (s *PipScanner) Name() string { return "pip" }

func (s *PipScanner) Available() bool {
	// Try pip3 first, then pip
	for _, cmd := range []string{"pip3", "pip"} {
		if _, err := exec.LookPath(cmd); err == nil {
			return true
		}
	}
	return false
}

func (s *PipScanner) Scan() ([]Package, error) {
	pipCmd := s.findPip()
	if pipCmd == "" {
		return nil, fmt.Errorf("pip not found in PATH")
	}

	// Get all installed packages as JSON
	out, err := exec.Command(pipCmd, "list", "--format", "json").Output()
	if err != nil {
		return nil, fmt.Errorf("pip list failed: %w", err)
	}

	var pipPkgs []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(out, &pipPkgs); err != nil {
		return nil, fmt.Errorf("parsing pip output: %w", err)
	}

	// Also get the list of user-installed (direct) packages for the Direct flag
	directSet := s.getDirectPackages(pipCmd)

	packages := make([]Package, 0, len(pipPkgs))
	for _, p := range pipPkgs {
		_, isDirect := directSet[strings.ToLower(p.Name)]
		packages = append(packages, Package{
			Name:      p.Name,
			Version:   p.Version,
			Ecosystem: "pip",
			Location:  "PyPI",
			Direct:    isDirect,
		})
	}
	return packages, nil
}

// findPip returns the pip binary name available on the system.
func (s *PipScanner) findPip() string {
	for _, cmd := range []string{"pip3", "pip"} {
		if _, err := exec.LookPath(cmd); err == nil {
			return cmd
		}
	}
	return ""
}

// getDirectPackages returns a set of package names that were explicitly
// installed (not pulled in as transitive deps). Best effort.
func (s *PipScanner) getDirectPackages(pipCmd string) map[string]struct{} {
	set := make(map[string]struct{})

	// pip list --not-required shows packages nothing else depends on
	// This is an approximation of "direct" dependencies
	out, err := exec.Command(pipCmd, "list", "--not-required", "--format", "json").Output()
	if err != nil {
		return set
	}

	var pkgs []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(out, &pkgs); err != nil {
		return set
	}

	for _, p := range pkgs {
		set[strings.ToLower(p.Name)] = struct{}{}
	}
	return set
}
