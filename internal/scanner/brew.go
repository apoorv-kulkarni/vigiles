package scanner

import (
	"encoding/json"
	"fmt"
	"os/exec"
)

// BrewScanner inventories Homebrew packages.
type BrewScanner struct{}

func (s *BrewScanner) Name() string { return "brew" }

func (s *BrewScanner) Available() bool {
	_, err := exec.LookPath("brew")
	return err == nil
}

func (s *BrewScanner) Scan() ([]Package, error) {
	out, err := exec.Command("brew", "info", "--json=v2", "--installed").Output()
	if err != nil {
		return nil, fmt.Errorf("brew info failed: %w", err)
	}

	var result brewInfoOutput
	if err := json.Unmarshal(out, &result); err != nil {
		return nil, fmt.Errorf("parsing brew output: %w", err)
	}

	packages := make([]Package, 0, len(result.Formulae)+len(result.Casks))

	for _, f := range result.Formulae {
		ver := ""
		if len(f.Installed) > 0 {
			ver = f.Installed[0].Version
		}
		packages = append(packages, Package{
			Name:      f.Name,
			Version:   ver,
			Ecosystem: "brew",
			Location:  f.Tap,
			Direct:    !f.InstalledAsDep,
		})
	}

	for _, c := range result.Casks {
		packages = append(packages, Package{
			Name:      c.Token,
			Version:   c.Version,
			Ecosystem: "brew",
			Location:  c.Tap,
			Direct:    true,
		})
	}

	return packages, nil
}

type brewInfoOutput struct {
	Formulae []brewFormula `json:"formulae"`
	Casks    []brewCask    `json:"casks"`
}

type brewFormula struct {
	Name           string          `json:"name"`
	Tap            string          `json:"tap"`
	Installed      []brewInstalled `json:"installed"`
	InstalledAsDep bool            `json:"installed_as_dependency"`
}

type brewInstalled struct {
	Version string `json:"version"`
}

type brewCask struct {
	Token   string `json:"token"`
	Version string `json:"version"`
	Tap     string `json:"tap"`
}
