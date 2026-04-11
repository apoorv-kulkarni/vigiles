// gomod.go inventories dependencies from the local Go module graph.
package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
)

// GoModScanner inventories Go modules from the current module graph.
type GoModScanner struct{}

func (s *GoModScanner) Name() string { return "gomod" }

func (s *GoModScanner) Available() bool {
	if _, err := exec.LookPath("go"); err != nil {
		return false
	}
	_, err := os.Stat("go.mod")
	return err == nil
}

func (s *GoModScanner) Scan() ([]Package, error) {
	out, err := exec.Command("go", "list", "-m", "-json", "all").Output()
	if err != nil {
		return nil, fmt.Errorf("go list -m -json all failed: %w", err)
	}

	type goModule struct {
		Path    string `json:"Path"`
		Version string `json:"Version"`
		Main    bool   `json:"Main"`
	}

	dec := json.NewDecoder(bytes.NewReader(out))
	var pkgs []Package
	for {
		var m goModule
		if err := dec.Decode(&m); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("parsing go module graph: %w", err)
		}
		if m.Main || m.Path == "" || m.Version == "" {
			continue
		}
		pkgs = append(pkgs, Package{
			Name:      m.Path,
			Version:   m.Version,
			Ecosystem: "gomod",
			Location:  "go.mod",
			Direct:    false,
		})
	}
	if len(pkgs) == 0 {
		return nil, fmt.Errorf("no go modules found")
	}
	return pkgs, nil
}
