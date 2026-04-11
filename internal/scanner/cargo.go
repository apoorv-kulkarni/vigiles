// cargo.go inventories crates installed via cargo install for Rust ecosystem scanning.
package scanner

import (
	"bufio"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// CargoScanner inventories Rust crates installed via `cargo install`.
type CargoScanner struct{}

func (s *CargoScanner) Name() string { return "cargo" }

func (s *CargoScanner) Available() bool {
	_, err := exec.LookPath("cargo")
	return err == nil
}

func (s *CargoScanner) Scan() ([]Package, error) {
	out, err := exec.Command("cargo", "install", "--list").Output()
	if err != nil {
		return nil, fmt.Errorf("cargo install --list failed: %w", err)
	}

	lineRe := regexp.MustCompile(`^([^\s]+)\s+v([^:]+):$`)
	var pkgs []Package
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		m := lineRe.FindStringSubmatch(line)
		if len(m) != 3 {
			continue
		}
		pkgs = append(pkgs, Package{
			Name:      m[1],
			Version:   m[2],
			Ecosystem: "cargo",
			Location:  "cargo-install",
			Direct:    true,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("parsing cargo output: %w", err)
	}
	if len(pkgs) == 0 {
		return nil, fmt.Errorf("no cargo packages found")
	}
	return pkgs, nil
}
