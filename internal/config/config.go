// Package config loads and applies .vigiles.yaml project configuration.
//
// The parser handles a restricted YAML subset — only the specific structure
// used by Vigiles config files. It uses no external dependencies.
package config

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/apoorv-kulkarni/vigiles/internal/signal"
)

const DefaultFile = ".vigiles.yaml"

// Config is the parsed representation of a .vigiles.yaml file.
type Config struct {
	Version  int
	Policy   Policy
	Suppress []Suppression
}

// Policy controls default scan behaviour.
type Policy struct {
	// FailOn is the default --fail-on value when not set via CLI flag.
	FailOn string
}

// Suppression silences a specific signal, optionally scoped to a package.
type Suppression struct {
	ID      string // required: signal ID to suppress (e.g. VIGILES-NPM-INSTALL-SCRIPT)
	Package string // optional: limit to a specific package name
	Reason  string // optional: human-readable justification
	Expires string // optional: YYYY-MM-DD expiry date
}

// Load reads path and returns the parsed Config.
// If the file does not exist, an empty Config is returned with no error.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &Config{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return parse(data)
}

// ApplySuppressions removes signals that match an active suppression rule.
// Expired suppressions are logged to w (typically stderr) and not applied.
func ApplySuppressions(signals []signal.Signal, suppressions []Suppression, w io.Writer) []signal.Signal {
	if len(suppressions) == 0 {
		return signals
	}

	today := time.Now().Format("2006-01-02")
	active := make([]Suppression, 0, len(suppressions))
	for _, s := range suppressions {
		if s.Expires != "" && s.Expires <= today {
			fmt.Fprintf(w, "⚠  Suppression for %s (expires %s) has expired and will not be applied\n", s.ID, s.Expires)
			continue
		}
		active = append(active, s)
	}

	var out []signal.Signal
	for _, sig := range signals {
		if !isSuppressed(sig, active) {
			out = append(out, sig)
		}
	}
	return out
}

func isSuppressed(sig signal.Signal, suppressions []Suppression) bool {
	for _, s := range suppressions {
		if s.ID != sig.ID {
			continue
		}
		if s.Package != "" && !strings.EqualFold(s.Package, sig.Package) {
			continue
		}
		return true
	}
	return false
}

// --- minimal YAML parser ---

// parse handles the restricted .vigiles.yaml structure:
//
//	version: 1
//	policy:
//	  fail-on: vulnerability,heuristic
//	suppress:
//	  - id: VIGILES-XXX
//	    package: some-pkg
//	    reason: "why"
//	    expires: 2026-09-01
func parse(data []byte) (*Config, error) {
	cfg := &Config{Version: 1}

	type section int
	const (
		secRoot section = iota
		secPolicy
		secSuppress
	)

	sec := secRoot
	var cur *Suppression

	for lineNum, raw := range strings.Split(string(data), "\n") {
		// strip inline comments
		line := raw
		if idx := strings.Index(line, " #"); idx >= 0 {
			line = line[:idx]
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		indent := len(raw) - len(strings.TrimLeft(raw, " \t"))

		// top-level key — resets section
		if indent == 0 {
			// flush any open suppress item
			if cur != nil {
				cfg.Suppress = append(cfg.Suppress, *cur)
				cur = nil
			}
			sec = secRoot
			k, _ := splitKV(trimmed)
			switch k {
			case "version":
				_, v := splitKV(trimmed)
				n, err := strconv.Atoi(v)
				if err != nil {
					return nil, fmt.Errorf("line %d: version must be an integer", lineNum+1)
				}
				if n != 1 {
					return nil, fmt.Errorf("line %d: unsupported config version %d (only version 1 is supported)", lineNum+1, n)
				}
				cfg.Version = n
			case "policy":
				sec = secPolicy
			case "suppress":
				sec = secSuppress
			default:
				return nil, fmt.Errorf("line %d: unknown key %q", lineNum+1, k)
			}
			continue
		}

		switch sec {
		case secPolicy:
			k, v := splitKV(trimmed)
			switch k {
			case "fail-on":
				cfg.Policy.FailOn = v
			default:
				return nil, fmt.Errorf("line %d: unknown policy key %q", lineNum+1, k)
			}

		case secSuppress:
			if strings.HasPrefix(trimmed, "- ") {
				// new list item
				if cur != nil {
					cfg.Suppress = append(cfg.Suppress, *cur)
				}
				cur = &Suppression{}
				k, v := splitKV(strings.TrimPrefix(trimmed, "- "))
				if err := setSuppressField(cur, k, v, lineNum+1); err != nil {
					return nil, err
				}
			} else {
				if cur == nil {
					return nil, fmt.Errorf("line %d: suppress field outside of list item", lineNum+1)
				}
				k, v := splitKV(trimmed)
				if err := setSuppressField(cur, k, v, lineNum+1); err != nil {
					return nil, err
				}
			}
		}
	}

	// flush final suppress item
	if cur != nil {
		cfg.Suppress = append(cfg.Suppress, *cur)
	}

	// validate suppressions
	for i, s := range cfg.Suppress {
		if s.ID == "" {
			return nil, fmt.Errorf("suppression %d: missing required field 'id'", i+1)
		}
		if s.Expires != "" {
			if _, err := time.Parse("2006-01-02", s.Expires); err != nil {
				return nil, fmt.Errorf("suppression %d: invalid expires date %q (expected YYYY-MM-DD)", i+1, s.Expires)
			}
		}
	}

	return cfg, nil
}

func setSuppressField(s *Suppression, k, v string, lineNum int) error {
	switch k {
	case "id":
		s.ID = v
	case "package":
		s.Package = v
	case "reason":
		s.Reason = v
	case "expires":
		s.Expires = v
	default:
		return fmt.Errorf("line %d: unknown suppress field %q", lineNum, k)
	}
	return nil
}

// splitKV splits "key: value" into (key, value).
// Quoted values have their surrounding quotes stripped.
func splitKV(s string) (string, string) {
	idx := strings.Index(s, ":")
	if idx < 0 {
		return strings.TrimSpace(s), ""
	}
	key := strings.TrimSpace(s[:idx])
	val := strings.TrimSpace(s[idx+1:])
	if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
		val = val[1 : len(val)-1]
	}
	return key, val
}
