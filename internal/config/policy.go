package config

import (
	"fmt"
	"strings"

	"github.com/apoorv-kulkarni/vigiles/internal/signal"
)

// validFailOnTypes is the set of accepted --fail-on values.
var validFailOnTypes = map[string]bool{
	"vulnerability":    true,
	"heuristic":        true,
	"system-heuristic": true,
	"trust-signal":     true,
	"all":              true,
	"none":             true,
}

// ParseFailOn parses a comma-separated --fail-on value into a type set.
func ParseFailOn(input string) (map[string]bool, error) {
	result := map[string]bool{}
	for _, t := range strings.Split(input, ",") {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if !validFailOnTypes[t] {
			return nil, fmt.Errorf("invalid --fail-on value %q (valid: vulnerability, heuristic, system-heuristic, trust-signal, all, none)", t)
		}
		result[t] = true
	}
	return result, nil
}

// HasBlockingSignal reports whether any signal matches the fail-on policy.
// A nil or empty map defaults to "all" behaviour (backward-compatible).
func HasBlockingSignal(signals []signal.Signal, failOn map[string]bool) bool {
	if len(failOn) == 0 || failOn["all"] {
		return len(signals) > 0
	}
	if failOn["none"] {
		return false
	}
	for _, s := range signals {
		if failOn[s.Type] {
			return true
		}
	}
	return false
}
