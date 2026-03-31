package checker

import (
	"strings"

	"github.com/apoorv-kulkarni/vigiles/internal/signal"
)

// CheckUnpinned examines a dependency specifier and returns a trust signal
// if the version is not exactly pinned. This is useful in diff/requirements
// contexts where we have the raw specifier string.
func CheckUnpinned(name, specifier, ecosystem string) *signal.Signal {
	spec := strings.TrimSpace(specifier)
	if spec == "" {
		return &signal.Signal{
			Package: name, Version: "(any)", Ecosystem: ecosystem,
			Type: "trust-signal", Severity: "info",
			ID:      "VIGILES-UNPINNED",
			Summary: "Dependency has no version constraint",
			Details: "This dependency has no version pin, meaning any version may be installed. Consider pinning to an exact version.",
		}
	}

	// Exact pin: name==1.2.3
	if strings.HasPrefix(spec, "==") && !strings.Contains(spec, "*") {
		return nil // exactly pinned, no signal
	}

	// npm exact: "1.2.3" with no prefix operators
	if ecosystem == "npm" && !strings.ContainsAny(spec, "^~><=*|") {
		return nil // exact
	}

	// Everything else is a range specifier
	return &signal.Signal{
		Package: name, Version: spec, Ecosystem: ecosystem,
		Type: "trust-signal", Severity: "info",
		ID:      "VIGILES-UNPINNED",
		Summary: "Dependency uses a version range, not an exact pin",
		Details: "Version specifier '" + spec + "' allows a range of versions. An exact pin (==) ensures reproducible installs.",
	}
}

// IsExactlyPinned returns true if the specifier is an exact version pin.
func IsExactlyPinned(specifier, ecosystem string) bool {
	s := strings.TrimSpace(specifier)
	if s == "" {
		return false
	}
	switch ecosystem {
	case "pip":
		return strings.HasPrefix(s, "==") && !strings.Contains(s, "*")
	case "npm":
		return !strings.ContainsAny(s, "^~><=*|")
	default:
		return false
	}
}
