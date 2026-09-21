package gate

import (
	"io"

	"github.com/apoorv-kulkarni/vigiles/internal/config"
)

// Decide applies the trusted policy identically for CLI and MCP callers.
func Decide(r *Report, version string, warnings io.Writer) int {
	r.Version = version
	failOn, err := config.ParseFailOn(r.Policy.Policy.FailOn)
	if err != nil {
		r.Incomplete = append(r.Incomplete, "invalid base policy: "+err.Error())
	}
	r.Signals = config.ApplySuppressions(r.Signals, r.Policy.Suppress, warnings)
	code := 0
	r.Status = "pass"
	if config.HasBlockingSignal(r.Signals, failOn) {
		r.Status, code = "blocked", 1
	}
	if len(r.Incomplete) > 0 {
		r.Status, code = "incomplete", 2
	}
	return code
}
