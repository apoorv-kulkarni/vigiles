// Package signal defines the core finding/signal model used across Vigiles.
//
// Every checker produces []Signal. The reporter consumes them. This avoids
// circular dependencies between checker and reporter packages.
package signal

// Signal represents a single finding — either a known vulnerability or a
// heuristic trust signal. The Type field makes this distinction explicit.
type Signal struct {
	// Package name (or "system" for system-level checks).
	Package string `json:"package"`
	Version string `json:"version"`

	// Ecosystem: "pip", "npm", "brew", or "system" for host-level checks.
	Ecosystem string `json:"ecosystem"`

	// Type classifies what kind of signal this is.
	//   "vulnerability"      — known CVE/GHSA from a vulnerability database
	//   "heuristic"          — package-level behavioral red flag
	//   "system-heuristic"   — host-level check (not attributable to a single package)
	//   "trust-signal"       — informational risk signal (e.g., recently published, unpinned)
	Type string `json:"type"`

	// Severity: "critical", "high", "medium", "low", "info", "unknown".
	// Use "info" for trust signals that are informational, not actionable vulnerabilities.
	Severity string `json:"severity"`

	// ID is a stable identifier: CVE-*, GHSA-*, or VIGILES-* for heuristic rules.
	ID string `json:"id"`

	// Summary is a one-line human-readable description.
	Summary string `json:"summary"`

	// Details provides additional context, remediation, or a URL.
	Details string `json:"details"`

	// Aliases are alternative identifiers (e.g., CVE for a GHSA, or vice versa).
	Aliases []string `json:"aliases,omitempty"`
}

// SeverityOrder returns a numeric ordering for severity (lower = more severe).
func SeverityOrder(sev string) int {
	switch sev {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	case "info":
		return 4
	case "unknown":
		return 5
	default:
		return 6
	}
}

// SortSignals sorts signals by severity (most severe first).
func SortSignals(signals []Signal) {
	for i := 1; i < len(signals); i++ {
		key := signals[i]
		j := i - 1
		for j >= 0 && SeverityOrder(signals[j].Severity) > SeverityOrder(key.Severity) {
			signals[j+1] = signals[j]
			j--
		}
		signals[j+1] = key
	}
}

// Summary counts signals by type and severity.
type Summary struct {
	Total          int            `json:"total"`
	BySeverity     map[string]int `json:"by_severity"`
	ByType         map[string]int `json:"by_type"`
	Vulnerabilities int           `json:"vulnerabilities"`
	Heuristics     int            `json:"heuristics"`
	TrustSignals   int            `json:"trust_signals"`
}

// Summarize computes a Summary from a slice of signals.
func Summarize(signals []Signal) Summary {
	s := Summary{
		Total:      len(signals),
		BySeverity: map[string]int{},
		ByType:     map[string]int{},
	}
	for _, sig := range signals {
		s.BySeverity[sig.Severity]++
		s.ByType[sig.Type]++
		switch sig.Type {
		case "vulnerability":
			s.Vulnerabilities++
		case "heuristic", "system-heuristic":
			s.Heuristics++
		case "trust-signal":
			s.TrustSignals++
		}
	}
	return s
}

// ValidSeverities is the set of valid severity values.
var ValidSeverities = []string{"critical", "high", "medium", "low", "info", "unknown"}
