package checker

import (
	"math"
	"strings"
)

// CVSS v3.1 base metric weights, from specification section 7.4.
var (
	cvss3AttackVector     = map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
	cvss3AttackComplexity = map[string]float64{"L": 0.77, "H": 0.44}
	cvss3UserInteraction  = map[string]float64{"N": 0.85, "R": 0.62}
	cvss3ImpactMetric     = map[string]float64{"H": 0.56, "L": 0.22, "N": 0}

	// Privileges Required is weighted higher when Scope is Changed.
	cvss3PrivilegesUnchanged = map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	cvss3PrivilegesChanged   = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.50}
)

// cvss3BaseScore computes the CVSS v3.x base score from a vector string, per
// specification section 7.1.
//
// OSV stores CVSS severities as vectors such as
// "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", never as bare numbers, so
// scoring the vector is the only way to rank most findings. Vectors that are
// not v3.x, or that omit or misspell a base metric, report ok=false so the
// caller can fall back rather than publish a wrong number.
func cvss3BaseScore(vector string) (float64, bool) {
	m, ok := parseCVSSVector(vector, "CVSS:3.")
	if !ok {
		return 0, false
	}

	scope, ok := m["S"]
	if !ok || (scope != "U" && scope != "C") {
		return 0, false
	}
	scopeChanged := scope == "C"

	privileges := cvss3PrivilegesUnchanged
	if scopeChanged {
		privileges = cvss3PrivilegesChanged
	}

	av, okAV := cvss3AttackVector[m["AV"]]
	ac, okAC := cvss3AttackComplexity[m["AC"]]
	pr, okPR := privileges[m["PR"]]
	ui, okUI := cvss3UserInteraction[m["UI"]]
	conf, okC := cvss3ImpactMetric[m["C"]]
	integ, okI := cvss3ImpactMetric[m["I"]]
	avail, okA := cvss3ImpactMetric[m["A"]]
	if !okAV || !okAC || !okPR || !okUI || !okC || !okI || !okA {
		return 0, false
	}

	iss := 1 - ((1 - conf) * (1 - integ) * (1 - avail))
	impact := 6.42 * iss
	if scopeChanged {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}
	if impact <= 0 {
		return 0, true
	}

	score := impact + 8.22*av*ac*pr*ui
	if scopeChanged {
		score *= 1.08
	}
	return cvss3Roundup(math.Min(score, 10)), true
}

// cvss3Roundup implements the CVSS v3.1 Roundup function, which rounds up to
// one decimal place while tolerating floating point representation error.
func cvss3Roundup(score float64) float64 {
	scaled := int(math.Round(score * 100000))
	if scaled%10000 == 0 {
		return float64(scaled) / 100000.0
	}
	return float64(scaled/10000+1) / 10.0
}

// parseCVSSVector splits a slash-delimited CVSS vector into its metrics after
// checking the version prefix.
func parseCVSSVector(vector, prefix string) (map[string]string, bool) {
	vector = strings.TrimSpace(vector)
	if !strings.HasPrefix(vector, prefix) {
		return nil, false
	}

	metrics := map[string]string{}
	for _, part := range strings.Split(vector, "/")[1:] {
		if key, value, found := strings.Cut(part, ":"); found {
			metrics[key] = value
		}
	}
	return metrics, len(metrics) > 0
}
