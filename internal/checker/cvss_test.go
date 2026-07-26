package checker

import "testing"

// Reference vectors and their published base scores. The scope-changed cases
// matter most: they exercise the modified impact formula and the 1.08
// multiplier, which is where a hand-rolled scorer usually goes wrong.
func TestCVSS3BaseScore(t *testing.T) {
	tests := []struct {
		name   string
		vector string
		want   float64
	}{
		{"critical, scope unchanged", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		{"maximum, scope changed", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0},
		{"stored XSS, scope changed", "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", 5.4},
		{"CVE-2024-35195", "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:H/I:H/A:N", 5.6},
		{"information disclosure only", "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5},
		{"physical, high complexity", "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6},
		{"no impact scores zero", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := cvss3BaseScore(tt.vector)
			if !ok {
				t.Fatalf("expected %s to be scoreable", tt.vector)
			}
			if got != tt.want {
				t.Errorf("cvss3BaseScore(%s) = %v, want %v", tt.vector, got, tt.want)
			}
		})
	}
}

// Anything not scoreable must say so rather than return a plausible number, so
// the caller can fall back to database_specific.severity.
func TestCVSS3BaseScoreRejectsUnscoreableVectors(t *testing.T) {
	tests := []struct {
		name   string
		vector string
	}{
		{"empty", ""},
		{"CVSS v2", "AV:N/AC:L/Au:N/C:P/I:P/A:P"},
		{"CVSS v4", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"},
		{"missing scope", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/C:H/I:H/A:H"},
		{"unknown scope value", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:X/C:H/I:H/A:H"},
		{"missing impact metric", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H"},
		{"unknown metric value", "CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
		{"prefix only", "CVSS:3.1"},
		{"truncated pair", "CVSS:3.1/AVN/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if score, ok := cvss3BaseScore(tt.vector); ok {
				t.Errorf("expected %q to be rejected, got %v", tt.vector, score)
			}
		})
	}
}

// Roundup always rounds up to one decimal, except on exact tenths where
// floating point error would otherwise push the score a notch too high.
func TestCVSS3Roundup(t *testing.T) {
	tests := []struct {
		in, want float64
	}{
		{4.02, 4.1},
		{4.0, 4.0},
		{9.76, 9.8},
		{10.0, 10.0},
		{0.0, 0.0},
	}
	for _, tt := range tests {
		if got := cvss3Roundup(tt.in); got != tt.want {
			t.Errorf("cvss3Roundup(%v) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestParseCVSSVector(t *testing.T) {
	m, ok := parseCVSSVector("CVSS:3.1/AV:N/AC:L", "CVSS:3.")
	if !ok {
		t.Fatal("expected a v3 vector to parse")
	}
	if m["AV"] != "N" || m["AC"] != "L" {
		t.Errorf("unexpected metrics: %v", m)
	}
	if _, ok := parseCVSSVector("CVSS:2.0/AV:N", "CVSS:3."); ok {
		t.Error("expected a version prefix mismatch to be rejected")
	}
}
