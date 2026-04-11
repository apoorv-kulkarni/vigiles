package cmd

import "testing"

func TestParseEcosystems_Valid(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"pip", 1},
		{"pip,npm", 2},
		{"pip, npm, brew", 3},
		{"cargo,gomod", 2},
		{" pip , npm ", 2},
	}

	for _, tt := range tests {
		ecos, err := parseEcosystems(tt.input, false)
		if err != nil {
			t.Errorf("parseEcosystems(%q) error: %v", tt.input, err)
			continue
		}
		if len(ecos) != tt.want {
			t.Errorf("parseEcosystems(%q) = %d ecosystems, want %d", tt.input, len(ecos), tt.want)
		}
	}
}

func TestParseEcosystems_Invalid(t *testing.T) {
	tests := []string{
		"pip,nuget",
		"invalid",
		"pip,,invalid",
	}

	for _, input := range tests {
		_, err := parseEcosystems(input, false)
		if err == nil {
			t.Errorf("parseEcosystems(%q) should have returned error", input)
		}
	}
}

func TestParseEcosystems_Empty(t *testing.T) {
	_, err := parseEcosystems(",,,", false)
	if err == nil {
		t.Error("parseEcosystems with only commas should return error")
	}
}

func TestParseEcosystems_TrimsWhitespace(t *testing.T) {
	ecos, err := parseEcosystems("  pip  ,  npm  ", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ecos) != 2 {
		t.Fatalf("expected 2 ecosystems, got %d", len(ecos))
	}
	if ecos[0] != "pip" || ecos[1] != "npm" {
		t.Errorf("expected [pip npm], got %v", ecos)
	}
}

func TestValidFormats(t *testing.T) {
	for _, f := range []string{"table", "json", "summary", "sarif"} {
		if !validFormats[f] {
			t.Errorf("format %q should be valid", f)
		}
	}
	for _, f := range []string{"xml", "csv", "yaml", ""} {
		if validFormats[f] {
			t.Errorf("format %q should be invalid", f)
		}
	}
}
