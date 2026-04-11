package checker

import "testing"

func TestExtractGitHubRepo(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"https://github.com/org/repo", "org/repo"},
		{"https://github.com/org/repo.git", "org/repo"},
		{"git+https://github.com/org/repo", "org/repo"},
		{"git@github.com:org/repo.git", "org/repo"},
		{"https://example.com/notgithub", ""},
	}

	for _, tt := range tests {
		if got := extractGitHubRepo(tt.in); got != tt.want {
			t.Fatalf("extractGitHubRepo(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
