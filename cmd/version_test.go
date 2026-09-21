package cmd

import (
	"runtime/debug"
	"testing"
)

func TestSourceVersion(t *testing.T) {
	for _, tc := range []struct {
		name, module, revision, modified, want string
	}{
		{"module release", "v0.4.0", "abc", "true", "v0.4.0"},
		{"module prerelease", "v0.4.0-rc.1", "", "", "v0.4.0-rc.1"},
		{"source checkout", "(devel)", "abc", "false", "git-abc"},
		{"dirty checkout", "(devel)", "abc", "true", "git-abc-dirty"},
		{"source archive", "(devel)", "", "", "dev"},
		{"missing metadata", "", "", "", "dev"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			info := &debug.BuildInfo{
				Main: debug.Module{Version: tc.module},
				Settings: []debug.BuildSetting{
					{Key: "vcs.revision", Value: tc.revision},
					{Key: "vcs.modified", Value: tc.modified},
				},
			}
			if got := sourceVersion(info); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
