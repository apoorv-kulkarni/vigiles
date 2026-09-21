package cmd

import "runtime/debug"

// Version can be set with -ldflags "-X github.com/apoorv-kulkarni/vigiles/cmd.Version=...".
var Version = "dev"

func init() {
	if Version == "dev" {
		if info, ok := debug.ReadBuildInfo(); ok {
			Version = sourceVersion(info)
		}
	}
}

func sourceVersion(info *debug.BuildInfo) string {
	if info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	var revision string
	dirty := false
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			revision = setting.Value
		case "vcs.modified":
			dirty = setting.Value == "true"
		}
	}
	if revision == "" {
		return "dev"
	}
	version := "git-" + revision
	if dirty {
		version += "-dirty"
	}
	return version
}
