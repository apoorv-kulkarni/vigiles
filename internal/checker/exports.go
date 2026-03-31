package checker

// CheckTyposquatExported is the exported version of checkTyposquat for use
// by other packages (e.g., diff).
func CheckTyposquatExported(name string, popular []string) string {
	return checkTyposquat(name, popular)
}

// PopularPipPackages returns the list used for typosquat detection.
func PopularPipPackages() []string { return popularPipPackages }

// PopularNpmPackages returns the list used for typosquat detection.
func PopularNpmPackages() []string { return popularNpmPackages }
