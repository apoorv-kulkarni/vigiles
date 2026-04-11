package scanner

// Package represents an installed dependency across any ecosystem.
type Package struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"` // "pip", "npm", "brew"
	Location  string `json:"location"`  // install path or source
	Direct    bool   `json:"direct"`    // true if directly installed (not transitive)
}

// Scanner is the interface every ecosystem scanner implements.
type Scanner interface {
	// Name returns the ecosystem identifier (e.g. "pip", "npm", "brew").
	Name() string

	// Available returns true if the package manager is installed on this system.
	Available() bool

	// Scan inventories all installed packages.
	Scan() ([]Package, error)
}

// registry holds all registered scanners.
var registry = map[string]Scanner{}

// Register adds a scanner to the registry.
func Register(s Scanner) {
	registry[s.Name()] = s
}

// Get returns the scanner for the given ecosystem, or nil.
func Get(name string) Scanner {
	return registry[name]
}

func init() {
	Register(&PipScanner{})
	Register(&NpmScanner{})
	Register(&BrewScanner{})
	Register(&CargoScanner{})
	Register(&GoModScanner{})
}
