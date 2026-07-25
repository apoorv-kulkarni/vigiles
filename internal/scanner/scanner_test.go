package scanner

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// sortByName makes comparisons deterministic for parsers that iterate a map.
func sortByName(pkgs []Package) {
	sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].Name < pkgs[j].Name })
}

// --- registry ---

func TestRegistryHasAllEcosystems(t *testing.T) {
	want := []string{"pip", "npm", "brew", "cargo", "gomod"}
	for _, name := range want {
		s := Get(name)
		if s == nil {
			t.Errorf("Get(%q) returned nil, expected a registered scanner", name)
			continue
		}
		if s.Name() != name {
			t.Errorf("Get(%q).Name() = %q, want %q", name, s.Name(), name)
		}
	}
}

func TestGetUnknownEcosystem(t *testing.T) {
	if s := Get("composer"); s != nil {
		t.Errorf("expected nil for unregistered ecosystem, got %T", s)
	}
}

type fakeScanner struct{}

func (fakeScanner) Name() string             { return "fake" }
func (fakeScanner) Available() bool          { return false }
func (fakeScanner) Scan() ([]Package, error) { return nil, nil }

func TestRegister(t *testing.T) {
	t.Cleanup(func() { delete(registry, "fake") })

	Register(fakeScanner{})
	if Get("fake") == nil {
		t.Fatal("expected registered scanner to be retrievable")
	}
}

// --- pip ---

func TestParsePipList(t *testing.T) {
	out := []byte(`[{"name": "requests", "version": "2.32.0"}, {"name": "Flask", "version": "3.0.0"}]`)
	direct := map[string]struct{}{"flask": {}}

	pkgs, err := parsePipList(out, direct)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(pkgs))
	}
	sortByName(pkgs)

	// Direct matching is case-insensitive: "Flask" is in the set as "flask".
	if pkgs[0].Name != "Flask" || !pkgs[0].Direct {
		t.Errorf("expected Flask to be direct, got %+v", pkgs[0])
	}
	if pkgs[1].Name != "requests" || pkgs[1].Direct {
		t.Errorf("expected requests to be transitive, got %+v", pkgs[1])
	}
	for _, p := range pkgs {
		if p.Ecosystem != "pip" || p.Location != "PyPI" {
			t.Errorf("unexpected ecosystem/location: %+v", p)
		}
	}
}

func TestParsePipListEmpty(t *testing.T) {
	pkgs, err := parsePipList([]byte(`[]`), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pkgs == nil {
		t.Error("expected non-nil empty slice so callers can range without a nil check")
	}
	if len(pkgs) != 0 {
		t.Errorf("expected 0 packages, got %d", len(pkgs))
	}
}

func TestParsePipListMalformed(t *testing.T) {
	if _, err := parsePipList([]byte(`{not json`), nil); err == nil {
		t.Fatal("expected an error for malformed pip output")
	}
}

func TestParsePipDirect(t *testing.T) {
	set := parsePipDirect([]byte(`[{"name": "Requests"}, {"name": "flask"}]`))
	for _, want := range []string{"requests", "flask"} {
		if _, ok := set[want]; !ok {
			t.Errorf("expected %q in direct set, got %v", want, set)
		}
	}
	if len(set) != 2 {
		t.Errorf("expected 2 entries, got %d", len(set))
	}
}

func TestParsePipDirectMalformedIsEmpty(t *testing.T) {
	set := parsePipDirect([]byte(`not json`))
	if set == nil {
		t.Fatal("expected non-nil set")
	}
	if len(set) != 0 {
		t.Errorf("expected empty set on malformed input, got %v", set)
	}
}

// --- npm ---

func TestParseNpmList(t *testing.T) {
	out := []byte(`{"dependencies": {"axios": {"version": "1.7.2"}, "esbuild": {"version": "0.21.5"}}}`)

	pkgs, err := parseNpmList(out, "global")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(pkgs))
	}
	sortByName(pkgs)

	if pkgs[0].Name != "axios" || pkgs[0].Version != "1.7.2" {
		t.Errorf("unexpected first package: %+v", pkgs[0])
	}
	for _, p := range pkgs {
		if p.Ecosystem != "npm" || p.Location != "global" || !p.Direct {
			t.Errorf("unexpected package fields: %+v", p)
		}
	}
}

func TestParseNpmListNoDependencies(t *testing.T) {
	pkgs, err := parseNpmList([]byte(`{}`), "local")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkgs) != 0 {
		t.Errorf("expected 0 packages, got %d", len(pkgs))
	}
}

func TestParseNpmListMalformed(t *testing.T) {
	if _, err := parseNpmList([]byte(`{"dependencies":`), "local"); err == nil {
		t.Fatal("expected an error for malformed npm output")
	}
}

// --- brew ---

func TestParseBrewInfo(t *testing.T) {
	out := []byte(`{
	  "formulae": [
	    {"name": "jq", "tap": "homebrew/core", "installed": [{"version": "1.7.1"}], "installed_as_dependency": false},
	    {"name": "oniguruma", "tap": "homebrew/core", "installed": [{"version": "6.9.9"}], "installed_as_dependency": true},
	    {"name": "nover", "tap": "homebrew/core", "installed": []}
	  ],
	  "casks": [
	    {"token": "firefox", "version": "127.0", "tap": "homebrew/cask"}
	  ]
	}`)

	pkgs, err := parseBrewInfo(out)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkgs) != 4 {
		t.Fatalf("expected 3 formulae + 1 cask, got %d", len(pkgs))
	}

	byName := map[string]Package{}
	for _, p := range pkgs {
		byName[p.Name] = p
		if p.Ecosystem != "brew" {
			t.Errorf("expected brew ecosystem, got %+v", p)
		}
	}

	if got := byName["jq"]; got.Version != "1.7.1" || !got.Direct {
		t.Errorf("expected jq 1.7.1 direct, got %+v", got)
	}
	if got := byName["oniguruma"]; got.Direct {
		t.Error("expected installed_as_dependency formula to be transitive")
	}
	if got := byName["nover"]; got.Version != "" {
		t.Errorf("expected empty version when installed list is empty, got %q", got.Version)
	}
	if got := byName["firefox"]; got.Version != "127.0" || got.Location != "homebrew/cask" || !got.Direct {
		t.Errorf("unexpected cask mapping: %+v", got)
	}
}

func TestParseBrewInfoMalformed(t *testing.T) {
	if _, err := parseBrewInfo([]byte(`[]`)); err == nil {
		t.Fatal("expected an error when output is not a brew info object")
	}
}

// --- cargo ---

func TestParseCargoList(t *testing.T) {
	// `cargo install --list` puts each crate on a header line and indents its
	// binaries beneath, which must not be mistaken for crates.
	out := []byte("ripgrep v14.1.0:\n    rg\ncargo-edit v0.12.2:\n    cargo-add\n    cargo-rm\n")

	pkgs, err := parseCargoList(out)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("expected 2 crates, got %d: %+v", len(pkgs), pkgs)
	}
	sortByName(pkgs)

	if pkgs[0].Name != "cargo-edit" || pkgs[0].Version != "0.12.2" {
		t.Errorf("unexpected crate: %+v", pkgs[0])
	}
	if pkgs[1].Name != "ripgrep" || pkgs[1].Version != "14.1.0" {
		t.Errorf("unexpected crate: %+v", pkgs[1])
	}
	for _, p := range pkgs {
		if p.Ecosystem != "cargo" || p.Location != "cargo-install" || !p.Direct {
			t.Errorf("unexpected package fields: %+v", p)
		}
	}
}

func TestParseCargoListEmpty(t *testing.T) {
	if _, err := parseCargoList([]byte("")); err == nil {
		t.Fatal("expected an error when no crates are installed")
	}
}

func TestParseCargoListIgnoresBinariesOnly(t *testing.T) {
	if _, err := parseCargoList([]byte("    rg\n    cargo-add\n")); err == nil {
		t.Fatal("expected an error when output has no crate header lines")
	}
}

// --- gomod ---

func TestParseGoModList(t *testing.T) {
	// `go list -m -json all` emits concatenated objects, not an array. The main
	// module carries no Version and must be skipped.
	out := []byte(`{"Path":"github.com/apoorv-kulkarni/vigiles","Main":true,"Dir":"/tmp/x","GoVersion":"1.22.2"}
{"Path":"golang.org/x/mod","Version":"v0.17.0"}
{"Path":"golang.org/x/tools","Version":"v0.21.0"}
{"Path":"example.com/noversion"}`)

	pkgs, err := parseGoModList(out)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("expected 2 modules after skipping main and versionless, got %d: %+v", len(pkgs), pkgs)
	}
	sortByName(pkgs)

	if pkgs[0].Name != "golang.org/x/mod" || pkgs[0].Version != "v0.17.0" {
		t.Errorf("unexpected module: %+v", pkgs[0])
	}
	for _, p := range pkgs {
		if p.Ecosystem != "gomod" || p.Location != "go.mod" || p.Direct {
			t.Errorf("unexpected package fields: %+v", p)
		}
	}
}

func TestParseGoModListEmpty(t *testing.T) {
	if _, err := parseGoModList([]byte("")); err == nil {
		t.Fatal("expected an error when the module graph is empty")
	}
}

func TestParseGoModListMalformed(t *testing.T) {
	if _, err := parseGoModList([]byte(`{"Path":`)); err == nil {
		t.Fatal("expected an error for a truncated module object")
	}
}

// --- availability ---

func TestGoModScannerAvailableRequiresGoMod(t *testing.T) {
	if !(&GoModScanner{}).Available() {
		// A missing go toolchain makes this assertion meaningless.
		if _, err := os.Stat("go.mod"); err != nil {
			t.Skip("no go.mod in the package directory, as expected")
		}
	}

	dir := t.TempDir()
	restore := chdir(t, dir)
	defer restore()

	s := &GoModScanner{}
	if s.Available() {
		t.Error("expected Available() to be false in a directory without go.mod")
	}

	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !s.Available() {
		t.Error("expected Available() to be true once go.mod exists")
	}
}

// --- end-to-end Scan() against stub package managers ---
//
// These tests put a stub executable on PATH so Scan() exercises the real
// subprocess plumbing (argument construction, output threading, error paths)
// without needing the actual package manager installed.

// stubBin writes an executable shell script named name into dir. The script
// echoes altOutput when any argument matches altArg, and output otherwise,
// which lets one stub serve the two different invocations a scanner makes.
//
// Only shell builtins are used, because PATH is reduced to dir and external
// tools like cat would not resolve.
func stubBin(t *testing.T, dir, name, altArg, altOutput, output string) {
	t.Helper()

	emit := func(s string) string {
		if strings.Contains(s, "'") {
			t.Fatalf("stub output must not contain single quotes: %q", s)
		}
		return "echo '" + s + "'\n"
	}

	script := "#!/bin/sh\n"
	if altArg != "" {
		script += "for a in \"$@\"; do\n" +
			"  if [ \"$a\" = \"" + altArg + "\" ]; then\n" +
			"    " + emit(altOutput) +
			"    exit 0\n" +
			"  fi\n" +
			"done\n"
	}
	script += emit(output)

	if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
}

// stubPath creates a directory containing only stub executables and points PATH
// at it. Tests using it must not run in parallel.
func stubPath(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("stub executables rely on a POSIX shell")
	}

	dir := t.TempDir()
	prev, hadPath := os.LookupEnv("PATH")
	if err := os.Setenv("PATH", dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if hadPath {
			os.Setenv("PATH", prev)
			return
		}
		os.Unsetenv("PATH")
	})
	return dir
}

func TestPipScannerScan(t *testing.T) {
	dir := stubPath(t)
	stubBin(t, dir, "pip3",
		"--not-required", `[{"name": "Flask"}]`,
		`[{"name": "Flask", "version": "3.0.0"}, {"name": "werkzeug", "version": "3.0.1"}]`)

	s := &PipScanner{}
	if !s.Available() {
		t.Fatal("expected pip to be available with a stub on PATH")
	}
	if got := s.findPip(); got != "pip3" {
		t.Errorf("findPip() = %q, want pip3", got)
	}

	pkgs, err := s.Scan()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("expected 2 packages, got %d: %+v", len(pkgs), pkgs)
	}
	sortByName(pkgs)

	// Flask appears in --not-required output, so it should be flagged direct.
	if pkgs[0].Name != "Flask" || !pkgs[0].Direct {
		t.Errorf("expected Flask direct, got %+v", pkgs[0])
	}
	if pkgs[1].Name != "werkzeug" || pkgs[1].Direct {
		t.Errorf("expected werkzeug transitive, got %+v", pkgs[1])
	}
}

func TestPipScannerUnavailable(t *testing.T) {
	stubPath(t)

	s := &PipScanner{}
	if s.Available() {
		t.Error("expected pip to be unavailable with an empty PATH")
	}
	if got := s.findPip(); got != "" {
		t.Errorf("findPip() = %q, want empty", got)
	}
	if _, err := s.Scan(); err == nil {
		t.Error("expected Scan to fail when pip is missing")
	}
}

func TestNpmScannerScan(t *testing.T) {
	dir := stubPath(t)
	stubBin(t, dir, "npm",
		"--global", `{"dependencies": {"typescript": {"version": "5.5.3"}}}`,
		`{"dependencies": {"axios": {"version": "1.7.2"}}}`)

	s := &NpmScanner{}
	if !s.Available() {
		t.Fatal("expected npm to be available with a stub on PATH")
	}

	pkgs, err := s.Scan()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("expected global + local packages, got %d: %+v", len(pkgs), pkgs)
	}
	sortByName(pkgs)

	if pkgs[0].Name != "axios" || pkgs[0].Location != "local" {
		t.Errorf("expected axios scanned as local, got %+v", pkgs[0])
	}
	if pkgs[1].Name != "typescript" || pkgs[1].Location != "global" {
		t.Errorf("expected typescript scanned as global, got %+v", pkgs[1])
	}
}

func TestNpmScannerScanNoOutput(t *testing.T) {
	dir := stubPath(t)
	// A stub that exits without writing anything mimics npm failing outright.
	if err := os.WriteFile(filepath.Join(dir, "npm"), []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	pkgs, err := (&NpmScanner{}).Scan()
	if err == nil {
		t.Fatal("expected an error when npm produces no output")
	}
	if pkgs == nil {
		t.Error("expected a non-nil slice alongside the error")
	}
}

func TestBrewScannerScan(t *testing.T) {
	dir := stubPath(t)
	stubBin(t, dir, "brew", "", "",
		`{"formulae": [{"name": "jq", "tap": "homebrew/core", "installed": [{"version": "1.7.1"}]}], "casks": []}`)

	s := &BrewScanner{}
	if !s.Available() {
		t.Fatal("expected brew to be available with a stub on PATH")
	}

	pkgs, err := s.Scan()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkgs) != 1 || pkgs[0].Name != "jq" || pkgs[0].Version != "1.7.1" {
		t.Fatalf("unexpected packages: %+v", pkgs)
	}
}

func TestBrewScannerScanCommandFails(t *testing.T) {
	dir := stubPath(t)
	if err := os.WriteFile(filepath.Join(dir, "brew"), []byte("#!/bin/sh\nexit 2\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	if _, err := (&BrewScanner{}).Scan(); err == nil {
		t.Fatal("expected an error when brew exits non-zero")
	}
}

func TestCargoScannerScan(t *testing.T) {
	dir := stubPath(t)
	stubBin(t, dir, "cargo", "", "", "ripgrep v14.1.0:\n    rg")

	s := &CargoScanner{}
	if !s.Available() {
		t.Fatal("expected cargo to be available with a stub on PATH")
	}

	pkgs, err := s.Scan()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkgs) != 1 || pkgs[0].Name != "ripgrep" || pkgs[0].Version != "14.1.0" {
		t.Fatalf("unexpected packages: %+v", pkgs)
	}
}

func TestGoModScannerScan(t *testing.T) {
	dir := stubPath(t)
	stubBin(t, dir, "go", "", "", `{"Path":"example.com/main","Main":true}
{"Path":"golang.org/x/mod","Version":"v0.17.0"}`)

	restore := chdir(t, dir)
	defer restore()

	s := &GoModScanner{}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !s.Available() {
		t.Fatal("expected gomod to be available with a stub go and a go.mod")
	}

	pkgs, err := s.Scan()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkgs) != 1 || pkgs[0].Name != "golang.org/x/mod" {
		t.Fatalf("expected only the non-main module, got %+v", pkgs)
	}
}

func TestScannersUnavailableOnEmptyPath(t *testing.T) {
	stubPath(t)

	for _, s := range []Scanner{&NpmScanner{}, &BrewScanner{}, &CargoScanner{}, &GoModScanner{}} {
		if s.Available() {
			t.Errorf("expected %s to be unavailable with an empty PATH", s.Name())
		}
	}
}

// chdir switches to dir and returns a function restoring the previous directory.
// Tests using it must not run in parallel.
func chdir(t *testing.T, dir string) func() {
	t.Helper()
	prev, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	return func() {
		if err := os.Chdir(prev); err != nil {
			t.Fatal(err)
		}
	}
}
