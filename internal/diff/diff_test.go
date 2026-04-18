package diff

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/apoorv-kulkarni/vigiles/internal/signal"
)

type noopRecencyChecker struct{}

func (noopRecencyChecker) CheckVersion(name, version, ecosystem string) *signal.Signal {
	return nil
}

type noopNpmRiskChecker struct{}

func (noopNpmRiskChecker) CheckNewPackage(name, version string) []signal.Signal {
	return nil
}

func TestMain(m *testing.M) {
	origRecency := newRecencyChecker
	origNpmRisk := newNpmRiskChecker
	newRecencyChecker = func() recencyVersionChecker { return noopRecencyChecker{} }
	newNpmRiskChecker = func() npmNewPackageRiskChecker { return noopNpmRiskChecker{} }
	code := m.Run()
	newRecencyChecker = origRecency
	newNpmRiskChecker = origNpmRisk
	os.Exit(code)
}

// --- Requirements.txt parsing ---

func TestParseRequirementsTxt(t *testing.T) {
	content := `
# Comment
requests==2.31.0
flask>=2.0
numpy  # inline comment
boto3==1.28.0
-e git+https://github.com/foo/bar.git
pandas>=1.5,<2.0; python_version >= "3.8"
requests[security]==2.32.0
`
	deps := ParseRequirementsTxt(content)

	expect := map[string]string{
		"requests": "==2.32.0", // extras stripped, last wins
		"flask":    ">=2.0",
		"numpy":    "",
		"boto3":    "==1.28.0",
		"pandas":   ">=1.5,<2.0",
	}
	for name, wantVer := range expect {
		got, ok := deps[name]
		if !ok {
			t.Errorf("missing package %q", name)
		} else if got != wantVer {
			t.Errorf("deps[%q] = %q, want %q", name, got, wantVer)
		}
	}

	// Editable installs must not leak
	for k := range deps {
		if k == "-e" || k == "git+https" {
			t.Errorf("editable install leaked: %q", k)
		}
	}
}

func TestParseRequirementsTxt_Operators(t *testing.T) {
	tests := []struct{ line, wantName, wantVer string }{
		{"requests==2.31.0", "requests", "==2.31.0"},
		{"flask>=2.0", "flask", ">=2.0"},
		{"numpy~=1.24", "numpy", "~=1.24"},
		{"Django!=3.0", "django", "!=3.0"},
		{"boto3>1.0", "boto3", ">1.0"},
		{"click<9.0", "click", "<9.0"},
		{"redis===3.0.0", "redis", "===3.0.0"},
		{"celery", "celery", ""},
	}
	for _, tt := range tests {
		deps := ParseRequirementsTxt(tt.line)
		got, ok := deps[tt.wantName]
		if !ok {
			t.Errorf("line %q: missing %q", tt.line, tt.wantName)
		} else if got != tt.wantVer {
			t.Errorf("line %q: got %q, want %q", tt.line, got, tt.wantVer)
		}
	}
}

func TestParseRequirementsTxt_Empty(t *testing.T) {
	deps := ParseRequirementsTxt("# only comments\n\n  \n")
	if len(deps) != 0 {
		t.Errorf("expected 0 deps from empty file, got %d", len(deps))
	}
}

// --- package.json parsing ---

func TestParsePackageJSON_Simple(t *testing.T) {
	data := []byte(`{
		"dependencies": {"express": "^4.18.2", "lodash": "4.17.21"},
		"devDependencies": {"jest": "^29.7.0"}
	}`)

	deps, err := parsePackageJSON(data)
	if err != nil {
		t.Fatalf("parsePackageJSON: %v", err)
	}

	expect := map[string]string{
		"express": "^4.18.2",
		"lodash":  "4.17.21",
		"jest":    "^29.7.0",
	}
	for name, want := range expect {
		if got := deps[name]; got != want {
			t.Errorf("deps[%q] = %q, want %q", name, got, want)
		}
	}
}

func TestParsePackageJSON_LockfileV3(t *testing.T) {
	data := []byte(`{
		"name": "test-app",
		"lockfileVersion": 3,
		"packages": {
			"": {"name": "test-app", "version": "1.0.0"},
			"node_modules/express": {"version": "4.18.2"},
			"node_modules/@babel/core": {"version": "7.23.9"},
			"node_modules/@babel/core/node_modules/semver": {"version": "6.3.1"},
			"node_modules/accepts": {"version": "1.3.8"}
		}
	}`)

	deps, err := parsePackageJSON(data)
	if err != nil {
		t.Fatalf("parsePackageJSON: %v", err)
	}

	// Root package ("") should be skipped
	if _, ok := deps[""]; ok {
		t.Error("root package should be skipped")
	}
	if _, ok := deps["test-app"]; ok {
		t.Error("root package name should not appear as dep")
	}

	expect := map[string]string{
		"express":     "4.18.2",
		"@babel/core": "7.23.9",
		"semver":      "6.3.1", // nested dep extracted by last node_modules/ segment
		"accepts":     "1.3.8",
	}
	for name, want := range expect {
		got, ok := deps[name]
		if !ok {
			t.Errorf("missing package %q (have: %v)", name, mapKeys(deps))
		} else if got != want {
			t.Errorf("deps[%q] = %q, want %q", name, got, want)
		}
	}
}

func TestParsePackageJSON_ScopedPackages(t *testing.T) {
	data := []byte(`{
		"dependencies": {
			"@types/node": "^20.0.0",
			"@aws-sdk/client-s3": "^3.450.0",
			"@nestjs/core": "^10.0.0"
		}
	}`)

	deps, err := parsePackageJSON(data)
	if err != nil {
		t.Fatalf("parsePackageJSON: %v", err)
	}

	for _, name := range []string{"@types/node", "@aws-sdk/client-s3", "@nestjs/core"} {
		if _, ok := deps[name]; !ok {
			t.Errorf("missing scoped package %q", name)
		}
	}
}

func TestParsePackageJSON_EmptySections(t *testing.T) {
	// Missing dependencies/devDependencies/packages entirely
	data := []byte(`{"name": "empty-app", "version": "1.0.0"}`)

	deps, err := parsePackageJSON(data)
	if err != nil {
		t.Fatalf("parsePackageJSON: %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("expected 0 deps for empty package.json, got %d", len(deps))
	}
}

func TestParsePackageJSON_Malformed(t *testing.T) {
	data := []byte(`{ this is not valid json`)
	_, err := parsePackageJSON(data)
	if err == nil {
		t.Error("expected error for malformed JSON")
	}
}

func TestParsePackageJSON_PartialLockfile(t *testing.T) {
	// Lockfile with packages map but some entries missing version
	data := []byte(`{
		"packages": {
			"": {"name": "root"},
			"node_modules/has-version": {"version": "1.0.0"},
			"node_modules/no-version": {},
			"node_modules/empty-version": {"version": ""}
		}
	}`)

	deps, err := parsePackageJSON(data)
	if err != nil {
		t.Fatalf("parsePackageJSON: %v", err)
	}

	if _, ok := deps["has-version"]; !ok {
		t.Error("should include package with version")
	}
	if _, ok := deps["no-version"]; ok {
		t.Error("should skip package without version field")
	}
	if _, ok := deps["empty-version"]; ok {
		t.Error("should skip package with empty version")
	}
}

// --- Diff computation ---

func TestComputeDiff(t *testing.T) {
	old := map[string]string{"requests": "==2.31.0", "flask": "==2.0.0", "numpy": "==1.24.0"}
	new := map[string]string{"requests": "==2.32.0", "flask": "==2.0.0", "boto3": "==1.28.0"}

	entries := computeDiff(old, new, "pip")

	counts := map[Status]int{}
	for _, e := range entries {
		counts[e.Status]++
	}
	if counts[Added] != 1 || counts[Updated] != 1 || counts[Removed] != 1 {
		t.Errorf("expected 1 add, 1 update, 1 remove; got %v", counts)
	}
}

func TestComputeDiff_NoDifferences(t *testing.T) {
	same := map[string]string{"a": "1.0", "b": "2.0"}
	if entries := computeDiff(same, same, "pip"); len(entries) != 0 {
		t.Errorf("expected 0 entries for identical deps, got %d", len(entries))
	}
}

func TestComputeDiff_Ordering(t *testing.T) {
	old := map[string]string{"a": "1.0"}
	new := map[string]string{"a": "2.0", "b": "1.0"}

	entries := computeDiff(old, new, "pip")
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].Status != Added {
		t.Errorf("first should be Added, got %s", entries[0].Status)
	}
	if entries[1].Status != Updated {
		t.Errorf("second should be Updated, got %s", entries[1].Status)
	}
}

type stubRecencyChecker struct {
	called     bool
	gotName    string
	gotVersion string
	gotEco     string
	ret        *signal.Signal
}

func (s *stubRecencyChecker) CheckVersion(name, version, ecosystem string) *signal.Signal {
	s.called = true
	s.gotName = name
	s.gotVersion = version
	s.gotEco = ecosystem
	return s.ret
}

type stubNpmRiskChecker struct {
	called bool
	name   string
	ver    string
	sigs   []signal.Signal
}

func (s *stubNpmRiskChecker) CheckNewPackage(name, version string) []signal.Signal {
	s.called = true
	s.name = name
	s.ver = version
	return s.sigs
}

func TestComputeDiff_NewDependencySignal(t *testing.T) {
	oldRecency := newRecencyChecker
	oldNpmRisk := newNpmRiskChecker
	t.Cleanup(func() {
		newRecencyChecker = oldRecency
		newNpmRiskChecker = oldNpmRisk
	})

	stub := &stubRecencyChecker{
		ret: &signal.Signal{
			Package: "requests", Version: "2.32.0", Ecosystem: "pip",
			Type: "trust-signal", Severity: "info",
			ID: "VIGILES-RECENTLY-PUBLISHED",
		},
	}
	newRecencyChecker = func() recencyVersionChecker { return stub }

	entries := computeDiff(
		map[string]string{},
		map[string]string{"requests": "==2.32.0"},
		"pip",
	)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Status != Added {
		t.Fatalf("expected Added entry, got %s", entries[0].Status)
	}

	hasNew := false
	hasRecent := false
	for _, sig := range entries[0].Signals {
		if sig.ID == "VIGILES-NEW-DEPENDENCY" {
			hasNew = true
		}
		if sig.ID == "VIGILES-RECENTLY-PUBLISHED" {
			hasRecent = true
		}
	}
	if !hasNew {
		t.Error("expected VIGILES-NEW-DEPENDENCY signal for added dependency")
	}
	if !hasRecent {
		t.Error("expected recency signal for exact pinned new pip dependency")
	}
	if !stub.called {
		t.Fatal("expected recency checker to be called")
	}
	if stub.gotName != "requests" || stub.gotVersion != "2.32.0" || stub.gotEco != "pip" {
		t.Errorf("unexpected recency check call: got %s %s %s", stub.gotName, stub.gotVersion, stub.gotEco)
	}
}

func TestComputeDiff_RecencySkippedForNonPinnedVersion(t *testing.T) {
	oldRecency := newRecencyChecker
	oldNpmRisk := newNpmRiskChecker
	t.Cleanup(func() {
		newRecencyChecker = oldRecency
		newNpmRiskChecker = oldNpmRisk
	})

	stub := &stubRecencyChecker{}
	newRecencyChecker = func() recencyVersionChecker { return stub }

	entries := computeDiff(
		map[string]string{},
		map[string]string{"requests": ">=2.32.0"},
		"pip",
	)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if stub.called {
		t.Fatal("did not expect recency checker call for non-pinned pip version")
	}
}

func TestComputeDiff_NewNpmRiskSignal(t *testing.T) {
	oldRecency := newRecencyChecker
	oldNpmRisk := newNpmRiskChecker
	t.Cleanup(func() {
		newRecencyChecker = oldRecency
		newNpmRiskChecker = oldNpmRisk
	})

	riskStub := &stubNpmRiskChecker{
		sigs: []signal.Signal{{
			Package: "plain-crypto-js", Version: "4.2.1", Ecosystem: "npm",
			Type: "heuristic", Severity: "high", ID: "VIGILES-SUSPICIOUS-NEW-NPM-PACKAGE",
		}},
	}
	newNpmRiskChecker = func() npmNewPackageRiskChecker { return riskStub }

	entries := computeDiff(
		map[string]string{"axios": "1.14.0"},
		map[string]string{"axios": "1.14.1", "plain-crypto-js": "4.2.1"},
		"npm",
	)

	var added Entry
	foundAdded := false
	for _, e := range entries {
		if e.Name == "plain-crypto-js" && e.Status == Added {
			added = e
			foundAdded = true
			break
		}
	}
	if !foundAdded {
		t.Fatal("expected added plain-crypto-js entry")
	}
	if !riskStub.called || riskStub.name != "plain-crypto-js" || riskStub.ver != "4.2.1" {
		t.Fatalf("expected npm risk checker called for added dep, got called=%v %s@%s", riskStub.called, riskStub.name, riskStub.ver)
	}
	hasSignal := false
	for _, sig := range added.Signals {
		if sig.ID == "VIGILES-SUSPICIOUS-NEW-NPM-PACKAGE" {
			hasSignal = true
		}
	}
	if !hasSignal {
		t.Fatal("expected suspicious new npm package signal on added dependency")
	}
}

func TestEvaluateNewNpmScriptRisk(t *testing.T) {
	sigs := evaluateNewNpmScriptRisk("plain-crypto-js", "4.2.1", map[string]string{
		"postinstall": "node -e \"eval(Buffer.from(payload,'base64').toString())\"",
	})
	if len(sigs) == 0 {
		t.Fatal("expected suspicious script signal")
	}
	if sigs[0].ID != "VIGILES-SUSPICIOUS-NEW-NPM-PACKAGE" || sigs[0].Severity != "high" {
		t.Fatalf("unexpected signal: %+v", sigs[0])
	}

	popular := evaluateNewNpmScriptRisk("axios", "1.14.1", map[string]string{
		"postinstall": "node -e \"eval(Buffer.from(payload,'base64').toString())\"",
	})
	if len(popular) != 0 {
		t.Fatal("did not expect high-risk signal for popular npm package from this rule")
	}

	benign := evaluateNewNpmScriptRisk("new-helper", "1.0.0", map[string]string{
		"install": "node-gyp rebuild",
	})
	if len(benign) != 0 {
		t.Fatal("did not expect signal for non-obfuscated install script")
	}
}

func TestNormalizeVersionForRecency(t *testing.T) {
	tests := []struct {
		version   string
		ecosystem string
		want      string
		ok        bool
	}{
		{version: "==2.32.0", ecosystem: "pip", want: "2.32.0", ok: true},
		{version: "===2.32.0", ecosystem: "pip", want: "2.32.0", ok: true},
		{version: ">=2.32.0", ecosystem: "pip", ok: false},
		{version: "^1.2.3", ecosystem: "npm", ok: false},
	}
	for _, tt := range tests {
		got, ok := normalizeVersionForRecency(tt.version, tt.ecosystem)
		if ok != tt.ok || got != tt.want {
			t.Errorf("normalizeVersionForRecency(%q, %q) = (%q, %v), want (%q, %v)",
				tt.version, tt.ecosystem, got, ok, tt.want, tt.ok)
		}
	}
}

// --- File-based diff tests using testdata fixtures ---

func TestDiff_FixtureRequirements(t *testing.T) {
	result, err := Run("../../testdata/requirements-pinned.txt", "../../testdata/requirements-mixed.txt")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if result.Ecosystem != "pip" {
		t.Errorf("ecosystem = %q, want pip", result.Ecosystem)
	}
	if len(result.Entries) == 0 {
		t.Fatal("expected entries in diff")
	}

	// anthropic and celery should be added, flask changed, boto3 removed
	statuses := map[string]Status{}
	for _, e := range result.Entries {
		statuses[e.Name] = e.Status
	}
	if statuses["anthropic"] != Added {
		t.Errorf("anthropic should be Added, got %s", statuses["anthropic"])
	}
	if statuses["celery"] != Added {
		t.Errorf("celery should be Added, got %s", statuses["celery"])
	}
	if statuses["boto3"] != Removed {
		t.Errorf("boto3 should be Removed, got %s", statuses["boto3"])
	}
}

func TestDiff_FixturePackageJSON(t *testing.T) {
	result, err := Run("../../testdata/package.json", "../../testdata/package-updated.json")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if result.Ecosystem != "npm" {
		t.Errorf("ecosystem = %q, want npm", result.Ecosystem)
	}

	statuses := map[string]Status{}
	for _, e := range result.Entries {
		statuses[e.Name] = e.Status
	}
	if statuses["zod"] != Added {
		t.Errorf("zod should be Added, got %s", statuses["zod"])
	}
	if statuses["lodash"] != Removed {
		t.Errorf("lodash should be Removed, got %s", statuses["lodash"])
	}
}

func TestDiff_FixtureEmpty(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "requirements-old.txt")
	b := filepath.Join(dir, "requirements-new.txt")
	os.WriteFile(a, []byte("# empty\n"), 0644)
	os.WriteFile(b, []byte("# also empty\n"), 0644)

	result, err := Run(a, b)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(result.Entries) != 0 {
		t.Errorf("expected 0 entries for empty→empty diff, got %d", len(result.Entries))
	}
}

func TestDiff_MalformedJSON(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "package.json")
	os.WriteFile(good, []byte(`{"dependencies":{"a":"1.0"}}`), 0644)

	_, err := Run(good, "../../testdata/malformed.json")
	if err == nil {
		t.Error("expected error for malformed JSON input")
	}
}

func TestDiff_NonexistentFile(t *testing.T) {
	_, err := Run("/nonexistent/file.txt", "/also/nonexistent.txt")
	if err == nil {
		t.Error("expected error for nonexistent files")
	}
}

func TestDiff_MixedEcosystems(t *testing.T) {
	dir := t.TempDir()
	txt := filepath.Join(dir, "old.txt")
	js := filepath.Join(dir, "new.json")
	os.WriteFile(txt, []byte("requests==1.0\n"), 0644)
	os.WriteFile(js, []byte(`{"dependencies":{"a":"1.0"}}`), 0644)

	// Can't diff different file types — but since both get auto-detected
	// and one is .txt (pip) and one is .json (npm), this should error
	_, err := Run(txt, js)
	if err == nil {
		t.Error("expected error for mismatched ecosystems")
	}
}

// --- npm install scripts from fixture ---

func TestFixture_PackageWithScripts(t *testing.T) {
	data, err := os.ReadFile("../../testdata/package-with-scripts.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}

	// Just verify it parses as valid package.json
	deps, err := parsePackageJSON(data)
	if err != nil {
		t.Fatalf("parsing fixture: %v", err)
	}
	// package-with-scripts.json has empty dependencies
	if len(deps) != 0 {
		t.Errorf("expected 0 deps from scripts fixture, got %d", len(deps))
	}
}

func mapKeys(m map[string]string) []string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}
