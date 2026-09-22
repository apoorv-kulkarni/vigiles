package checker

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This is the post-install half of the replay. The .pth fixture is inert and
// lives outside site-packages in the repository. The test copies it into a
// temporary fake site directory and points Vigiles at a stub interpreter; no
// Python code from the fixture is executed.
func TestLiteLLMReplayPostInstallDetectsPthStartupHook(t *testing.T) {
	body, err := os.ReadFile("../../testdata/litellm-replay/post-install/litellm_init.pth")
	if err != nil {
		t.Fatal(err)
	}

	site := t.TempDir()
	pth := filepath.Join(site, "litellm_init.pth")
	writeFileAt(t, pth, string(body))
	stubPython3(t, site)

	sigs := NewHeuristicChecker().checkPthFiles(true)
	if len(sigs) != 1 {
		t.Fatalf("expected one .pth finding, got %+v", sigs)
	}
	got := sigs[0]
	if got.ID != "VIGILES-MALICIOUS-PTH" || got.Severity != "critical" || got.Type != "system-heuristic" {
		t.Fatalf("unexpected replay finding: %+v", got)
	}
	if got.Package != "litellm_init.pth" || !strings.Contains(got.Details, "VIGILES_REPLAY_ONLY") {
		t.Fatalf("replay finding did not identify the planted startup hook: %+v", got)
	}
}
