package diff

import (
	"testing"

	"github.com/apoorv-kulkarni/vigiles/internal/signal"
)

// This replay models the dependency transition that mattered in the March 24,
// 2026 LiteLLM incident. Registry freshness is injected so the test is
// deterministic and never depends on live PyPI state.
func TestLiteLLMReplayPreInstallFlagsFreshUpgrade(t *testing.T) {
	oldDeps, eco, err := parseFile("../../testdata/litellm-replay/before/requirements.txt")
	if err != nil {
		t.Fatal(err)
	}
	newDeps, newEco, err := parseFile("../../testdata/litellm-replay/after/requirements.txt")
	if err != nil {
		t.Fatal(err)
	}
	if eco != "pip" || newEco != eco {
		t.Fatalf("unexpected ecosystems: old=%s new=%s", eco, newEco)
	}

	recency := &stubRecencyChecker{
		ret: &signal.Signal{
			Package: "litellm", Version: "1.82.8", Ecosystem: "pip",
			Type: "trust-signal", Severity: "info",
			ID:      "VIGILES-RECENTLY-PUBLISHED",
			Summary: "Version was published recently",
		},
	}
	entries := computeDiffWith(oldDeps, newDeps, eco, recency, noopNpmRiskChecker{})
	if len(entries) != 1 {
		t.Fatalf("expected one dependency change, got %+v", entries)
	}
	entry := entries[0]
	if entry.Name != "litellm" || entry.Status != Updated ||
		entry.OldVersion != "==1.82.6" || entry.NewVersion != "==1.82.8" {
		t.Fatalf("unexpected LiteLLM replay diff: %+v", entry)
	}
	if !recency.called || recency.gotName != "litellm" || recency.gotVersion != "1.82.8" || recency.gotEco != "pip" {
		t.Fatalf("pinned upgrade did not receive recency check: %+v", recency)
	}

	found := false
	for _, sig := range entry.Signals {
		if sig.ID == "VIGILES-RECENTLY-PUBLISHED" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected recent-version signal on LiteLLM upgrade: %+v", entry.Signals)
	}
}
