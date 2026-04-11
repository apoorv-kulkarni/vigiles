package reporter

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/apoorv-kulkarni/vigiles/internal/scanner"
	"github.com/apoorv-kulkarni/vigiles/internal/signal"
)

func sarifReport() Report {
	return NewReport("0.3.1", time.Second, []string{"pip"},
		[]scanner.Package{{Name: "requests", Version: "2.32.0", Ecosystem: "pip"}},
		[]signal.Signal{{
			Package: "requests", Version: "2.32.0", Ecosystem: "pip",
			Type: "vulnerability", Severity: "high", ID: "CVE-2026-0001",
			Summary: "Test vuln", Details: "details here",
			Remediation: "upgrade to 2.32.1",
		}},
	)
}

func decodedSARIF(t *testing.T) map[string]any {
	t.Helper()
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, sarifReport()); err != nil {
		t.Fatalf("WriteSARIF error: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("invalid sarif json: %v", err)
	}
	return out
}

func TestWriteSARIF_Version(t *testing.T) {
	doc := decodedSARIF(t)
	if doc["version"] != "2.1.0" {
		t.Fatalf("unexpected sarif version: %v", doc["version"])
	}
}

func TestWriteSARIF_RuleHelpUri(t *testing.T) {
	doc := decodedSARIF(t)
	rule := firstRule(t, doc)
	if rule["helpUri"] != "https://github.com/apoorv-kulkarni/vigiles#signal-types" {
		t.Fatalf("missing or wrong helpUri: %v", rule["helpUri"])
	}
}

func TestWriteSARIF_RuleHelpText(t *testing.T) {
	doc := decodedSARIF(t)
	rule := firstRule(t, doc)
	help, ok := rule["help"].(map[string]any)
	if !ok {
		t.Fatalf("rule missing 'help' field")
	}
	text, _ := help["text"].(string)
	if text == "" {
		t.Fatal("help.text is empty")
	}
	if !contains(text, "details here") {
		t.Errorf("help.text missing details: %q", text)
	}
	if !contains(text, "upgrade to 2.32.1") {
		t.Errorf("help.text missing remediation: %q", text)
	}
	md, _ := help["markdown"].(string)
	if !contains(md, "**Remediation:**") {
		t.Errorf("help.markdown missing bold remediation: %q", md)
	}
}

func TestWriteSARIF_RuleTags(t *testing.T) {
	doc := decodedSARIF(t)
	rule := firstRule(t, doc)
	props, ok := rule["properties"].(map[string]any)
	if !ok {
		t.Fatalf("rule missing 'properties' field")
	}
	tags, ok := props["tags"].([]any)
	if !ok || len(tags) == 0 {
		t.Fatalf("rule missing or empty 'tags': %v", props["tags"])
	}
	wantTags := map[string]bool{"security": true, "supply-chain": true, "vulnerability": true}
	for _, tag := range tags {
		delete(wantTags, tag.(string))
	}
	if len(wantTags) > 0 {
		t.Errorf("missing expected tags: %v", wantTags)
	}
}

// --- helpers ---

func firstRule(t *testing.T, doc map[string]any) map[string]any {
	t.Helper()
	runs := doc["runs"].([]any)
	run := runs[0].(map[string]any)
	driver := run["tool"].(map[string]any)["driver"].(map[string]any)
	rules := driver["rules"].([]any)
	if len(rules) == 0 {
		t.Fatal("no rules in SARIF output")
	}
	return rules[0].(map[string]any)
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		func() bool {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		}())
}
