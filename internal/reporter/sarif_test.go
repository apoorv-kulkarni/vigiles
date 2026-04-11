package reporter

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/apoorv-kulkarni/vigiles/internal/scanner"
	"github.com/apoorv-kulkarni/vigiles/internal/signal"
)

func TestWriteSARIF(t *testing.T) {
	report := NewReport("0.2.1", time.Second, []string{"pip"}, []scanner.Package{{Name: "requests", Version: "2.32.0", Ecosystem: "pip"}}, []signal.Signal{{
		Package: "requests", Version: "2.32.0", Ecosystem: "pip", Type: "vulnerability", Severity: "high", ID: "CVE-2026-0001", Summary: "Test vuln", Details: "details",
	}})

	var buf bytes.Buffer
	if err := WriteSARIF(&buf, report); err != nil {
		t.Fatalf("WriteSARIF error: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid sarif json: %v", err)
	}
	if decoded["version"] != "2.1.0" {
		t.Fatalf("unexpected sarif version: %v", decoded["version"])
	}
}
