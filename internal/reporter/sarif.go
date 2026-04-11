// sarif.go converts Vigiles findings into SARIF 2.1.0 output for code scanning tools.
package reporter

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/apoorv-kulkarni/vigiles/internal/signal"
)

// WriteSARIF writes findings in SARIF 2.1.0 format for GitHub Code Scanning.
func WriteSARIF(w io.Writer, report Report) error {
	rules := map[string]map[string]any{}
	results := make([]map[string]any, 0, len(report.Signals))

	for _, s := range report.Signals {
		if _, ok := rules[s.ID]; !ok {
			rules[s.ID] = map[string]any{
				"id": s.ID,
				"shortDescription": map[string]string{
					"text": s.Summary,
				},
				"fullDescription": map[string]string{
					"text": s.Details,
				},
				"helpUri": "https://github.com/apoorv-kulkarni/vigiles#signal-types",
				"help": map[string]string{
					"text":     ruleHelpText(s),
					"markdown": ruleHelpMarkdown(s),
				},
				"defaultConfiguration": map[string]string{
					"level": sarifLevel(s.Severity),
				},
				"properties": map[string]any{
					"tags": []string{"security", "supply-chain", s.Type},
				},
			}
		}

		results = append(results, map[string]any{
			"ruleId": s.ID,
			"level":  sarifLevel(s.Severity),
			"message": map[string]string{
				"text": fmt.Sprintf("%s (%s %s)", s.Summary, s.Package, s.Version),
			},
			"properties": map[string]any{
				"ecosystem": s.Ecosystem,
				"type":      s.Type,
				"package":   s.Package,
				"version":   s.Version,
				"severity":  s.Severity,
			},
		})
	}

	rulesArr := make([]map[string]any, 0, len(rules))
	for _, r := range rules {
		rulesArr = append(rulesArr, r)
	}

	doc := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]any{{
			"tool": map[string]any{
				"driver": map[string]any{
					"name":           "vigiles",
					"version":        report.Version,
					"informationUri": "https://github.com/apoorv-kulkarni/vigiles",
					"rules":          rulesArr,
				},
			},
			"results": results,
			"invocations": []map[string]any{{
				"executionSuccessful": true,
			}},
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func ruleHelpText(s signal.Signal) string {
	out := s.Details
	if s.Remediation != "" {
		out += "\n\nRemediation: " + s.Remediation
	}
	return out
}

func ruleHelpMarkdown(s signal.Signal) string {
	out := s.Details
	if s.Remediation != "" {
		out += "\n\n**Remediation:** " + s.Remediation
	}
	return out
}

func sarifLevel(sev string) string {
	switch sev {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	case "low", "info", "unknown":
		return "note"
	default:
		return "note"
	}
}

func SignalsToSARIFLevel(s signal.Signal) string {
	return sarifLevel(s.Severity)
}
