package checker

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/apoorv-kulkarni/vigiles/internal/scanner"
	"github.com/apoorv-kulkarni/vigiles/internal/signal"
)

const (
	osvBatchURL = "https://api.osv.dev/v1/querybatch"
	batchSize   = 100
	httpTimeout = 30 * time.Second
)

type OSVChecker struct {
	client *http.Client
}

func NewOSVChecker() *OSVChecker {
	return &OSVChecker{client: &http.Client{Timeout: httpTimeout}}
}

func (c *OSVChecker) Check(packages []scanner.Package) ([]signal.Signal, error) {
	// Filter out ecosystems we can't meaningfully query.
	queryable := make([]scanner.Package, 0, len(packages))
	for _, pkg := range packages {
		if mapEcosystem(pkg.Ecosystem) != "" {
			queryable = append(queryable, pkg)
		}
	}

	var signals []signal.Signal
	for i := 0; i < len(queryable); i += batchSize {
		end := i + batchSize
		if end > len(queryable) {
			end = len(queryable)
		}
		batch, err := c.checkBatch(queryable[i:end])
		if err != nil {
			return signals, fmt.Errorf("batch %d-%d failed: %w", i, end, err)
		}
		signals = append(signals, batch...)
	}
	return signals, nil
}

func (c *OSVChecker) checkBatch(packages []scanner.Package) ([]signal.Signal, error) {
	queries := make([]osvQuery, len(packages))
	for i, pkg := range packages {
		queries[i] = osvQuery{
			Package: osvPackage{Name: pkg.Name, Ecosystem: mapEcosystem(pkg.Ecosystem)},
			Version: pkg.Version,
		}
	}

	body, err := json.Marshal(osvBatchRequest{Queries: queries})
	if err != nil {
		return nil, err
	}

	resp, err := c.client.Post(osvBatchURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("OSV API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("OSV API returned %d: %s", resp.StatusCode, string(respBody))
	}

	var batchResp osvBatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&batchResp); err != nil {
		return nil, fmt.Errorf("parsing OSV response: %w", err)
	}

	var signals []signal.Signal
	for i, result := range batchResp.Results {
		if len(result.Vulns) == 0 {
			continue
		}
		pkg := packages[i]
		for _, vuln := range result.Vulns {
			signals = append(signals, signal.Signal{
				Package:   pkg.Name,
				Version:   pkg.Version,
				Ecosystem: pkg.Ecosystem,
				Type:      "vulnerability",
				Severity:  classifySeverity(vuln),
				ID:        vuln.ID,
				Summary:   vuln.Summary,
				Details:   fmt.Sprintf("https://osv.dev/vulnerability/%s", vuln.ID),
				Aliases:   vuln.Aliases,
			})
		}
	}
	return signals, nil
}

// mapEcosystem returns the OSV ecosystem name, or "" if we can't query it.
// Homebrew has no OSV ecosystem — we skip it rather than producing false negatives.
func mapEcosystem(eco string) string {
	switch eco {
	case "pip":
		return "PyPI"
	case "npm":
		return "npm"
	default:
		return ""
	}
}

// classifySeverity uses the standard CVSS v3 score ranges when a numeric
// score is available. Falls back to "unknown" rather than guessing.
func classifySeverity(vuln osvVuln) string {
	for _, sev := range vuln.Severity {
		if score, err := strconv.ParseFloat(strings.TrimSpace(sev.Score), 64); err == nil {
			return scoreToSeverity(score)
		}
	}
	return "unknown"
}

func scoreToSeverity(score float64) string {
	score = math.Round(score*10) / 10
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score >= 0.1:
		return "low"
	default:
		return "info"
	}
}

type osvBatchRequest struct{ Queries []osvQuery `json:"queries"` }
type osvQuery struct {
	Package osvPackage `json:"package"`
	Version string     `json:"version"`
}
type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}
type osvBatchResponse struct{ Results []osvResult `json:"results"` }
type osvResult struct{ Vulns []osvVuln `json:"vulns"` }
type osvVuln struct {
	ID       string        `json:"id"`
	Summary  string        `json:"summary"`
	Aliases  []string      `json:"aliases"`
	Severity []osvSeverity `json:"severity"`
}
type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}
