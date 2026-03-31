package reporter

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/apoorv-kulkarni/vigiles/internal/scanner"
	"github.com/apoorv-kulkarni/vigiles/internal/signal"
)

// Report is the full scan output, serialized to JSON.
type Report struct {
	Version    string            `json:"version"`
	Timestamp  time.Time         `json:"timestamp"`
	DurationMs int64             `json:"duration_ms"`
	Ecosystems []string          `json:"ecosystems"`
	Packages   []scanner.Package `json:"packages"`
	Signals    []signal.Signal   `json:"signals"`
	Summary    signal.Summary    `json:"summary"`
}

// NewReport constructs a Report with computed summary.
func NewReport(version string, elapsed time.Duration, ecosystems []string,
	packages []scanner.Package, signals []signal.Signal) Report {
	if signals == nil {
		signals = []signal.Signal{}
	}
	if packages == nil {
		packages = []scanner.Package{}
	}
	signal.SortSignals(signals)
	return Report{
		Version:    version,
		Timestamp:  time.Now().UTC(),
		DurationMs: elapsed.Milliseconds(),
		Ecosystems: ecosystems,
		Packages:   packages,
		Signals:    signals,
		Summary:    signal.Summarize(signals),
	}
}

// WriteJSON writes a stable JSON report to w.
func WriteJSON(w io.Writer, report Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

// PrintTable renders signals as a formatted terminal table.
func PrintTable(w io.Writer, report Report) {
	fmt.Fprintln(w)
	printBanner(w)

	if len(report.Signals) == 0 {
		fmt.Fprintf(w, "\n  ✅ No issues found across %d packages (%s)\n\n",
			len(report.Packages), strings.Join(report.Ecosystems, ", "))
		printStats(w, report)
		return
	}

	signal.SortSignals(report.Signals)
	printPackageSummary(w, report.Signals)

	bySeverity := map[string][]signal.Signal{}
	for _, s := range report.Signals {
		bySeverity[s.Severity] = append(bySeverity[s.Severity], s)
	}

	for _, sev := range signal.ValidSeverities {
		sigs, ok := bySeverity[sev]
		if !ok {
			continue
		}
		icon := severityIcon(sev)
		fmt.Fprintf(w, "\n  %s %s (%d)\n", icon, strings.ToUpper(sev), len(sigs))
		fmt.Fprintf(w, "  %s\n", strings.Repeat("─", 70))

		for _, s := range sigs {
			fmt.Fprintf(w, "  %-20s %-12s %-8s %s\n",
				truncateStr(s.Package, 20),
				truncateStr(s.Version, 12),
				s.Ecosystem,
				s.ID,
			)
			fmt.Fprintf(w, "  %s%s\n", strings.Repeat(" ", 20), s.Summary)
			if s.Details != "" {
				if strings.HasPrefix(s.Details, "http") {
					fmt.Fprintf(w, "  %s↗  %s\n", strings.Repeat(" ", 20), s.Details)
				} else {
					for _, line := range wordWrap(s.Details, 58) {
						fmt.Fprintf(w, "  %s%s\n", strings.Repeat(" ", 20), line)
					}
				}
			}
			fmt.Fprintln(w)
		}
	}

	printStats(w, report)
}

type packageSummaryRow struct {
	Package         string
	Ecosystem       string
	Count           int
	Vulnerabilities int
	Heuristics      int
	TrustSignals    int
	WorstSeverity   string
}

func printPackageSummary(w io.Writer, sigs []signal.Signal) {
	byPackage := map[string]*packageSummaryRow{}
	for _, s := range sigs {
		key := s.Ecosystem + "/" + s.Package
		row, ok := byPackage[key]
		if !ok {
			row = &packageSummaryRow{
				Package:       s.Package,
				Ecosystem:     s.Ecosystem,
				WorstSeverity: s.Severity,
			}
			byPackage[key] = row
		}

		row.Count++
		if signal.SeverityOrder(s.Severity) < signal.SeverityOrder(row.WorstSeverity) {
			row.WorstSeverity = s.Severity
		}
		switch s.Type {
		case "vulnerability":
			row.Vulnerabilities++
		case "heuristic", "system-heuristic":
			row.Heuristics++
		case "trust-signal":
			row.TrustSignals++
		}
	}

	rows := make([]*packageSummaryRow, 0, len(byPackage))
	for _, row := range byPackage {
		rows = append(rows, row)
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Count != rows[j].Count {
			return rows[i].Count > rows[j].Count
		}
		if rows[i].WorstSeverity != rows[j].WorstSeverity {
			return signal.SeverityOrder(rows[i].WorstSeverity) < signal.SeverityOrder(rows[j].WorstSeverity)
		}
		if rows[i].Ecosystem != rows[j].Ecosystem {
			return rows[i].Ecosystem < rows[j].Ecosystem
		}
		return rows[i].Package < rows[j].Package
	})

	fmt.Fprintln(w, "\n  Top Packages by Findings")
	fmt.Fprintf(w, "  %s\n", strings.Repeat("─", 70))
	for _, row := range rows {
		parts := []string{}
		if row.Vulnerabilities > 0 {
			parts = append(parts, fmt.Sprintf("%d vuln", row.Vulnerabilities))
		}
		if row.Heuristics > 0 {
			parts = append(parts, fmt.Sprintf("%d heuristic", row.Heuristics))
		}
		if row.TrustSignals > 0 {
			parts = append(parts, fmt.Sprintf("%d trust", row.TrustSignals))
		}
		fmt.Fprintf(w, "  %-20s %-8s %3d  %s %s\n",
			truncateStr(row.Package, 20),
			row.Ecosystem,
			row.Count,
			severityIcon(row.WorstSeverity),
			strings.Join(parts, ", "),
		)
	}
}

// PrintSummary renders a compact one-line-per-signal summary.
func PrintSummary(w io.Writer, report Report) {
	fmt.Fprintln(w)
	printBanner(w)

	if len(report.Signals) == 0 {
		fmt.Fprintf(w, "\n  ✅ Clean: %d packages, 0 findings\n\n", len(report.Packages))
		return
	}

	signal.SortSignals(report.Signals)

	fmt.Fprintf(w, "\n  %-4s %-22s %-12s %-8s %s\n", "SEV", "PACKAGE", "VERSION", "ECO", "ID")
	fmt.Fprintf(w, "  %s\n", strings.Repeat("─", 70))

	for _, s := range report.Signals {
		fmt.Fprintf(w, "  %s  %-22s %-12s %-8s %s\n",
			severityIcon(s.Severity),
			truncateStr(s.Package, 22),
			truncateStr(s.Version, 12),
			s.Ecosystem,
			s.ID,
		)
	}
	fmt.Fprintln(w)
	printStats(w, report)
}

func printBanner(w io.Writer) {
	fmt.Fprintln(w, "  ╔═══════════════════════════════════════════════════╗")
	fmt.Fprintln(w, "  ║  vigiles — the night watch for your dependencies  ║")
	fmt.Fprintln(w, "  ╚═══════════════════════════════════════════════════╝")
}

func printStats(w io.Writer, report Report) {
	s := report.Summary
	ecoCount := map[string]int{}
	for _, pkg := range report.Packages {
		ecoCount[pkg.Ecosystem]++
	}

	fmt.Fprintln(w, "  ── Summary ──────────────────────────────────")
	fmt.Fprintf(w, "  Packages scanned: %d", len(report.Packages))
	for eco, count := range ecoCount {
		fmt.Fprintf(w, " (%s: %d)", eco, count)
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  Findings:         %d total", s.Total)
	if s.Vulnerabilities > 0 {
		fmt.Fprintf(w, " (%d vuln)", s.Vulnerabilities)
	}
	if s.Heuristics > 0 {
		fmt.Fprintf(w, " (%d heuristic)", s.Heuristics)
	}
	if s.TrustSignals > 0 {
		fmt.Fprintf(w, " (%d trust-signal)", s.TrustSignals)
	}
	fmt.Fprintln(w)
	if s.Total > 0 {
		fmt.Fprintf(w, "  Severity:         ")
		parts := []string{}
		for _, sev := range []string{"critical", "high", "medium", "low", "info", "unknown"} {
			if n := s.BySeverity[sev]; n > 0 {
				parts = append(parts, fmt.Sprintf("%s %d %s", severityIcon(sev), n, sev))
			}
		}
		fmt.Fprintln(w, strings.Join(parts, "  "))
	}
	fmt.Fprintf(w, "  Duration:         %dms\n", report.DurationMs)
	fmt.Fprintln(w, "  ─────────────────────────────────────────────")
	fmt.Fprintln(w)
}

func severityIcon(sev string) string {
	switch sev {
	case "critical":
		return "🔴"
	case "high":
		return "🟠"
	case "medium":
		return "🟡"
	case "low":
		return "🔵"
	case "info":
		return "ℹ️"
	default:
		return "⚪"
	}
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-1] + "…"
}

func wordWrap(text string, width int) []string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return nil
	}
	var lines []string
	current := words[0]
	for _, word := range words[1:] {
		if len(current)+1+len(word) > width {
			lines = append(lines, current)
			current = word
		} else {
			current += " " + word
		}
	}
	return append(lines, current)
}
