package cmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/apoorv-kulkarni/vigiles/internal/checker"
	"github.com/apoorv-kulkarni/vigiles/internal/diff"
	"github.com/apoorv-kulkarni/vigiles/internal/reporter"
	"github.com/apoorv-kulkarni/vigiles/internal/scanner"
	"github.com/apoorv-kulkarni/vigiles/internal/signal"
)

const Version = "0.2.1"

// Exit codes:
//   0 — scan completed, no findings
//   1 — scan completed, findings exist
//   2 — runtime/usage error
const (
	ExitClean    = 0
	ExitFindings = 1
	ExitError    = 2
)

// validEcosystems is the set of supported ecosystem names.
var validEcosystems = map[string]bool{"pip": true, "npm": true, "brew": true}

// validFormats is the set of supported output formats.
var validFormats = map[string]bool{"table": true, "json": true, "summary": true}

// Execute parses args and runs the appropriate subcommand.
// Returns an exit code.
func Execute() int {
	if len(os.Args) < 2 {
		printUsage()
		return ExitClean
	}

	switch os.Args[1] {
	case "scan":
		return runScanCmd(os.Args[2:])
	case "diff":
		return runDiffCmd(os.Args[2:])
	case "version":
		fmt.Printf("vigiles %s\n", Version)
		return ExitClean
	case "help", "-h", "--help":
		printUsage()
		return ExitClean
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown command %q\nRun 'vigiles help' for usage.\n", os.Args[1])
		return ExitError
	}
}

func runScanCmd(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	ecosystems := fs.String("ecosystems", "auto", "Comma-separated: pip,npm,brew or 'auto'")
	outputFmt := fs.String("format", "table", "Output format: table, json, summary")
	outputFile := fs.String("output", "", "Write results to file (default: stdout)")
	skipVuln := fs.Bool("skip-vuln", false, "Skip OSV vulnerability check")
	skipHeuristic := fs.Bool("skip-heuristic", false, "Skip heuristic checks")
	skipRecency := fs.Bool("skip-recency", false, "Skip recently-published check")
	verbose := fs.Bool("verbose", false, "Show detailed progress")

	if err := fs.Parse(args); err != nil {
		return ExitError
	}

	// H: Validate --format
	if !validFormats[*outputFmt] {
		fmt.Fprintf(os.Stderr, "Error: invalid format %q (valid: table, json, summary)\n", *outputFmt)
		return ExitError
	}

	// H: Validate --ecosystems
	ecoList, err := parseEcosystems(*ecosystems, *verbose)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return ExitError
	}

	// Progress goes to stderr for json format to keep stdout clean
	progress := io.Discard
	if *outputFmt != "json" || *outputFile != "" {
		progress = os.Stderr
	}
	if *verbose {
		progress = os.Stderr
	}

	return runScan(ecoList, *outputFmt, *outputFile, *skipVuln, *skipHeuristic, *skipRecency, *verbose, progress)
}

func runScan(ecoList []string, outputFmt, outputFile string, skipVuln, skipHeuristic, skipRecency, verbose bool, progress io.Writer) int {
	startTime := time.Now()

	if len(ecoList) == 0 {
		fmt.Fprintln(progress, "⚠  No supported package managers detected on this system.")
		return ExitClean
	}

	if verbose {
		fmt.Fprintf(progress, "Scanning ecosystems: %s\n", strings.Join(ecoList, ", "))
	}

	// Phase 1: Inventory
	var allPackages []scanner.Package
	for _, eco := range ecoList {
		s := scanner.Get(eco)
		if s == nil {
			continue
		}
		fmt.Fprintf(progress, "▸ Scanning %s packages...\n", eco)
		pkgs, err := s.Scan()
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ⚠  %s scan failed: %v\n", eco, err)
			continue
		}
		fmt.Fprintf(progress, "  Found %d packages\n", len(pkgs))
		allPackages = append(allPackages, pkgs...)
	}

	// D: Deduplicate packages (npm local+global can overlap)
	before := len(allPackages)
	allPackages = deduplicatePackages(allPackages)
	if verbose && before != len(allPackages) {
		fmt.Fprintf(progress, "  Deduplicated %d → %d packages\n", before, len(allPackages))
	}

	if len(allPackages) == 0 {
		fmt.Fprintln(progress, "No packages found to audit.")
		return ExitClean
	}

	// Phase 2: Checks
	var signals []signal.Signal

	if !skipVuln {
		t := time.Now()
		fmt.Fprintf(progress, "▸ Checking %d packages against OSV...\n", len(allPackages))
		vulns, err := checker.NewOSVChecker().Check(allPackages)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ⚠  OSV check failed: %v\n", err)
		} else {
			fmt.Fprintf(progress, "  Found %d vulnerabilities (%s)\n", len(vulns), time.Since(t).Round(time.Millisecond))
			signals = append(signals, vulns...)
		}
	}

	if !skipHeuristic {
		t := time.Now()
		fmt.Fprintf(progress, "▸ Running heuristic checks...\n")
		h := checker.NewHeuristicChecker().Check(allPackages)
		fmt.Fprintf(progress, "  Found %d heuristic signals (%s)\n", len(h), time.Since(t).Round(time.Millisecond))
		signals = append(signals, h...)

		if hasEcosystem(ecoList, "npm") {
			if _, err := os.Stat("node_modules"); err == nil {
				fmt.Fprintf(progress, "▸ Checking npm install scripts...\n")
				ns := checker.CheckNpmInstallScriptsInNodeModules("node_modules")
				if len(ns) > 0 {
					fmt.Fprintf(progress, "  Found %d packages with install scripts\n", len(ns))
				}
				signals = append(signals, ns...)
			}
		}
	}

	if !skipRecency {
		fmt.Fprintf(progress, "▸ Checking for recently published versions...\n")
		rc := checker.NewRecencyChecker()
		r, stats := rc.CheckWithStats(allPackages)
		if stats.Checked > 0 {
			fmt.Fprintf(progress, "  Checked %d PyPI packages (%s)", stats.Checked, stats.Duration.Round(time.Millisecond))
			if stats.Errors > 0 {
				fmt.Fprintf(progress, ", %d unavailable", stats.Errors)
			}
			if stats.Signals > 0 {
				fmt.Fprintf(progress, ", %d recently published", stats.Signals)
			}
			fmt.Fprintln(progress)
		}
		signals = append(signals, r...)
	}

	// D: Deduplicate signals
	signals = deduplicateSignals(signals)

	// Phase 3: Report
	report := reporter.NewReport(Version, time.Since(startTime), ecoList, allPackages, signals)

	output, cleanup, err := openOutput(outputFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return ExitError
	}
	defer cleanup()

	switch outputFmt {
	case "json":
		if err := reporter.WriteJSON(output, report); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing JSON: %v\n", err)
			return ExitError
		}
	case "summary":
		reporter.PrintSummary(output, report)
	default:
		reporter.PrintTable(output, report)
	}

	if len(signals) > 0 {
		return ExitFindings
	}
	return ExitClean
}

// deduplicatePackages removes duplicate packages by name+version+ecosystem.
// Keeps the first occurrence (preserves ordering from earlier scanners).
func deduplicatePackages(pkgs []scanner.Package) []scanner.Package {
	seen := map[string]bool{}
	var result []scanner.Package
	for _, p := range pkgs {
		key := p.Ecosystem + "/" + p.Name + "@" + p.Version
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, p)
	}
	return result
}

// deduplicateSignals removes duplicate signals by ID+package+version.
func deduplicateSignals(sigs []signal.Signal) []signal.Signal {
	seen := map[string]bool{}
	var result []signal.Signal
	for _, s := range sigs {
		key := s.ID + "/" + s.Package + "@" + s.Version
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, s)
	}
	return result
}

func runDiffCmd(args []string) int {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	outputFmt := fs.String("format", "table", "Output format: table, json")

	if err := fs.Parse(args); err != nil {
		return ExitError
	}

	remaining := fs.Args()
	if len(remaining) != 2 {
		fmt.Fprintln(os.Stderr, "Usage: vigiles diff [--format table|json] <old-file> <new-file>")
		return ExitError
	}

	if !validFormats[*outputFmt] {
		fmt.Fprintf(os.Stderr, "Error: invalid format %q\n", *outputFmt)
		return ExitError
	}

	result, err := diff.Run(remaining[0], remaining[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return ExitError
	}

	switch *outputFmt {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(result); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return ExitError
		}
	default:
		printDiffTable(os.Stdout, result)
	}

	// Exit 1 if there are any changes with signals
	for _, e := range result.Entries {
		if len(e.Signals) > 0 {
			return ExitFindings
		}
	}
	if len(result.Entries) > 0 {
		return ExitClean // changes exist but no risk signals
	}
	return ExitClean
}

func printDiffTable(w io.Writer, result *diff.Result) {
	fmt.Fprintf(w, "\n  Diff: %s → %s (%s)\n", result.OldFile, result.NewFile, result.Ecosystem)
	fmt.Fprintf(w, "  %s\n\n", strings.Repeat("─", 60))

	if len(result.Entries) == 0 {
		fmt.Fprintln(w, "  No changes detected.")
		return
	}

	for _, e := range result.Entries {
		var icon, ver string
		switch e.Status {
		case diff.Added:
			icon = "+"
			ver = e.NewVersion
		case diff.Removed:
			icon = "-"
			ver = e.OldVersion
		case diff.Updated:
			icon = "~"
			ver = fmt.Sprintf("%s → %s", e.OldVersion, e.NewVersion)
		}

		fmt.Fprintf(w, "  %s %-30s %s\n", icon, e.Name, ver)
		for _, sig := range e.Signals {
			fmt.Fprintf(w, "    %s %s: %s\n", severityIcon(sig.Severity), sig.ID, sig.Summary)
		}
	}
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

// --- Helpers ---

func parseEcosystems(input string, verbose bool) ([]string, error) {
	if input == "auto" {
		var detected []string
		for _, eco := range []string{"pip", "npm", "brew"} {
			s := scanner.Get(eco)
			if s != nil && s.Available() {
				detected = append(detected, eco)
				if verbose {
					fmt.Fprintf(os.Stderr, "  ✓ Detected %s\n", eco)
				}
			} else if verbose {
				fmt.Fprintf(os.Stderr, "  ✗ %s not found\n", eco)
			}
		}
		return detected, nil
	}

	var ecos []string
	for _, e := range strings.Split(input, ",") {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if !validEcosystems[e] {
			return nil, fmt.Errorf("invalid ecosystem %q (valid: pip, npm, brew)", e)
		}
		ecos = append(ecos, e)
	}
	if len(ecos) == 0 {
		return nil, fmt.Errorf("no ecosystems specified")
	}
	return ecos, nil
}

func openOutput(path string) (io.Writer, func(), error) {
	if path == "" {
		return os.Stdout, func() {}, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot create output file: %w", err)
	}
	return f, func() { f.Close() }, nil
}

func hasEcosystem(ecoList []string, eco string) bool {
	for _, e := range ecoList {
		if e == eco {
			return true
		}
	}
	return false
}

func printUsage() {
	fmt.Print(`vigiles — the night watch for your dependencies

Usage:
  vigiles scan [flags]                  Scan installed packages
  vigiles diff <old-file> <new-file>    Compare dependency files
  vigiles version                       Print version
  vigiles help                          Show this help

Scan flags:
  --ecosystems string   pip,npm,brew or 'auto' (default "auto")
  --format string       table, json, summary (default "table")
  --output string       Write to file instead of stdout
  --skip-vuln           Skip OSV vulnerability lookup
  --skip-heuristic      Skip heuristic checks
  --skip-recency        Skip recently-published check
  --verbose             Show detailed progress

Diff flags:
  --format string       table, json (default "table")

Exit codes:
  0  Scan completed, no findings
  1  Scan completed, findings exist
  2  Runtime or usage error

Examples:
  vigiles scan
  vigiles scan --ecosystems pip,npm --format json
  vigiles diff requirements-old.txt requirements-new.txt
  vigiles diff --format json old/package.json new/package.json
`)
}
