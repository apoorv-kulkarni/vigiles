package cmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/apoorv-kulkarni/vigiles/internal/checker"
	"github.com/apoorv-kulkarni/vigiles/internal/diff"
	"github.com/apoorv-kulkarni/vigiles/internal/reporter"
	"github.com/apoorv-kulkarni/vigiles/internal/scanner"
	"github.com/apoorv-kulkarni/vigiles/internal/signal"
)

const Version = "0.3.2"

// Exit codes:
//
//	0 — scan completed, no findings
//	1 — scan completed, findings exist
//	2 — runtime/usage error
const (
	ExitClean    = 0
	ExitFindings = 1
	ExitError    = 2
)

// validEcosystems is the set of supported ecosystem names.
var validEcosystems = map[string]bool{"pip": true, "npm": true, "brew": true, "cargo": true, "gomod": true}

// validFormats is the set of supported output formats.
var validFormats = map[string]bool{"table": true, "json": true, "summary": true, "sarif": true}

var validDiffFormats = map[string]bool{"table": true, "json": true}

// validFailOnTypes is the set of accepted --fail-on values.
var validFailOnTypes = map[string]bool{
	"vulnerability":   true,
	"heuristic":       true,
	"system-heuristic": true,
	"trust-signal":    true,
	"all":             true,
	"none":            true,
}

type scanOptions struct {
	EnableProvenance bool
	EnableSigstore   bool
	WatchMode        bool
	WatchInterval    time.Duration
	Notify           bool
	FailOn           map[string]bool
}

// parseFailOn parses a comma-separated --fail-on value into a type set.
func parseFailOn(input string) (map[string]bool, error) {
	result := map[string]bool{}
	for _, t := range strings.Split(input, ",") {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if !validFailOnTypes[t] {
			return nil, fmt.Errorf("invalid --fail-on value %q (valid: vulnerability, heuristic, system-heuristic, trust-signal, all, none)", t)
		}
		result[t] = true
	}
	return result, nil
}

// hasBlockingSignal reports whether any signal matches the fail-on policy.
// A nil or empty map defaults to "all" behaviour (backward-compatible).
func hasBlockingSignal(signals []signal.Signal, failOn map[string]bool) bool {
	if len(failOn) == 0 || failOn["all"] {
		return len(signals) > 0
	}
	if failOn["none"] {
		return false
	}
	for _, s := range signals {
		if failOn[s.Type] {
			return true
		}
	}
	return false
}

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
	outputFmt := fs.String("format", "table", "Output format: table, json, summary, sarif")
	outputFile := fs.String("output", "", "Write results to file (default: stdout)")
	skipVuln := fs.Bool("skip-vuln", false, "Skip OSV vulnerability check")
	skipHeuristic := fs.Bool("skip-heuristic", false, "Skip heuristic checks")
	skipRecency := fs.Bool("skip-recency", false, "Skip recently-published check")
	provenance := fs.Bool("provenance", false, "Verify registry package versions against GitHub source tags")
	sigstore := fs.Bool("sigstore", false, "Check PyPI releases for PEP 740 attestation metadata")
	watch := fs.Bool("watch", false, "Re-run scans continuously")
	watchInterval := fs.Duration("watch-interval", 5*time.Minute, "Watch mode interval (e.g., 30s, 2m)")
	notify := fs.Bool("notify", false, "Send desktop notifications in watch mode")
	verbose := fs.Bool("verbose", false, "Show detailed progress")
	failOnFlag := fs.String("fail-on", "all", "Signal types that trigger exit 1: vulnerability, heuristic, system-heuristic, trust-signal, all, none")

	if err := fs.Parse(args); err != nil {
		return ExitError
	}

	// H: Validate --format
	if !validFormats[*outputFmt] {
		fmt.Fprintf(os.Stderr, "Error: invalid format %q (valid: table, json, summary, sarif)\n", *outputFmt)
		return ExitError
	}

	// H: Validate --ecosystems
	ecoList, err := parseEcosystems(*ecosystems, *verbose)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return ExitError
	}

	failOn, err := parseFailOn(*failOnFlag)
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

	opts := scanOptions{
		EnableProvenance: *provenance,
		EnableSigstore:   *sigstore,
		WatchMode:        *watch,
		WatchInterval:    *watchInterval,
		Notify:           *notify,
		FailOn:           failOn,
	}
	if opts.WatchMode {
		if opts.WatchInterval <= 0 {
			fmt.Fprintln(os.Stderr, "Error: --watch-interval must be > 0")
			return ExitError
		}
		return runScanWatch(ecoList, *outputFmt, *outputFile, *skipVuln, *skipHeuristic, *skipRecency, *verbose, progress, opts)
	}

	return runScanWithOptions(ecoList, *outputFmt, *outputFile, *skipVuln, *skipHeuristic, *skipRecency, *verbose, progress, opts)
}

func runScan(ecoList []string, outputFmt, outputFile string, skipVuln, skipHeuristic, skipRecency, verbose bool, progress io.Writer) int {
	return runScanWithOptions(ecoList, outputFmt, outputFile, skipVuln, skipHeuristic, skipRecency, verbose, progress, scanOptions{})
}

func runScanWithOptions(ecoList []string, outputFmt, outputFile string, skipVuln, skipHeuristic, skipRecency, verbose bool, progress io.Writer, opts scanOptions) int {
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
			if _, err := os.Stat("package.json"); err == nil {
				signals = append(signals, checker.CheckNpmInstallScriptsDeep("package.json")...)
			}
			if _, err := os.Stat("node_modules"); err == nil {
				fmt.Fprintf(progress, "▸ Checking npm install scripts...\n")
				ns := checker.CheckNpmInstallScriptsInNodeModules("node_modules")
				if len(ns) > 0 {
					fmt.Fprintf(progress, "  Found %d packages with install scripts\n", len(ns))
				}
				signals = append(signals, ns...)
			}
		}

		if hasEcosystem(ecoList, "pip") {
			if _, err := os.Stat("setup.py"); err == nil {
				signals = append(signals, checker.CheckSetupPyDeep("setup.py")...)
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

	if opts.EnableProvenance {
		fmt.Fprintf(progress, "▸ Verifying package provenance tags...\n")
		signals = append(signals, checker.NewProvenanceChecker().Check(allPackages)...)
	}

	if opts.EnableSigstore {
		fmt.Fprintf(progress, "▸ Verifying PyPI attestations (PEP 740 metadata)...\n")
		signals = append(signals, checker.NewSigstoreChecker().Check(allPackages)...)
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
	case "sarif":
		if err := reporter.WriteSARIF(output, report); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing SARIF: %v\n", err)
			return ExitError
		}
	case "summary":
		reporter.PrintSummary(output, report)
	default:
		reporter.PrintTable(output, report)
	}

	if hasBlockingSignal(signals, opts.FailOn) {
		return ExitFindings
	}
	return ExitClean
}

func runScanWatch(ecoList []string, outputFmt, outputFile string, skipVuln, skipHeuristic, skipRecency, verbose bool, progress io.Writer, opts scanOptions) int {
	fmt.Fprintf(progress, "Entering watch mode (interval: %s). Press Ctrl+C to stop.\n", opts.WatchInterval)
	lastHadFindings := false

	for {
		code := runScanWithOptions(ecoList, outputFmt, outputFile, skipVuln, skipHeuristic, skipRecency, verbose, progress, opts)
		hasFindings := code == ExitFindings
		if opts.Notify && hasFindings && !lastHadFindings {
			sendNotification("Vigiles", "New dependency findings detected")
		}
		lastHadFindings = hasFindings
		time.Sleep(opts.WatchInterval)
	}
}

func sendNotification(title, message string) {
	if runtime.GOOS == "darwin" {
		_ = exec.Command("osascript", "-e", fmt.Sprintf("display notification %q with title %q", message, title)).Run()
	}
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
	failOnFlag := fs.String("fail-on", "all", "Signal types that trigger exit 1: vulnerability, heuristic, system-heuristic, trust-signal, all, none")

	if err := fs.Parse(args); err != nil {
		return ExitError
	}

	remaining := fs.Args()
	if len(remaining) != 2 {
		fmt.Fprintln(os.Stderr, "Usage: vigiles diff [--format table|json] <old-file> <new-file>")
		return ExitError
	}

	if !validDiffFormats[*outputFmt] {
		fmt.Fprintf(os.Stderr, "Error: invalid format %q\n", *outputFmt)
		return ExitError
	}

	failOn, err := parseFailOn(*failOnFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
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

	// Collect all diff signals and apply fail-on policy
	var allSignals []signal.Signal
	for _, e := range result.Entries {
		allSignals = append(allSignals, e.Signals...)
	}
	if hasBlockingSignal(allSignals, failOn) {
		return ExitFindings
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
		if e.Status == diff.Added {
			fmt.Fprintln(w, "  NEW DEPENDENCY:")
			fmt.Fprintf(w, "  %s %s\n", e.Name, e.NewVersion)

			if len(e.Signals) > 0 {
				fmt.Fprintln(w, "  Signals:")
				seen := map[string]bool{}
				for _, sig := range e.Signals {
					msg := humanizeDiffSignal(sig)
					if msg == "" || seen[msg] {
						continue
					}
					seen[msg] = true
					fmt.Fprintf(w, "  • %s\n", msg)
				}
			}
			fmt.Fprintln(w)
			continue
		}

		var icon, ver string
		switch e.Status {
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

func humanizeDiffSignal(sig signal.Signal) string {
	switch sig.ID {
	case "VIGILES-NEW-DEPENDENCY":
		return "new transitive dependency"
	case "VIGILES-RECENTLY-PUBLISHED":
		lower := strings.ToLower(sig.Summary)
		if strings.Contains(lower, "< 1 hour") || strings.Contains(lower, "hour") {
			return "published today"
		}
		return "recently published"
	}

	if sig.Summary != "" {
		return strings.ToLower(sig.Summary[:1]) + sig.Summary[1:]
	}
	return sig.ID
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
		for _, eco := range []string{"pip", "npm", "brew", "cargo", "gomod"} {
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
			return nil, fmt.Errorf("invalid ecosystem %q (valid: pip, npm, brew, cargo, gomod)", e)
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
	--ecosystems string   pip,npm,brew,cargo,gomod or 'auto' (default "auto")
	--format string       table, json, summary, sarif (default "table")
  --output string       Write to file instead of stdout
  --fail-on string      Signal types that trigger exit 1: vulnerability, heuristic,
                        system-heuristic, trust-signal, all, none (default "all")
  --skip-vuln           Skip OSV vulnerability lookup
  --skip-heuristic      Skip heuristic checks
  --skip-recency        Skip recently-published check
	--provenance          Check registry ↔ GitHub tag provenance (pip/npm)
	--sigstore            Check PyPI PEP 740 attestation metadata
	--watch               Re-run scan continuously
	--watch-interval      Interval between watch scans (default 5m)
	--notify              Desktop notifications (watch mode)
  --verbose             Show detailed progress

Diff flags:
  --format string       table, json (default "table")
  --fail-on string      Signal types that trigger exit 1 (same values as scan)

Exit codes:
  0  Scan completed, no findings (or no findings matching --fail-on policy)
  1  Scan completed, findings matching --fail-on policy exist
  2  Runtime or usage error

Examples:
  vigiles scan
  vigiles scan --ecosystems pip,npm --format json
	vigiles scan --ecosystems cargo,gomod --format sarif --output vigiles.sarif
	vigiles scan --provenance --sigstore
  vigiles diff requirements-old.txt requirements-new.txt
  vigiles diff --format json old/package.json new/package.json
`)
}
