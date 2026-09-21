package cmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/apoorv-kulkarni/vigiles/internal/config"
	"github.com/apoorv-kulkarni/vigiles/internal/diff"
	"github.com/apoorv-kulkarni/vigiles/internal/gate"
	"github.com/apoorv-kulkarni/vigiles/internal/signal"
)

func runGateCmd(args []string) int {
	fs := flag.NewFlagSet("gate", flag.ContinueOnError)
	base := fs.String("base", "", "Full trusted base commit ID")
	head := fs.String("head", "", "Full candidate commit ID")
	repo := fs.String("repo", ".", "Git repository to inspect")
	if err := fs.Parse(args); err != nil {
		return ExitError
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "gate does not accept file lists or policy overrides")
		return ExitError
	}
	r, err := gate.Run(*repo, *base, *head)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		if err := json.NewEncoder(os.Stdout).Encode(map[string]any{"version": Version, "status": "incomplete", "incomplete": []string{err.Error()}}); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		return ExitError
	}
	r.Version = Version
	failOn, err := parseFailOn(resolveFailOn("", r.Policy.Policy.FailOn))
	if err != nil {
		r.Incomplete = append(r.Incomplete, "invalid base policy: "+err.Error())
	}
	r.Signals = config.ApplySuppressions(r.Signals, r.Policy.Suppress, os.Stderr)
	code := ExitClean
	r.Status = "pass"
	if hasBlockingSignal(r.Signals, failOn) {
		r.Status, code = "blocked", ExitFindings
	}
	if len(r.Incomplete) > 0 {
		r.Status, code = "incomplete", ExitError
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return ExitError
	}
	return code
}

func runStrictDiff(oldPath, newPath, format string, cfg *config.Config, failOn map[string]bool) int {
	r, err := diff.RunStrict(oldPath, newPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return ExitError
	}
	if format == "json" {
		if err := json.NewEncoder(os.Stdout).Encode(r); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return ExitError
		}
	} else {
		printDiffTable(os.Stdout, &r.Result)
		for _, problem := range r.Incomplete {
			fmt.Fprintf(os.Stderr, "Incomplete: %s\n", problem)
		}
	}
	if !r.Complete {
		return ExitError
	}
	var signals []signal.Signal
	for _, entry := range r.Entries {
		signals = append(signals, entry.Signals...)
	}
	signals = config.ApplySuppressions(signals, cfg.Suppress, os.Stderr)
	if hasBlockingSignal(signals, failOn) {
		return ExitFindings
	}
	return ExitClean
}
