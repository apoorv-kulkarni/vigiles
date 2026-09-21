package cmd

import (
	"flag"
	"fmt"
	"os"
	"runtime"

	"github.com/apoorv-kulkarni/vigiles/internal/gate"
	"github.com/apoorv-kulkarni/vigiles/internal/mcp"
)

func runMCPCmd(args []string) int {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	repo := fs.String("repo", "", "Repository root fixed for this server session")
	base := fs.String("base", "", "Full trusted base commit ID fixed at startup")
	if err := fs.Parse(args); err != nil {
		return ExitError
	}
	if fs.NArg() != 0 || *repo == "" || *base == "" {
		fmt.Fprintln(os.Stderr, "Usage: vigiles mcp --repo DIR --base FULL_COMMIT_ID")
		return ExitError
	}
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		fmt.Fprintln(os.Stderr, "MCP worktree checks require Linux or macOS")
		return ExitError
	}
	workspace, err := gate.OpenWorkspace(*repo, *base)
	if err != nil {
		fmt.Fprintln(os.Stderr, "MCP startup:", err)
		return ExitError
	}
	defer workspace.Close()
	if err := mcp.Serve(os.Stdin, os.Stdout, os.Stderr, Version, workspace.Check); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return ExitError
	}
	return ExitClean
}
