//go:build !linux && !darwin

package gate

import (
	"fmt"
	"os"
)

func openManifest(root *os.Root, name string) (*os.File, error) {
	return nil, fmt.Errorf("worktree checks require Linux or macOS")
}
