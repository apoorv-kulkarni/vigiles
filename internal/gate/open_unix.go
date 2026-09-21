//go:build linux || darwin

package gate

import (
	"os"
	"syscall"
)

func openManifest(root *os.Root, name string) (*os.File, error) {
	// Nonblocking opens prevent a raced FIFO from hanging the server. Root confines
	// parent traversal, and NOFOLLOW rejects a raced final-component symlink.
	return root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
}
