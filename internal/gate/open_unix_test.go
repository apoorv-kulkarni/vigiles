//go:build linux || darwin

package gate

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestManifestOpenRejectsLinksAndDoesNotBlockOnFIFO(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := os.Symlink(t.TempDir(), filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if f, err := openManifest(root, "link"); err == nil {
		f.Close()
		t.Fatal("followed symlink")
	}
	if err := syscall.Mkfifo(filepath.Join(dir, "fifo"), 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		f, err := openManifest(root, "fifo")
		if err == nil {
			err = f.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("FIFO open blocked")
	}
}
