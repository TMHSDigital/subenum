//go:build unix

package tui

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// The saved form can contain private file paths and resolver settings. Even a
// permissive umask must not make it readable by other users (#413).
func TestSaveConfigPrivatePermissions(t *testing.T) {
	// Umask is process-wide: keep this test and its subtests non-parallel.
	old := syscall.Umask(0)
	defer syscall.Umask(old)
	for _, existing := range []bool{false, true} {
		name := "new"
		if existing {
			name = "replace"
		}
		t.Run(name, func(t *testing.T) {
			redirectConfig(t)
			p, err := configPath()
			if err != nil {
				t.Fatal(err)
			}
			if existing {
				if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte("{}"), 0o666); err != nil {
					t.Fatal(err)
				}
			}
			if err := saveConfig(savedConfig{Domain: "example.com"}); err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(p)
			if err != nil {
				t.Fatal(err)
			}
			if got := info.Mode().Perm(); got != 0o600 {
				t.Errorf("last.json mode = %04o with umask 000, want 0600", got)
			}
		})
	}
}
