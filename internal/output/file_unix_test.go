//go:build unix

package output

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestCreateFileHonorsUmask covers #119: a new results file gets 0666 less
// the umask, as os.Create would, instead of a fixed 0644.
func TestCreateFileHonorsUmask(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	path := filepath.Join(t.TempDir(), "results.txt")
	f, err := CreateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("www.example.com\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(true); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v under umask 077, want 0600", fi.Mode().Perm())
	}
}

// TestCreateFileFollowsSymlink covers #119: an -o path that is a symlink
// stays a symlink, and the file it points at receives the results.
func TestCreateFileFollowsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "data", "results.txt")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("old\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "results.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	f, err := CreateFile(link)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("new\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(true); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("-o symlink was replaced (mode %v, err %v)", fi.Mode(), err)
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "new\n" {
		t.Fatalf("target holds %q (err %v), want the new results", data, err)
	}
	if fi, _ := os.Stat(target); fi.Mode().Perm() != 0o640 {
		t.Errorf("target mode %v, want its original 0640", fi.Mode().Perm())
	}
}
