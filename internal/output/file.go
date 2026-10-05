package output

import (
	"bufio"
	"os"
	"path/filepath"
)

// File is an -o results file that is replaced atomically. Output goes to a
// temporary file in the target's directory and Close(true) renames it over the
// target, so a run that fails before any scan finishes (preflight, wildcard
// abort, Ctrl+C during preflight) leaves an existing results file unchanged
// (#52). A target that exists but is not a regular file, such as /dev/stdout
// or a named pipe, is written directly.
type File struct {
	*bufio.Writer
	path   string
	f      *os.File
	tmp    bool
	closed bool
}

// CreateFile opens path for writing results. An existing regular file keeps
// its permissions; a new one is created 0644.
func CreateFile(path string) (*File, error) {
	mode := os.FileMode(0o644)
	if fi, err := os.Stat(path); err == nil {
		if !fi.Mode().IsRegular() {
			f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
			if err != nil {
				return nil, err
			}
			return &File{Writer: bufio.NewWriter(f), path: path, f: f}, nil
		}
		mode = fi.Mode().Perm()
	}
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return nil, err
	}
	_ = f.Chmod(mode) // best effort; Windows only honors the read-only bit
	return &File{Writer: bufio.NewWriter(f), path: path, f: f, tmp: true}, nil
}

// Close flushes and closes the file. With commit set, the temporary file
// replaces the target; otherwise it is discarded and the target is left as it
// was. A failed flush or close also discards it rather than replacing a good
// file with a truncated one. Close returns the first error and is safe to call
// more than once.
func (f *File) Close(commit bool) error {
	if f.closed {
		return nil
	}
	f.closed = true
	err := f.Flush()
	if cerr := f.f.Close(); err == nil {
		err = cerr
	}
	if !f.tmp {
		return err
	}
	if commit && err == nil {
		if err = os.Rename(f.f.Name(), f.path); err == nil {
			return nil
		}
	}
	_ = os.Remove(f.f.Name())
	return err
}
