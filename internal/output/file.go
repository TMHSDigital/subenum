package output

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strconv"
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
// its permissions; a new one gets 0666 less the process umask, as os.Create
// would, so a umask of 077 keeps results private (#119). A path that is a
// symlink is followed: the file it points at is replaced and the link kept.
func CreateFile(path string) (*File, error) {
	if real, err := filepath.EvalSymlinks(path); err == nil {
		path = real
	}
	keep := os.FileMode(0)
	if fi, err := os.Stat(path); err == nil {
		if !fi.Mode().IsRegular() {
			f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
			if err != nil {
				return nil, err
			}
			return &File{Writer: bufio.NewWriter(f), path: path, f: f}, nil
		}
		keep = fi.Mode().Perm()
	}
	f, err := createTemp(filepath.Dir(path), "."+filepath.Base(path)+".")
	if err != nil {
		return nil, err
	}
	if keep != 0 {
		_ = f.Chmod(keep) // best effort; Windows only honors the read-only bit
	}
	return &File{Writer: bufio.NewWriter(f), path: path, f: f, tmp: true}, nil
}

// createTemp is os.CreateTemp with mode 0666, so the umask applies the way
// it does to os.Create; os.CreateTemp always creates 0600.
func createTemp(dir, prefix string) (*os.File, error) {
	for range 100 {
		name := filepath.Join(dir, prefix+strconv.FormatUint(rand.Uint64(), 36)+".tmp")
		f, err := os.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o666) //nolint:gosec // the user names the output path
		if !errors.Is(err, fs.ErrExist) {
			return f, err
		}
	}
	return nil, fmt.Errorf("creating a temporary file in %s: too many collisions", dir)
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
