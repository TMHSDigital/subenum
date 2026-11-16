// Copyright (c) 2026 TM Hospitality Strategies

// Command licenses writes the licence notices of everything linked into the
// subenum binary to one file: the Go standard library's licence, then each
// third-party module's licence files, read from the module cache (#326).
//
// GoReleaser and the Dockerfile run it at release time, so the archives and
// the image carry the notices for the exact module set they were built from:
//
//	go run ./tools/licenses -o build/THIRD_PARTY_LICENSES
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// releaseGOOS lists the operating systems .goreleaser.yaml builds for. The
// module set is the union over all of them, so one file covers every archive.
// TestReleaseGOOS fails when the two lists differ.
var releaseGOOS = []string{"linux", "darwin", "windows", "freebsd"}

// module is one third-party module linked into the binary.
type module struct {
	Path    string
	Version string
	Dir     string
}

func main() {
	out := flag.String("o", "-", "output file (- for stdout)")
	pkg := flag.String("pkg", ".", "main package whose dependencies are listed")
	flag.Parse()
	if err := run(*pkg, *out); err != nil {
		fmt.Fprintln(os.Stderr, "licenses:", err)
		os.Exit(1)
	}
}

func run(pkg, out string) error {
	mods, err := listModules("", pkg)
	if err != nil {
		return err
	}
	goroot, err := goEnv("GOROOT")
	if err != nil {
		return err
	}
	goversion, err := goEnv("GOVERSION")
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	if err := write(&buf, goversion, goroot, mods); err != nil {
		return err
	}
	if out == "-" {
		_, err = os.Stdout.Write(buf.Bytes())
		return err
	}
	// The file ships in archives and the image, where every user reads it.
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil { //nolint:gosec // see above
		return err
	}
	return os.WriteFile(out, buf.Bytes(), 0o644) //nolint:gosec // see above
}

// listModules returns the non-main modules that provide packages pkg depends
// on, for any release GOOS, sorted by path. dir is the working directory for
// the go command ("" for the current one).
func listModules(dir, pkg string) ([]module, error) {
	const format = `{{with .Module}}{{if not .Main}}{{.Path}}{{"\t"}}{{.Version}}{{"\t"}}{{with .Replace}}{{.Dir}}{{else}}{{.Dir}}{{end}}{{end}}{{end}}`
	seen := map[string]module{}
	for _, goos := range releaseGOOS {
		cmd := exec.CommandContext(context.Background(), "go", "list", "-deps", "-f", format, pkg) //nolint:gosec // the go tool, with a package pattern from the release config
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GOOS="+goos, "CGO_ENABLED=0")
		cmd.Stderr = os.Stderr
		outb, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("go list (GOOS=%s): %w", goos, err)
		}
		for _, line := range strings.Split(string(outb), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			f := strings.Split(line, "\t")
			if len(f) != 3 || f[2] == "" {
				return nil, fmt.Errorf("go list: unexpected line %q", line)
			}
			seen[f[0]] = module{Path: f[0], Version: f[1], Dir: f[2]}
		}
	}
	mods := make([]module, 0, len(seen))
	for _, m := range seen {
		mods = append(mods, m)
	}
	sort.Slice(mods, func(i, j int) bool { return mods[i].Path < mods[j].Path })
	return mods, nil
}

func goEnv(key string) (string, error) {
	out, err := exec.CommandContext(context.Background(), "go", "env", key).Output() //nolint:gosec // the go tool, with a fixed variable name
	if err != nil {
		return "", fmt.Errorf("go env %s: %w", key, err)
	}
	return strings.TrimSpace(string(out)), nil
}

// noticeNames are the file names (case-insensitive, extension aside) that
// hold a module's licence or notices.
var noticeNames = map[string]bool{"LICENSE": true, "LICENCE": true, "COPYING": true, "NOTICE": true, "PATENTS": true}

// noticeFiles returns the licence and notice files at the top of dir, sorted.
func noticeFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		base := strings.ToUpper(e.Name())
		switch ext := filepath.Ext(base); ext {
		case "", ".MD", ".TXT", ".RST":
			base = strings.TrimSuffix(base, ext)
		default:
			continue
		}
		if noticeNames[base] || strings.HasPrefix(base, "LICENSE-") || strings.HasPrefix(base, "LICENCE-") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

// write renders the notices file: a header, the Go standard library's
// licence from goroot, then each module's. A directory without a licence
// file is an error, so a release never ships an incomplete file.
func write(w io.Writer, goversion, goroot string, mods []module) error {
	if _, err := fmt.Fprint(w, "Third-party licence notices for subenum\n\n"+
		"subenum is licensed under the GNU General Public License v3.0; see LICENSE.\n"+
		"The subenum binary also contains the Go standard library and the modules\n"+
		"below. Their licence and notice files follow, as their licences ask.\n"+
		"Generated by tools/licenses from the module set of the build.\n"); err != nil {
		return err
	}
	if err := section(w, "Go standard library", goversion, goroot); err != nil {
		return err
	}
	for _, m := range mods {
		if err := section(w, m.Path, m.Version, m.Dir); err != nil {
			return err
		}
	}
	return nil
}

func section(w io.Writer, name, version, dir string) error {
	files, err := noticeFiles(dir)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if len(files) == 0 {
		return fmt.Errorf("%s: no licence file in %s", name, dir)
	}
	rule := strings.Repeat("=", 78)
	if _, err := fmt.Fprintf(w, "\n%s\n%s %s\n%s\n", rule, name, version, rule); err != nil {
		return err
	}
	for _, f := range files {
		b, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		text := strings.TrimRight(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
		if text == "" {
			return errors.New(name + ": empty " + f)
		}
		if _, err := fmt.Fprintf(w, "\n--- %s ---\n\n%s\n", f, text); err != nil {
			return err
		}
	}
	return nil
}
