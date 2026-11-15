package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFiles(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestNoticeFiles(t *testing.T) {
	dir := writeFiles(t, map[string]string{
		"LICENSE":     "x",
		"COPYING.txt": "x",
		"PATENTS":     "x",
		"License-MIT": "x",
		"license.go":  "package x",
		"README.md":   "x",
		"NOTICE.md":   "x",
	})
	got, err := noticeFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := "COPYING.txt LICENSE License-MIT NOTICE.md PATENTS"
	if strings.Join(got, " ") != want {
		t.Errorf("noticeFiles = %v, want %s", got, want)
	}
}

func TestWrite(t *testing.T) {
	goroot := writeFiles(t, map[string]string{"LICENSE": "Go BSD\r\n", "PATENTS": "grant\n"})
	a := writeFiles(t, map[string]string{"LICENSE": "MIT A\n\n"})
	var buf bytes.Buffer
	err := write(&buf, "go1.26.11", goroot, []module{{Path: "example.com/a", Version: "v1.2.3", Dir: a}})
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"Go standard library go1.26.11", "Go BSD\n", "grant\n", "example.com/a v1.2.3", "MIT A\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\r") {
		t.Error("output keeps CRLF line endings")
	}
	if strings.Index(out, "Go BSD") > strings.Index(out, "MIT A") {
		t.Error("standard library notice should come first")
	}

	none := writeFiles(t, map[string]string{"README.md": "x"})
	err = write(&bytes.Buffer{}, "go", goroot, []module{{Path: "example.com/none", Dir: none}})
	if err == nil || !strings.Contains(err.Error(), "example.com/none") {
		t.Errorf("module without a licence: err = %v, want an error naming it", err)
	}
}

// TestRepoModules runs the generator over subenum itself: every module the
// binary links must be listed and have a licence file.
func TestRepoModules(t *testing.T) {
	mods, err := listModules(filepath.Join("..", ".."), ".")
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, m := range mods {
		have[m.Path] = true
		if m.Path == "github.com/TMHSDigital/subenum" {
			t.Error("the main module is listed")
		}
	}
	for _, want := range []string{"charm.land/bubbletea/v2", "golang.org/x/net", "golang.org/x/sys", "github.com/atotto/clipboard"} {
		if !have[want] {
			t.Errorf("module %s missing from %v", want, mods)
		}
	}
	goroot, err := goEnv("GOROOT")
	if err != nil {
		t.Fatal(err)
	}
	if err := write(&bytes.Buffer{}, "go", goroot, mods); err != nil {
		t.Fatal(err)
	}
}
