//go:build unix

package main

import (
	"fmt"
	"strings"
	"syscall"
	"testing"
)

// TestE2ESIGTERMExits143 covers #82: SIGTERM (container stop, systemd) exits
// 143, not the SIGINT code 130.
func TestE2ESIGTERMExits143(t *testing.T) {
	var words strings.Builder
	for i := 0; i < 200; i++ {
		fmt.Fprintf(&words, "w%d\n", i)
	}
	wl := writeFile(t, "wl.txt", words.String())

	// 200 names at -rate 10 would take 20s; the signal, sent once the first
	// result is out rather than after a fixed sleep (#260), ends it early.
	code, _ := runCLIUntilLines(t, 1, func() { _ = syscall.Kill(syscall.Getpid(), syscall.SIGTERM) }, runArgs{
		args: []string{"-simulate", "-hit-rate", "100", "-rate", "10", "-progress=false", "-w", wl, "example.com"}})
	if code != 143 {
		t.Fatalf("exit %d after SIGTERM, want 143", code)
	}
}
