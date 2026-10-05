//go:build unix

package main

import (
	"fmt"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestE2ESIGTERMExits143 covers #82: SIGTERM (container stop, systemd) exits
// 143, not the SIGINT code 130.
func TestE2ESIGTERMExits143(t *testing.T) {
	var words strings.Builder
	for i := 0; i < 200; i++ {
		fmt.Fprintf(&words, "w%d\n", i)
	}
	wl := writeFile(t, "wl.txt", words.String())

	ready := make(chan struct{})
	signalReady = ready
	t.Cleanup(func() { signalReady = nil })
	go func() {
		<-ready
		time.Sleep(200 * time.Millisecond) // let the scan start
		_ = syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
	}()

	// 200 names at -rate 10 would take 20s; the signal ends it early.
	code, _ := runCLI(t, "", "-simulate", "-rate", "10", "-progress=false", "-w", wl, "example.com")
	if code != 143 {
		t.Fatalf("exit %d after SIGTERM, want 143", code)
	}
}
