package cli

import (
	"strings"
	"sync"
	"testing"

	"github.com/TMHSDigital/subenum/internal/dnstest"
	"golang.org/x/net/dns/dnsmessage"
)

// TestE2ERecursiveWordlist covers #403: with -recursive-w, depth 1 tries the
// -w list and every level below tries only the -recursive-w list.
func TestE2ERecursiveWordlist(t *testing.T) {
	t.Parallel()
	zone := map[string]bool{
		"www.example.com": true, "x.www.example.com": true, "x.x.www.example.com": true,
		"www.www.example.com": true, // only a -w label reaches it
	}
	var mu sync.Mutex
	asked := map[string]bool{}
	srv := dnstest.Start(t, func(q dnstest.Query) dnstest.Reply {
		mu.Lock()
		asked[q.Name] = true
		mu.Unlock()
		if !zone[q.Name] {
			return dnstest.NXDomain
		}
		if q.Type == dnsmessage.TypeA {
			return dnstest.Reply{A: []string{"192.0.2.10"}}
		}
		return dnstest.Reply{}
	})
	wl := writeFile(t, "wl.txt", "www\napi\n")
	deep := writeFile(t, "deep.txt", "x\n")
	code, out := runCLI(t, "", append(localArgs("-dns-server", srv.Addr, "-type", "A", "-progress=false",
		"-w", wl, "-recursive", "-depth", "3", "-recursive-w", deep), "example.com")...)
	if code != exitOK {
		t.Fatalf("exit %d\n%s", code, out)
	}
	for _, name := range []string{"www.example.com", "x.www.example.com", "x.x.www.example.com"} {
		if !strings.Contains(out, name) {
			t.Errorf("%s not reported:\n%s", name, out)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	for _, name := range []string{"www.www.example.com", "api.www.example.com"} {
		if asked[name] {
			t.Errorf("a -w label was tried below depth 1: %s", name)
		}
	}
}

// TestRecursiveWordlistFlagChecks covers #403: -recursive-w needs
// -recursive, reads standard input once, and must have a valid entry.
func TestRecursiveWordlistFlagChecks(t *testing.T) {
	t.Parallel()
	wl := writeFile(t, "wl.txt", "www\n")
	bad := writeFile(t, "bad.txt", "bad_label!\n")
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"no -recursive", []string{"-simulate", "-w", wl, "-recursive-w", wl, "example.com"}, "-recursive-w needs -recursive"},
		{"stdin twice", []string{"-simulate", "-recursive", "-depth", "2", "-w", "-", "-recursive-w", "-", "example.com"}, "standard input"},
		{"no valid entries", []string{"-simulate", "-recursive", "-depth", "2", "-w", wl, "-recursive-w", bad, "example.com"}, "has no valid entries"},
		{"missing file", []string{"-simulate", "-recursive", "-depth", "2", "-w", wl, "-recursive-w", wl + ".missing", "example.com"}, "reading -recursive-w file"},
	} {
		if code, out := runCLIMerged(t, tc.args...); code == exitOK || !strings.Contains(out, tc.want) {
			t.Errorf("%s: exit %d, want a failure saying %q\n%s", tc.name, code, tc.want, out)
		}
	}
}

// TestDryRunNotesRecursiveWordlist covers #403: the dry run says what each
// found name adds under -recursive.
func TestDryRunNotesRecursiveWordlist(t *testing.T) {
	t.Parallel()
	wl := writeFile(t, "wl.txt", "www\napi\nmail\n")
	deep := writeFile(t, "deep.txt", "x\ny\n")
	_, out := runCLIMerged(t, "-dry-run", "-simulate", "-w", wl, "-recursive", "-depth", "3", "-recursive-w", deep, "example.com")
	if !strings.Contains(out, "2 -recursive-w candidates under each name found") {
		t.Errorf("dry run does not count the -recursive-w list:\n%s", out)
	}
	_, out = runCLIMerged(t, "-dry-run", "-simulate", "-w", wl, "-recursive", "-depth", "3", "example.com")
	if !strings.Contains(out, "the -w candidates again under each name found") {
		t.Errorf("dry run without -recursive-w:\n%s", out)
	}
}

// TestE2EResumeRefusesChangedRecursiveWordlist covers #403: a -recursive-w
// file that changed since the interrupt refuses to resume.
func TestE2EResumeRefusesChangedRecursiveWordlist(t *testing.T) {
	t.Parallel()
	wl := writeFile(t, "wl.txt", "www\n")
	deep := writeFile(t, "deep.txt", "x\n")
	args := []string{"-simulate", "-seed", "3", "-progress=false", "-w", wl, "-recursive", "-depth", "2", "-recursive-w", deep, "example.com"}
	digests, err := inputDigests(cliFlags{wordlists: wordlistPaths{paths: []string{wl}}})
	if err != nil {
		t.Fatal(err)
	}
	digests[deep] = "digest-of-the-old-file"
	path := writeState(t, resumeState{Args: args, Inputs: digests, Targets: []resumeTarget{{Domain: "example.com"}}})
	if code, out := runCLIMerged(t, "-resume", path); code != exitFailure || !strings.Contains(out, deep+" changed since the stopped run") {
		t.Errorf("exit %d, want a refusal naming %s\n%s", code, deep, out)
	}
}
