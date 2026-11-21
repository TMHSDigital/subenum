package cli

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TMHSDigital/subenum/internal/dnstest"
	"golang.org/x/net/dns/dnsmessage"
)

// TestE2EZoneTransferOverlapsSources covers #365 item 4: a target's zone
// transfer runs while its passive sources are asked, not after them, and
// their messages and names still come in the order they did when the two
// ran one after the other.
func TestE2EZoneTransferOverlapsSources(t *testing.T) {
	t.Parallel()
	transferred := make(chan struct{})
	var once sync.Once
	srv := dnstest.Start(t, func(q dnstest.Query) dnstest.Reply {
		switch {
		case q.Type == dnsmessage.TypeAXFR:
			once.Do(func() { close(transferred) })
			return dnstest.Reply{Transfer: []string{"zt.example.test"}}
		case q.Name == "example.test" && q.Type == dnsmessage.TypeNS:
			return dnstest.Reply{NS: []string{"ns1.example.test"}}
		case q.Name == "ns1.example.test" && q.Type == dnsmessage.TypeA:
			return dnstest.Reply{A: []string{"127.0.0.1"}}
		case q.Name == "example.test" || q.Name == "ns1.example.test":
			return dnstest.Reply{}
		}
		return dnstest.NXDomain
	})
	// The CT stub answers only once the transfer has been asked for, or
	// gives up after a while: run one after the other, it would wait out the
	// whole time.
	var overlapped atomic.Bool
	ct := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		select {
		case <-transferred:
			overlapped.Store(true)
		case <-time.After(3 * time.Second):
		}
		_, _ = w.Write([]byte(`[{"name_value": "ct.example.test"}]`))
	}))
	defer ct.Close()
	_, port, err := net.SplitHostPort(srv.Addr)
	if err != nil {
		t.Fatal(err)
	}
	wl := writeFile(t, "wl.txt", "www\n")
	args := append(localArgs("-axfr", "-ct", "-dns-server", srv.Addr, "-type", "A", "-progress=false", "-w", wl), "example.test")
	code, out := runCLIMergedWith(t, runArgs{args: args, sourceURLs: map[string]string{"ct": ct.URL + "/"}, axfrPort: port})
	if code != exitOK {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if !overlapped.Load() {
		t.Error("the zone transfer waited for the passive source")
	}
	ctLine := strings.Index(out, "Certificate Transparency: 1 names")
	axfrLine := strings.Index(out, "Zone transfer: 1 names")
	if ctLine < 0 || axfrLine < 0 || ctLine > axfrLine {
		t.Errorf("want the source's line before the transfer's:\n%s", out)
	}
}

// TestE2EFetchesNextTargetAhead covers #365 item 4b: under -dL the next
// target's passive sources are asked while the current target scans, one
// request at a time, and the lines they print still come under that
// target's own header.
func TestE2EFetchesNextTargetAhead(t *testing.T) {
	t.Parallel()
	nextAsked := make(chan struct{})
	var once sync.Once
	var inFlight, maxInFlight atomic.Int32
	ct := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := inFlight.Add(1)
		defer inFlight.Add(-1)
		for {
			m := maxInFlight.Load()
			if n <= m || maxInFlight.CompareAndSwap(m, n) {
				break
			}
		}
		if strings.Contains(r.URL.Query().Get("q"), "b.test") {
			once.Do(func() { close(nextAsked) })
			_, _ = w.Write([]byte(`[{"name_value": "ct.b.test"}]`))
			return
		}
		_, _ = w.Write([]byte(`[{"name_value": "ct.a.test"}]`))
	}))
	defer ct.Close()
	// The first target's scan answers www only once the second target's
	// source has been asked, or after a while: fetched one after the other,
	// it would wait out the whole time.
	var overlapped atomic.Bool
	srv := dnstest.Start(t, func(q dnstest.Query) dnstest.Reply {
		switch {
		case q.Name == "www.a.test" && q.Type == dnsmessage.TypeA:
			select {
			case <-nextAsked:
				overlapped.Store(true)
			case <-time.After(3 * time.Second):
			}
			return dnstest.Reply{A: []string{"192.0.2.1"}}
		case q.Name == "a.test" || q.Name == "b.test":
			return dnstest.Reply{}
		}
		return dnstest.NXDomain
	})
	wl := writeFile(t, "wl.txt", "www\n")
	dl := writeFile(t, "targets.txt", "a.test\nb.test\n")
	args := localArgs("-ct", "-dns-server", srv.Addr, "-type", "A", "-progress=false", "-w", wl, "-dL", dl)
	code, out := runCLIMergedWith(t, runArgs{args: args, sourceURLs: map[string]string{"ct": ct.URL + "/"}})
	if code != exitOK {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if !overlapped.Load() {
		t.Error("the second target's source was asked only after the first target's scan")
	}
	if m := maxInFlight.Load(); m != 1 {
		t.Errorf("the CT source had %d requests at once, want 1", m)
	}
	header := strings.Index(out, "=== [2/2] b.test ===")
	added := strings.Index(out, "Certificate Transparency: 1 names under b.test")
	found := strings.Index(out, "www.a.test")
	if header < 0 || added < header || found < 0 || found > header {
		t.Errorf("want the first target's result, then the second's header, then its source line:\n%s", out)
	}
}

// TestE2EResumeLeavesOutLookupFetchedAhead covers #365 item 4b: a lookup
// fetched ahead for a target the interrupt kept from starting is not saved,
// so the resumed run asks the source again.
func TestE2EResumeLeavesOutLookupFetchedAhead(t *testing.T) {
	t.Parallel()
	nextServed := make(chan struct{})
	var once sync.Once
	var nextHits atomic.Int32
	ct := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("q"), "b.test") {
			nextHits.Add(1)
			_, _ = w.Write([]byte(`[{"name_value": "late.b.test"}]`))
			once.Do(func() { close(nextServed) })
			return
		}
		_, _ = w.Write([]byte(`[]`))
	}))
	defer ct.Close()
	signals := make(chan os.Signal, 1)
	var interrupted atomic.Bool
	srv := dnstest.Start(t, func(q dnstest.Query) dnstest.Reply {
		switch {
		case q.Name == "www.a.test" && q.Type == dnsmessage.TypeA:
			if interrupted.CompareAndSwap(false, true) {
				select {
				case <-nextServed:
				case <-time.After(3 * time.Second):
				}
				signals <- os.Interrupt
			}
			return dnstest.Reply{A: []string{"192.0.2.1"}}
		case q.Name == "late.b.test" && q.Type == dnsmessage.TypeA:
			return dnstest.Reply{A: []string{"192.0.2.2"}}
		case q.Name == "a.test" || q.Name == "b.test":
			return dnstest.Reply{}
		}
		return dnstest.NXDomain
	})
	wl := writeFile(t, "wl.txt", "www\nmail\n")
	dl := writeFile(t, "targets.txt", "a.test\nb.test\n")
	path := filepath.Join(t.TempDir(), "state.json")
	urls := map[string]string{"ct": ct.URL + "/"}
	args := localArgs("-ct", "-dns-server", srv.Addr, "-type", "A", "-progress=false", "-state", path, "-w", wl, "-dL", dl)
	code, out := runCLIMergedWith(t, runArgs{args: args, sourceURLs: urls, signals: signals})
	if code != 130 {
		t.Fatalf("interrupted run: exit %d, want 130\n%s", code, out)
	}
	if strings.Contains(out, "names under b.test") {
		t.Errorf("printed the lookup of a target that never started:\n%s", out)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("no resume state saved: %v\n%s", err, out)
	}
	var st resumeState
	if err := json.Unmarshal(data, &st); err != nil {
		t.Fatal(err)
	}
	if _, ok := st.target("b.test").sourceNames("ct"); ok {
		t.Errorf("the lookup fetched ahead was saved: %s", data)
	}
	code, out = runCLIMergedWith(t, runArgs{sourceURLs: urls, args: []string{"-resume", path}})
	if code != exitOK || !strings.Contains(out, "late.b.test") {
		t.Errorf("resumed run: exit %d, want late.b.test from a new lookup\n%s", code, out)
	}
	if nextHits.Load() < 2 {
		t.Errorf("the resumed run did not ask the source again (%d requests)", nextHits.Load())
	}
}
