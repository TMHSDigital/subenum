package cli

import (
	"net"
	"net/http"
	"net/http/httptest"
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
