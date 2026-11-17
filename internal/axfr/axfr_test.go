package axfr

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/TMHSDigital/subenum/internal/dnstest"
)

// TestTryAsksNameServersAtOnce covers #365: a transfer that stalls no longer
// holds up the next name server's, so eight stalling servers cost about one
// stall, not eight. Each server's transfer still reports in server order.
func TestTryAsksNameServersAtOnce(t *testing.T) {
	const servers = 8
	var hosts []string
	for i := range servers {
		hosts = append(hosts, fmt.Sprintf("ns%d.example.test", i))
	}
	var (
		mu             sync.Mutex
		inFlight, peak int
		release        = make(chan struct{})
		releaseOnce    sync.Once
		stall          = 2 * time.Second
	)
	srv := dnstest.Start(t, func(q dnstest.Query) dnstest.Reply {
		switch {
		case q.Type == dnsmessage.TypeAXFR:
			mu.Lock()
			inFlight++
			peak = max(peak, inFlight)
			if peak == servers {
				releaseOnce.Do(func() { close(release) })
			}
			mu.Unlock()
			// Stall until every server is being asked, or long enough to
			// show they were asked in turn.
			select {
			case <-release:
			case <-time.After(stall):
			}
			mu.Lock()
			inFlight--
			mu.Unlock()
			return dnstest.Refused
		case q.Type == dnsmessage.TypeNS && q.Name == "example.test":
			return dnstest.Reply{NS: hosts}
		case q.Type == dnsmessage.TypeA:
			return dnstest.Reply{A: []string{"127.0.0.1"}}
		}
		return dnstest.Reply{}
	})
	_, port, err := net.SplitHostPort(srv.Addr)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	r := Try(context.Background(), "example.test", Options{
		Resolver: srv.Addr, Port: port, Timeout: 5 * time.Second,
		Debug: func(format string, args ...any) { lines = append(lines, fmt.Sprintf(format, args...)) },
	})
	if r.Tried != servers {
		t.Fatalf("tried %d addresses, want %d (%s)", r.Tried, servers, r.Err)
	}
	mu.Lock()
	defer mu.Unlock()
	if peak != servers {
		t.Errorf("at most %d transfers were in flight at once, want all %d", peak, servers)
	}
	var refused []string
	for _, l := range lines {
		for _, h := range hosts {
			if strings.HasPrefix(l, "-axfr: "+h+" ") {
				refused = append(refused, h)
			}
		}
	}
	if fmt.Sprint(refused) != fmt.Sprint(hosts) {
		t.Errorf("refusals reported for %v, want %v in order", refused, hosts)
	}
}
