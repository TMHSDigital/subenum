package scan

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TMHSDigital/subenum/internal/dns"
)

// TestInternalAddressIsReported covers #218: a name that resolves to an
// internal address carries the scope in its result, a name that resolves to
// a public address carries none, and the run counts the internal ones.
func TestInternalAddressIsReported(t *testing.T) {
	var n atomic.Int64
	cfg := Config{
		Domain:      "example.com",
		Entries:     makeEntries(20),
		Concurrency: 4,
		Timeout:     time.Second,
		Attempts:    1,
		// The wildcard probe looks the domain up for real, which a test
		// cannot do; -force scans without the wildcard filtering.
		Force: true,
		resolveHook: func(context.Context, string) ([]dns.Record, dns.Outcome) {
			// Every third name resolves to a private address, the others to a
			// public one. The addresses differ per name, so none of them is
			// taken for a wildcard answer.
			i := n.Add(1)
			if i%3 == 0 {
				return []dns.Record{{Type: "A", Value: "10.0." + itoa(int(i)) + ".1"}}, dns.OutcomeFound
			}
			return []dns.Record{{Type: "A", Value: "93.184.216." + itoa(int(i))}}, dns.OutcomeFound
		},
	}

	events := make(chan Event, 256)
	go Run(context.Background(), cfg, events)

	var internal, public int
	var stats Stats
	for ev := range events {
		switch ev.Kind {
		case EventResult:
			switch ev.Result.InternalAddress {
			case dns.ScopePrivate:
				internal++
			case "":
				public++
			default:
				t.Errorf("unexpected scope %q for %s", ev.Result.InternalAddress, ev.Result.Subdomain)
			}
		case EventDone:
			stats = ev.Stats
		}
	}
	if internal == 0 {
		t.Error("expected at least one result with an internal address")
	}
	if public == 0 {
		t.Error("expected at least one result with a public address")
	}
	if stats.Internal != int64(internal) {
		t.Errorf("Stats.Internal %d != the %d results with an internal address", stats.Internal, internal)
	}
}
