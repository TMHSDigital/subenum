// Package labzone parses -simulate-zone scenario files (#76). A scenario
// defines exact names, records, wildcards and failures for a lab exercise. A
// local DNS server answers from it, so a lab runs the real resolver, wildcard
// detection, -rate pacing and reliability guard, deterministically and
// without sending traffic off the machine.
//
// The format is line based; # starts a comment. Names are relative to the
// scanned domain: @ is the domain itself, and *.dev is a wildcard covering
// every name under dev that the file does not define.
//
//	$DELAY 20ms            # every answer waits this long
//	$REFUSE-ABOVE 50       # answer REFUSED past 50 queries a second
//	@        A        192.0.2.1
//	www      A        192.0.2.10
//	www      AAAA     2001:db8::10
//	shop     CNAME    www                    # relative target
//	blog     CNAME    ghost.example.net.     # absolute target (trailing dot)
//	*.dev    A        192.0.2.99
//	slow     TIMEOUT                         # never answered
//	broken   SERVFAIL                        # also REFUSED, NXDOMAIN
//
// Names the file does not define are NXDOMAIN (or NODATA when a deeper
// name exists under them). The server stands in for the student's resolver
// and the scenario is the whole world, so names outside the scanned domain
// (an external CNAME target, say) are NXDOMAIN too.
package labzone

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/TMHSDigital/subenum/internal/dnsserver"
)

// Zone is a parsed scenario.
type Zone struct {
	entries   map[string]*entry // relative name ("" is the apex) -> records
	wildcards map[string]*entry // parent of a *.parent wildcard -> records
	exists    map[string]bool   // every defined name and its ancestors

	Delay       time.Duration // $DELAY
	RefuseAbove int           // $REFUSE-ABOVE; 0 means no limit
}

type entry struct {
	a, aaaa []string
	cname   string
	fail    *dnsserver.Reply // TIMEOUT, SERVFAIL, REFUSED or NXDOMAIN
}

var failures = map[string]dnsserver.Reply{
	"TIMEOUT":  dnsserver.Dropped,
	"SERVFAIL": dnsserver.ServFail,
	"REFUSED":  dnsserver.Refused,
	"NXDOMAIN": dnsserver.NXDomain,
}

// Load parses the scenario file at path.
func Load(path string) (*Zone, error) {
	f, err := os.Open(path) //nolint:gosec // the user names the scenario file
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	z, err := Parse(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return z, nil
}

// Parse reads a scenario.
func Parse(r io.Reader) (*Zone, error) {
	z := &Zone{entries: map[string]*entry{}, wildcards: map[string]*entry{}, exists: map[string]bool{"": true}}
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line, _, _ := strings.Cut(sc.Text(), "#")
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if err := z.parseLine(fields); err != nil {
			return nil, fmt.Errorf("line %d: %w", n, err)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(z.entries) == 0 && len(z.wildcards) == 0 {
		return nil, fmt.Errorf("no records defined")
	}
	return z, nil
}

func (z *Zone) parseLine(fields []string) error {
	switch strings.ToUpper(fields[0]) {
	case "$DELAY":
		if len(fields) != 2 {
			return fmt.Errorf("want $DELAY <duration>, e.g. $DELAY 20ms")
		}
		d, err := time.ParseDuration(fields[1])
		if err != nil || d < 0 || d > 10*time.Second {
			return fmt.Errorf("bad $DELAY %q: want a duration up to 10s, e.g. 20ms", fields[1])
		}
		z.Delay = d
		return nil
	case "$REFUSE-ABOVE":
		if len(fields) != 2 {
			return fmt.Errorf("want $REFUSE-ABOVE <queries per second>")
		}
		v, err := strconv.Atoi(fields[1])
		if err != nil || v < 1 {
			return fmt.Errorf("bad $REFUSE-ABOVE %q: want a positive number of queries per second", fields[1])
		}
		z.RefuseAbove = v
		return nil
	}
	if strings.HasPrefix(fields[0], "$") {
		return fmt.Errorf("unknown directive %s (known: $DELAY, $REFUSE-ABOVE)", fields[0])
	}
	if len(fields) < 2 {
		return fmt.Errorf("want <name> <type> [value]")
	}

	name, wild, err := parseName(fields[0])
	if err != nil {
		return err
	}
	table := z.entries
	if wild {
		table = z.wildcards
	}
	e := table[name]
	if e == nil {
		e = &entry{}
		table[name] = e
	}
	// A name exists with all its ancestors; *.dev makes dev exist too.
	for n := name; ; n = parent(n) {
		z.exists[n] = true
		if n == "" {
			break
		}
	}

	typ := strings.ToUpper(fields[1])
	if fail, ok := failures[typ]; ok {
		if len(fields) != 2 {
			return fmt.Errorf("%s takes no value", typ)
		}
		if e.fail != nil || e.cname != "" || len(e.a)+len(e.aaaa) > 0 {
			return fmt.Errorf("%s: a failure cannot be combined with other records for the same name", fields[0])
		}
		e.fail = &fail
		return nil
	}
	if len(fields) != 3 {
		return fmt.Errorf("want <name> %s <value>", typ)
	}
	if e.fail != nil {
		return fmt.Errorf("%s: already defined as a failure", fields[0])
	}
	value := fields[2]
	switch typ {
	case "A", "AAAA":
		ip, err := netip.ParseAddr(value)
		if err != nil || (typ == "A") != ip.Is4() {
			return fmt.Errorf("bad %s address %q", typ, value)
		}
		if e.cname != "" {
			return fmt.Errorf("%s: a CNAME cannot be combined with other records", fields[0])
		}
		if typ == "A" {
			e.a = append(e.a, ip.String())
		} else {
			e.aaaa = append(e.aaaa, ip.String())
		}
	case "CNAME":
		if e.cname != "" || len(e.a)+len(e.aaaa) > 0 {
			return fmt.Errorf("%s: a CNAME cannot be combined with other records", fields[0])
		}
		e.cname = strings.ToLower(value)
	default:
		return fmt.Errorf("unknown type %s (known: A, AAAA, CNAME, TIMEOUT, SERVFAIL, REFUSED, NXDOMAIN)", fields[1])
	}
	return nil
}

// parseName returns the relative name and whether it is a wildcard; for
// *.dev the name returned is the wildcard's parent, dev.
func parseName(s string) (string, bool, error) {
	s = strings.ToLower(s)
	if s == "@" {
		return "", false, nil
	}
	if strings.HasSuffix(s, ".") {
		return "", false, fmt.Errorf("%s: names are relative to the scanned domain; drop the trailing dot", s)
	}
	wild := false
	if s == "*" {
		return "", true, nil
	}
	if rest, ok := strings.CutPrefix(s, "*."); ok {
		s, wild = rest, true
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || strings.ContainsAny(label, "*@ ") {
			return "", false, fmt.Errorf("bad name %q", s)
		}
	}
	return s, wild, nil
}

func parent(name string) string {
	_, rest, ok := strings.Cut(name, ".")
	if !ok {
		return ""
	}
	return rest
}

// Answer returns the reply for a name relative to the scanned domain ("" is
// the domain itself). origin is the scanned domain, used to resolve
// relative CNAME targets.
func (z *Zone) Answer(rel, origin string) dnsserver.Reply {
	e := z.entries[rel]
	if e == nil && !z.exists[rel] {
		// RFC 4592: a wildcard applies at the closest existing ancestor.
		enc := parent(rel)
		for !z.exists[enc] {
			enc = parent(enc)
		}
		e = z.wildcards[enc]
		if e == nil {
			return dnsserver.NXDomain
		}
	}
	if e == nil {
		return dnsserver.Reply{} // NODATA: a deeper name exists
	}
	if e.fail != nil {
		return *e.fail
	}
	if e.cname == "" {
		return dnsserver.Reply{A: e.a, AAAA: e.aaaa}
	}
	target := e.cname
	if !strings.HasSuffix(target, ".") {
		target += "." + origin
	}
	target = strings.TrimSuffix(target, ".")
	r := dnsserver.Reply{CNAME: target}
	// Follow an in-zone target one step, as an authoritative server includes
	// the target's addresses when it holds them.
	if t, ok := relative(target, origin); ok {
		if te := z.entries[t]; te != nil && te.fail == nil && te.cname == "" {
			r.A, r.AAAA = te.a, te.aaaa
		}
	}
	return r
}

// relative returns name relative to origin, if name is origin or under it.
func relative(name, origin string) (string, bool) {
	if name == origin {
		return "", true
	}
	rel, ok := strings.CutSuffix(name, "."+origin)
	return rel, ok
}

// Handler answers queries for any of origins (the scanned domains) from the
// zone, applying $DELAY and $REFUSE-ABOVE. Other names are NXDOMAIN.
func (z *Zone) Handler(origins []string) dnsserver.Handler {
	var mu sync.Mutex
	var window time.Time
	var inWindow int
	return func(q dnsserver.Query) dnsserver.Reply {
		if z.RefuseAbove > 0 {
			mu.Lock()
			now := time.Now()
			if now.Sub(window) >= time.Second {
				window, inWindow = now, 0
			}
			inWindow++
			over := inWindow > z.RefuseAbove
			mu.Unlock()
			if over {
				return dnsserver.Refused
			}
		}
		r := dnsserver.NXDomain
		best := -1
		for _, o := range origins {
			if rel, ok := relative(q.Name, o); ok && len(o) > best {
				best = len(o)
				r = z.Answer(rel, o)
			}
		}
		if !r.Drop {
			r.Delay = z.Delay
		}
		return r
	}
}
