package dns

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"strings"
	"time"
)

// SimulateResolve returns a synthetic DNS result without performing any network
// I/O, along with synthetic records for the requested types when the domain
// "resolves". Exactly hitRate percent (0-100) of names resolve, whatever their
// prefix.
//
// The outcome, records and reported timing are a pure function of (seed,
// domain), so the same seed reproduces the same scan regardless of worker
// scheduling. Callers pick a random seed when the user does not supply one.
func SimulateResolve(domain string, hitRate int, seed uint64, logf Logf, types []string) ([]Record, bool) {
	h := simHash(seed, domain)
	if int(h%100) < hitRate {
		return synthResolved(domain, types, h, logf)
	}
	return synthFailed(domain, h, logf)
}

// simHash mixes the seed and the lowercased name into 64 well-distributed bits.
func simHash(seed uint64, domain string) uint64 {
	f := fnv.New64a()
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], seed)
	_, _ = f.Write(b[:])
	_, _ = f.Write([]byte(strings.ToLower(strings.TrimSuffix(domain, "."))))
	// splitmix64 finalizer: FNV's low bits alone are too regular for h%100.
	x := f.Sum64()
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	x ^= x >> 31
	return x
}

func synthResolved(domain string, types []string, h uint64, logf Logf) ([]Record, bool) {
	if len(types) == 0 {
		types = DefaultTypes
	}
	var records []Record
	for _, t := range types {
		switch t {
		case "A":
			records = append(records, Record{Type: "A", Value: fmt.Sprintf("10.%d.%d.%d", (h>>8)%255, (h>>16)%255, 1+(h>>24)%254)})
		case "AAAA":
			records = append(records, Record{Type: "AAAA", Value: fmt.Sprintf("2001:db8::%x", (h>>32)&0xffff)})
		case "CNAME":
			records = append(records, Record{Type: "CNAME", Value: "target." + domain})
		}
	}
	if len(records) == 0 {
		return nil, false
	}
	if logf != nil {
		fakeTiming := time.Duration(50+(h>>48)%450) * time.Millisecond
		logf("Resolved (SIMULATED): %s (%s: %s) in %s", domain, records[0].Type, records[0].Value, fakeTiming)
	}
	return records, true
}

func synthFailed(domain string, h uint64, logf Logf) ([]Record, bool) {
	if logf != nil {
		fakeTiming := time.Duration(100+(h>>48)%500) * time.Millisecond
		logf("Failed to resolve (SIMULATED): %s (Error: no such host) in %s", domain, fakeTiming)
	}
	return nil, false
}
