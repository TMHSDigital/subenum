package dns

import (
	"fmt"
	"reflect"
	"sync"
	"testing"
)

func TestSimulateResolve(t *testing.T) {
	for seed := uint64(0); seed < 200; seed++ {
		if _, ok := SimulateResolve("zzz-random-prefix.example.com", 0, seed, nil, DefaultTypes); ok {
			t.Fatalf("seed %d: 0%% hit rate resolved", seed)
		}
		if _, ok := SimulateResolve("zzz-random-prefix.example.com", 100, seed, nil, DefaultTypes); !ok {
			t.Fatalf("seed %d: 100%% hit rate did not resolve", seed)
		}
	}
}

// TestSimulateHitRateHonored covers #44: -hit-rate applies uniformly, with no
// hidden 90% boost for common prefixes like www or api.
func TestSimulateHitRateHonored(t *testing.T) {
	const n = 5000
	for _, prefix := range []string{"www", "api", "p"} {
		hits := 0
		for i := 0; i < n; i++ {
			if _, ok := SimulateResolve(fmt.Sprintf("%s.example.com", prefix), 10, uint64(i), nil, DefaultTypes); ok {
				hits++
			}
		}
		if pct := hits * 100 / n; pct < 7 || pct > 13 {
			t.Errorf("prefix %q: %d%% resolved at -hit-rate 10", prefix, pct)
		}
	}
}

// TestSimulateDeterministic covers #44: the same seed reproduces the same
// outcome and records; a different seed generally does not.
func TestSimulateDeterministic(t *testing.T) {
	differs := false
	for i := 0; i < 100; i++ {
		name := fmt.Sprintf("h%d.example.com", i)
		r1, ok1 := SimulateResolve(name, 50, 42, nil, DefaultTypes)
		r2, ok2 := SimulateResolve(name, 50, 42, nil, DefaultTypes)
		if ok1 != ok2 || !reflect.DeepEqual(r1, r2) {
			t.Fatalf("%s: seed 42 not reproducible: %v/%v vs %v/%v", name, ok1, r1, ok2, r2)
		}
		if _, ok3 := SimulateResolve(name, 50, 43, nil, DefaultTypes); ok3 != ok1 {
			differs = true
		}
	}
	if !differs {
		t.Error("seeds 42 and 43 produced identical outcomes for 100 names")
	}
}

func TestParseTypes(t *testing.T) {
	got, err := ParseTypes("a, cname ,A")
	if err != nil {
		t.Fatalf("ParseTypes error: %v", err)
	}
	if len(got) != 2 || got[0] != "A" || got[1] != "CNAME" {
		t.Errorf("ParseTypes dedup/normalize failed: %v", got)
	}

	if d, _ := ParseTypes(""); len(d) != 2 || d[0] != "A" || d[1] != "AAAA" {
		t.Errorf("empty should default to A,AAAA, got %v", d)
	}

	if _, err := ParseTypes("MX"); err == nil {
		t.Error("expected error for unsupported type MX")
	}
}

func TestSimulateResolveTypes(t *testing.T) {
	// Force a resolve with hitRate 100 and request only CNAME.
	recs, ok := SimulateResolve("zzz.example.com", 100, 1, nil, []string{"CNAME"})
	if !ok {
		t.Fatal("expected simulate to resolve at hitRate 100")
	}
	if len(recs) != 1 || recs[0].Type != "CNAME" {
		t.Errorf("expected a single CNAME record, got %v", recs)
	}
}

// TestSimulateResolveConcurrent calls SimulateResolve from many goroutines at
// once. Results are a pure function of (seed, name), so this is race-free; the test
// exists to be caught by `go test -race`.
func TestSimulateResolveConcurrent(t *testing.T) {
	const goroutines = 64
	const perGoroutine = 200

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				SimulateResolve("api.example.com", 50, uint64(i), nil, DefaultTypes)
				SimulateResolve("zzz-random.example.com", 25, uint64(i), func(string, ...any) {}, DefaultTypes)
			}
		}()
	}
	wg.Wait()
}
