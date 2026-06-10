package dns

import (
	"sync"
	"testing"
)

func TestSimulateResolve(t *testing.T) {
	runs := 500

	resolved := 0
	for i := 0; i < runs; i++ {
		if _, ok := SimulateResolve("www.example.com", 15, false, DefaultTypes); ok {
			resolved++
		}
	}
	if resolved == 0 {
		t.Errorf("Expected common subdomains to resolve in simulation, got 0/%d", runs)
	}

	resolved = 0
	for i := 0; i < runs; i++ {
		if _, ok := SimulateResolve("zzz-random-prefix.example.com", 0, false, DefaultTypes); ok {
			resolved++
		}
	}
	if resolved != 0 {
		t.Errorf("Expected 0%% hit rate to never resolve, got %d/%d", resolved, runs)
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
	recs, ok := SimulateResolve("zzz.example.com", 100, false, []string{"CNAME"})
	if !ok {
		t.Fatal("expected simulate to resolve at hitRate 100")
	}
	if len(recs) != 1 || recs[0].Type != "CNAME" {
		t.Errorf("expected a single CNAME record, got %v", recs)
	}
}

// TestSimulateResolveConcurrent calls SimulateResolve from many goroutines at
// once. With math/rand/v2 top-level functions this is race-free; the test
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
				SimulateResolve("api.example.com", 50, false, DefaultTypes)
				SimulateResolve("zzz-random.example.com", 25, true, DefaultTypes)
			}
		}()
	}
	wg.Wait()
}
