package dns

import (
	"sync"
	"testing"
)

func TestSimulateResolution(t *testing.T) {
	runs := 500

	resolved := 0
	for i := 0; i < runs; i++ {
		if SimulateResolution("www.example.com", 15, false) {
			resolved++
		}
	}
	if resolved == 0 {
		t.Errorf("Expected common subdomains to resolve in simulation, got 0/%d", runs)
	}

	resolved = 0
	for i := 0; i < runs; i++ {
		if SimulateResolution("zzz-random-prefix.example.com", 0, false) {
			resolved++
		}
	}
	if resolved != 0 {
		t.Errorf("Expected 0%% hit rate to never resolve, got %d/%d", resolved, runs)
	}
}

// TestSimulateResolutionConcurrent calls SimulateResolution from many goroutines
// at once. With math/rand/v2 top-level functions this is race-free; the test
// exists to be caught by `go test -race`.
func TestSimulateResolutionConcurrent(t *testing.T) {
	const goroutines = 64
	const perGoroutine = 200

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				SimulateResolution("api.example.com", 50, false)
				SimulateResolution("zzz-random.example.com", 25, true)
			}
		}()
	}
	wg.Wait()
}
