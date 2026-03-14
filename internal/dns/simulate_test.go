package dns

import (
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
