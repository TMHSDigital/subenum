package subenum_test

import (
	"slices"
	"testing"

	"github.com/TMHSDigital/subenum/pkg/subenum"
)

func TestPermutations(t *testing.T) {
	got := subenum.Permutations([]string{"API.us.", "", "api.us"}, []string{"dev", "api"})
	want := []string{"api-dev.us", "api1.us", "api2.us", "api3.us", "dev-api.us", "dev.api.us"}
	if !slices.Equal(got, want) {
		t.Fatalf("Permutations = %q, want %q", got, want)
	}
}

func TestPermutationsNilWordsUsesBuiltinList(t *testing.T) {
	got := subenum.Permutations([]string{"api"}, nil)
	for _, name := range []string{"api-staging", "prod-api", "dev.api", "api-v2", "api2"} {
		if !slices.Contains(got, name) {
			t.Errorf("Permutations(nil words) is missing %q", name)
		}
	}
	if !slices.IsSorted(got) || len(slices.Compact(slices.Clone(got))) != len(got) {
		t.Errorf("Permutations(nil words) is not sorted and duplicate-free: %q", got)
	}
	if empty := subenum.Permutations([]string{"api"}, []string{}); len(empty) == 0 || slices.Contains(empty, "api-dev") {
		t.Errorf("Permutations(empty words) = %q, want only numbered variants", empty)
	}
}

func TestPermutationsDropsInvalidLabels(t *testing.T) {
	// "-x" makes "-x.api", whose first label starts with a hyphen.
	if got := subenum.Permutations([]string{"api"}, []string{"-x"}); slices.Contains(got, "-x.api") {
		t.Errorf("Permutations kept the invalid name -x.api: %q", got)
	}
	if got := subenum.Permutations(nil, nil); len(got) != 0 {
		t.Errorf("Permutations(nil, nil) = %q, want none", got)
	}
}
