package permute

import (
	"slices"
	"testing"
)

func TestGenerate(t *testing.T) {
	got := Generate([]string{"api", "web02.us"}, []string{"dev", "api"}, map[string]bool{"api-dev": false, "dev.api": true})
	for _, want := range []string{
		"api-dev", "dev-api", // word joins
		"api1", "api2", "api3", // numbering a bare label
		"web01.us", "web03.us", "web04.us", // numbering keeps width and the rest of the name
		"dev-web02.us", "web02-dev.us", "dev.web02.us", "api-web02.us",
	} {
		if !slices.Contains(got, want) {
			t.Errorf("missing %q in %v", want, got)
		}
	}
	for _, unwanted := range []string{"dev.api", "api-api", "api"} {
		if slices.Contains(got, unwanted) {
			t.Errorf("%q should not be generated (skipped, self-join or the seed itself)", unwanted)
		}
	}
	if !slices.IsSorted(got) {
		t.Error("output is not sorted")
	}
}

func TestNumbered(t *testing.T) {
	for in, want := range map[string][]string{
		"api":    {"api1", "api2", "api3"},
		"api0":   {"api1", "api2"},
		"web-09": {"web-08", "web-10", "web-11"},
	} {
		if got := numbered(in); !slices.Equal(got, want) {
			t.Errorf("numbered(%q) = %v, want %v", in, got, want)
		}
	}
}
