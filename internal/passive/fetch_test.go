package passive

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
)

// TestGather covers #355: the one fan-out the CLI, the TUI and pkg/subenum
// share sorts every answer the same way, in the order asked.
func TestGather(t *testing.T) {
	tr := &Truncated{Source: "ct", Why: "read limit"}
	answers := []struct {
		names []string
		err   error
	}{
		{[]string{"a", "b"}, nil},
		{[]string{"c"}, tr},
		{[]string{"ignored"}, errors.New("502 Bad Gateway")},
		{nil, nil},
		{[]string{"d"}, fmt.Errorf("wrapped: %w", tr)},
	}
	got := Gather(len(answers), func(i int) ([]string, error) {
		return answers[i].names, answers[i].err
	})
	want := []Lookup{
		{Names: []string{"a", "b"}, Fetched: true},
		{Names: []string{"c"}, Fetched: true, Truncated: tr.Error()},
		{Err: "502 Bad Gateway"},
		{Fetched: true},
		{Names: []string{"d"}, Fetched: true, Truncated: "wrapped: " + tr.Error()},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Gather = %+v\nwant %+v", got, want)
	}
	if got := Gather(0, nil); len(got) != 0 {
		t.Errorf("Gather(0) = %v, want none", got)
	}
}

func TestFetchAllUnknownSource(t *testing.T) {
	got := FetchAll(t.Context(), []string{"nope"}, Options{}, "example.com")
	if len(got) != 1 || got[0].Source != "nope" || got[0].Fetched || got[0].Err != `unknown source "nope"` {
		t.Errorf("FetchAll = %+v, want one failed lookup named nope", got)
	}
}

func TestMessages(t *testing.T) {
	if got, want := UserAgent("subenum/v1.0.0"), "subenum/v1.0.0 (+https://github.com/TMHSDigital/subenum)"; got != want {
		t.Errorf("UserAgent = %q, want %q", got, want)
	}
	if got, want := AddedLine("Wayback Machine", 2, "example.com", 1), "Wayback Machine: 2 names under example.com, 1 of them new candidates"; got != want {
		t.Errorf("AddedLine = %q, want %q", got, want)
	}
}
