package output

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TMHSDigital/subenum/internal/dns"
)

// TestWriterStampsSeen covers #420: with SetSeen every result found this
// run gets last_seen, and first_seen is the baseline's when it is earlier;
// a removed result keeps what it was given.
func TestWriterStampsSeen(t *testing.T) {
	at := time.Date(2026, 11, 18, 12, 0, 0, 0, time.FixedZone("x", 3600))
	var out bytes.Buffer
	w := New(nil, false, FormatJSONL)
	w.SetStdout(&out)
	w.SetSeen(at, map[string]string{"old.example.com": "2025-01-02T03:04:05Z", "later.example.com": "2027-01-01T00:00:00Z"})
	w.Emit(found("new.example.com", nil))
	w.Emit(found("OLD.example.com", nil))
	w.Emit(found("later.example.com", nil))
	removed := found("gone.example.com", []dns.Record{})
	removed.Change, removed.FirstSeen, removed.LastSeen = "removed", "2024-01-01T00:00:00Z", "2026-01-01T00:00:00Z"
	w.Emit(removed)

	want := map[string][2]string{
		"new.example.com":   {"2026-11-18T11:00:00Z", "2026-11-18T11:00:00Z"},
		"OLD.example.com":   {"2025-01-02T03:04:05Z", "2026-11-18T11:00:00Z"},
		"later.example.com": {"2026-11-18T11:00:00Z", "2026-11-18T11:00:00Z"}, // never later than the run
		"gone.example.com":  {"2024-01-01T00:00:00Z", "2026-01-01T00:00:00Z"},
	}
	for line := range strings.SplitSeq(strings.TrimSpace(out.String()), "\n") {
		var r Result
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatal(err)
		}
		if got := [2]string{r.FirstSeen, r.LastSeen}; got != want[r.Subdomain] {
			t.Errorf("%s: first/last %v, want %v", r.Subdomain, got, want[r.Subdomain])
		}
	}
}

// TestWriterSeenCSVColumns covers #420: CSV gains first_seen and last_seen
// after every other column, with SetSeen or SetSeenColumns, and not without.
func TestWriterSeenCSVColumns(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(*Writer)
		want []string
	}{
		{"none", func(*Writer) {}, []string{"subdomain", "type", "value", "target"}},
		{"stamped", func(w *Writer) { w.SetSeen(time.Unix(0, 0), nil) }, []string{"subdomain", "type", "value", "target", "first_seen", "last_seen"}},
		{"columns only", func(w *Writer) { w.SetSeenColumns(true) }, []string{"subdomain", "type", "value", "target", "first_seen", "last_seen"}},
	} {
		var out bytes.Buffer
		w := New(nil, false, FormatCSV)
		w.SetStdout(&out)
		w.SetTargetColumn(true)
		tc.set(w)
		w.Emit(found("a.example.com", []dns.Record{{Type: "A", Value: "192.0.2.1"}}))
		rows, err := csv.NewReader(&out).ReadAll()
		if err != nil || len(rows) != 2 {
			t.Fatalf("%s: rows %q, err %v", tc.name, rows, err)
		}
		if !slices.Equal(rows[0], tc.want) || len(rows[1]) != len(tc.want) {
			t.Errorf("%s: header %q row %q, want header %q", tc.name, rows[0], rows[1], tc.want)
		}
		if tc.name == "stamped" && rows[1][4] != "1970-01-01T00:00:00Z" {
			t.Errorf("stamped: row %q", rows[1])
		}
	}
}
