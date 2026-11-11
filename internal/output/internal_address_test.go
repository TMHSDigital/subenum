package output

import (
	"strings"
	"testing"

	"github.com/TMHSDigital/subenum/internal/dns"
	"github.com/TMHSDigital/subenum/internal/scan"
)

// TestInternalAddressOutput covers #218: the scope appears in JSONL, in a
// CSV column and in text with -show-records.
func TestInternalAddressOutput(t *testing.T) {
	recs := []dns.Record{{Type: "A", Value: "10.0.0.1"}}
	run := func(format Format, setup func(*Writer)) string {
		w := New(nil, false, format)
		w.SetPlain(true)
		setup(w)
		return captureStdout(t, func() {
			w.Emit(Result{Result: scan.Result{Subdomain: "leaky.example.com", Records: recs, InternalAddress: "private"}})
			_ = w.Finish()
		})
	}
	if out := run(FormatJSONL, func(*Writer) {}); !strings.Contains(out, `"internal_address":"private"`) {
		t.Errorf("jsonl: %q", out)
	}
	if out := run(FormatCSV, func(w *Writer) { w.SetInternalColumn(true) }); !strings.Contains(out, "internal_address\n") || !strings.Contains(out, ",private\n") {
		t.Errorf("csv: %q", out)
	}
	if out := run(FormatText, func(w *Writer) { w.SetShowRecords(true) }); !strings.Contains(out, "INTERNAL=private") {
		t.Errorf("text: %q", out)
	}
	if out := run(FormatText, func(*Writer) {}); out != "leaky.example.com\n" {
		t.Errorf("text without -show-records = %q, want the bare name", out)
	}
}

// TestInternalAddressColumnOnlyWhenAsked covers #218: the CSV column is
// added, never a renamed one, so a CSV file written without addresses keeps
// the columns it had.
func TestInternalAddressColumnOnlyWhenAsked(t *testing.T) {
	recs := []dns.Record{{Type: "A", Value: "10.0.0.1"}}
	run := func(setup func(*Writer)) string {
		w := New(nil, false, FormatCSV)
		w.SetPlain(true)
		setup(w)
		return captureStdout(t, func() {
			w.Emit(Result{Result: scan.Result{Subdomain: "leaky.example.com", Records: recs, InternalAddress: "private"}})
			_ = w.Finish()
		})
	}
	if out := run(func(*Writer) {}); strings.Contains(out, "internal_address") {
		t.Errorf("csv without the column = %q, want no internal_address column", out)
	}
	if out := run(func(w *Writer) { w.SetInternalColumn(true) }); !strings.Contains(out, "subdomain,type,value,internal_address\n") {
		t.Errorf("csv with the column = %q, want the column after the existing ones", out)
	}
}
