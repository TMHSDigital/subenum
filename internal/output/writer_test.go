package output

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/TMHSDigital/subenum/internal/dns"
)

func TestParseFormat(t *testing.T) {
	cases := map[string]Format{
		"":     FormatText,
		"text": FormatText,
		"JSON": FormatJSON,
		"csv":  FormatCSV,
	}
	for in, want := range cases {
		got, err := ParseFormat(in)
		if err != nil {
			t.Errorf("ParseFormat(%q) error: %v", in, err)
		}
		if got != want {
			t.Errorf("ParseFormat(%q) = %v, want %v", in, got, want)
		}
	}
	if _, err := ParseFormat("yaml"); err == nil {
		t.Error("expected error for invalid format")
	}
}

func TestWriterResultText(t *testing.T) {
	tmp, err := os.CreateTemp("", "output-test-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()

	bw := bufio.NewWriter(tmp)
	w := New(bw, false, FormatText)

	domains := []string{"www.example.com", "api.example.com", "mail.example.com"}
	for _, d := range domains {
		w.Result(d, []dns.Record{{Type: "A", Value: "1.2.3.4"}})
	}
	w.Finish()
	if err := bw.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatal(err)
	}

	content, err := os.ReadFile(tmp.Name())
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range domains {
		if !strings.Contains(string(content), d) {
			t.Errorf("expected output file to contain %q\nGot:\n%s", d, content)
		}
	}
}

func TestWriterResultJSONFile(t *testing.T) {
	tmp, err := os.CreateTemp("", "output-json-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()

	bw := bufio.NewWriter(tmp)
	w := New(bw, false, FormatJSON)
	w.Result("www.example.com", []dns.Record{{Type: "A", Value: "93.184.216.34"}})
	w.Result("ipv6.example.com", []dns.Record{{Type: "AAAA", Value: "2606:2800:220:1::1"}})
	w.Finish()
	if err := bw.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatal(err)
	}

	content, err := os.ReadFile(tmp.Name())
	if err != nil {
		t.Fatal(err)
	}

	var results []Result
	if err := json.Unmarshal(content, &results); err != nil {
		t.Fatalf("output is not valid JSON array: %v\nGot:\n%s", err, content)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if results[0].Subdomain != "www.example.com" || results[0].Records[0].Type != "A" {
		t.Errorf("unexpected first result: %+v", results[0])
	}
}

func TestWriterResultCSVFile(t *testing.T) {
	tmp, err := os.CreateTemp("", "output-csv-*.csv")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()

	bw := bufio.NewWriter(tmp)
	w := New(bw, false, FormatCSV)
	w.Result("www.example.com", []dns.Record{
		{Type: "A", Value: "1.1.1.1"},
		{Type: "AAAA", Value: "2606::1"},
	})
	w.Finish()
	if err := bw.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatal(err)
	}

	content, err := os.ReadFile(tmp.Name())
	if err != nil {
		t.Fatal(err)
	}
	got := string(content)
	if !strings.Contains(got, "subdomain,type,value") {
		t.Errorf("expected CSV header, got:\n%s", got)
	}
	if !strings.Contains(got, "www.example.com,A,1.1.1.1") {
		t.Errorf("expected A row, got:\n%s", got)
	}
	if !strings.Contains(got, "www.example.com,AAAA,2606::1") {
		t.Errorf("expected AAAA row, got:\n%s", got)
	}
}
