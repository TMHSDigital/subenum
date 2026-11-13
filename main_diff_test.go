package main

import (
	"testing"
)

// TestLoadBaselineRecords: structured formats carry records, text does not.
func TestLoadBaselineRecords(t *testing.T) {
	for _, c := range []struct {
		name, content string
		hasRecords    bool
	}{
		{"jsonl", `{"subdomain":"www.example.com","records":[{"type":"A","value":"192.0.2.1"}]}` + "\n", true},
		{"json", `[{"subdomain":"www.example.com","records":[{"type":"A","value":"192.0.2.1"}]}]`, true},
		{"csv", "subdomain,type,value\nwww.example.com,A,192.0.2.1\n", true},
		{"text", "www.example.com\n", false},
	} {
		b, err := loadBaseline(writeFile(t, c.name, c.content))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if _, ok := b.names["www.example.com"]; !ok || b.hasRecords != c.hasRecords {
			t.Errorf("%s: names %v, hasRecords %v; want www and %v", c.name, b.names, b.hasRecords, c.hasRecords)
		}
		if c.hasRecords && (len(b.records["www.example.com"]) != 1 || b.records["www.example.com"][0].Value != "192.0.2.1") {
			t.Errorf("%s: records %v", c.name, b.records)
		}
	}
}
