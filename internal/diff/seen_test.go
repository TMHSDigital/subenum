package diff

import (
	"maps"
	"testing"
)

// TestParseSeen covers #420: first_seen and last_seen are read from JSON,
// JSONL and CSV, normalized to UTC, and a name listed twice keeps the
// earliest first_seen and the latest last_seen. Values that are not times
// are ignored.
func TestParseSeen(t *testing.T) {
	wantFirst := map[string]string{"a.example.com": "2025-01-01T00:00:00Z", "b.example.com": "2025-06-01T10:00:00Z"}
	wantLast := map[string]string{"a.example.com": "2026-02-01T00:00:00Z", "b.example.com": "2025-06-01T10:00:00Z"}
	for name, data := range map[string]string{
		"json": `[{"subdomain":"a.example.com","records":[],"first_seen":"2025-03-01T00:00:00Z","last_seen":"2026-01-01T00:00:00Z"},
			{"subdomain":"a.example.com","records":[],"first_seen":"2025-01-01T00:00:00Z","last_seen":"2026-02-01T00:00:00Z"},
			{"subdomain":"b.example.com","records":[],"first_seen":"2025-06-01T12:00:00+02:00","last_seen":"2025-06-01T10:00:00Z"},
			{"subdomain":"c.example.com","records":[],"first_seen":"yesterday"}]`,
		"jsonl": `{"subdomain":"a.example.com","records":[],"first_seen":"2025-03-01T00:00:00Z","last_seen":"2026-02-01T00:00:00Z"}
{"subdomain":"a.example.com","records":[],"first_seen":"2025-01-01T00:00:00Z","last_seen":"2026-01-01T00:00:00Z"}
{"subdomain":"b.example.com","records":[],"first_seen":"2025-06-01T10:00:00Z","last_seen":"2025-06-01T10:00:00Z"}
{"subdomain":"c.example.com","records":[]}
{"type":"summary","first_seen":"2020-01-01T00:00:00Z"}`,
		"csv": "subdomain,type,value,sources,first_seen,last_seen\n" +
			"a.example.com,A,192.0.2.1,wordlist,2025-01-01T00:00:00Z,2026-02-01T00:00:00Z\n" +
			"a.example.com,AAAA,2001:db8::1,wordlist,2025-03-01T00:00:00Z,2026-01-01T00:00:00Z\n" +
			"b.example.com,A,192.0.2.2,wordlist,2025-06-01T10:00:00Z,2025-06-01T10:00:00Z\n" +
			"c.example.com,A,192.0.2.3,wordlist,,\n",
	} {
		b, err := Parse([]byte(data))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !maps.Equal(b.FirstSeen, wantFirst) || !maps.Equal(b.LastSeen, wantLast) {
			t.Errorf("%s: first %v last %v, want %v and %v", name, b.FirstSeen, b.LastSeen, wantFirst, wantLast)
		}
	}
	// Files without the fields, and text, have none.
	for _, data := range []string{"subdomain,type,value\na.example.com,A,192.0.2.1\n", "a.example.com\n"} {
		if b, err := Parse([]byte(data)); err != nil || len(b.FirstSeen)+len(b.LastSeen) != 0 {
			t.Errorf("%q: %v %v %v", data, b.FirstSeen, b.LastSeen, err)
		}
	}
}
