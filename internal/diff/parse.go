package diff

import (
	"encoding/csv"
	"encoding/json"
	"os"
	"strings"

	"github.com/TMHSDigital/subenum/internal/dns"
)

// Baseline is a results file read back: its names, and the records behind
// them when the format carries records (JSON, JSONL, CSV; not text).
type Baseline struct {
	Names      map[string]struct{}
	Records    map[string][]dns.Record
	HasRecords bool
}

// Load reads a subenum results file in any output format; see Parse.
func Load(path string) (Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Baseline{}, err
	}
	return Parse(data)
}

// Parse reads the names of a subenum results file in any output format:
// JSONL (summary lines are skipped), a JSON array, CSV, or text (bare names,
// "Found: name", -show-records lines, or -diff's +/-/~ lines). The CLI's
// -diff and -seeds and wordlist-gen's -from share it (#423).
func Parse(data []byte) (Baseline, error) {
	b := Baseline{Names: map[string]struct{}{}, Records: map[string][]dns.Record{}}
	add := func(name string, records ...dns.Record) {
		name = Name(name)
		if name == "" {
			return
		}
		b.Names[name] = struct{}{}
		for _, r := range records {
			if r.Type != "" {
				b.Records[name] = append(b.Records[name], r)
			}
		}
	}
	text := strings.TrimPrefix(string(data), string(rune(0xFEFF)))
	trimmed := strings.TrimSpace(text)

	type result struct {
		Type      string       `json:"type"`
		Subdomain string       `json:"subdomain"`
		Records   []dns.Record `json:"records"`
	}
	if strings.HasPrefix(trimmed, "[") {
		var results []result
		if err := json.Unmarshal([]byte(trimmed), &results); err != nil {
			return Baseline{}, err
		}
		for _, r := range results {
			add(r.Subdomain, r.Records...)
		}
		b.HasRecords = true
		return b, nil
	}
	if strings.HasPrefix(trimmed, "subdomain,") {
		rows, err := csv.NewReader(strings.NewReader(trimmed)).ReadAll()
		if err != nil {
			return Baseline{}, err
		}
		for _, row := range rows[1:] {
			switch {
			case len(row) >= 3:
				add(row[0], dns.Record{Type: row[1], Value: row[2]})
			case len(row) > 0:
				add(row[0])
			}
		}
		b.HasRecords = true
		return b, nil
	}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
			continue
		case strings.HasPrefix(line, "{"):
			var r result
			if err := json.Unmarshal([]byte(line), &r); err != nil {
				return Baseline{}, err
			}
			if r.Type != "summary" {
				add(r.Subdomain, r.Records...)
				b.HasRecords = true
			}
		default:
			for _, p := range []string{"Found (SIMULATED):", "Found:", "+ ", "- ", "~ "} {
				line = strings.TrimSpace(strings.TrimPrefix(line, p))
			}
			if fields := strings.Fields(line); len(fields) > 0 {
				add(fields[0])
			}
		}
	}
	return b, nil
}
