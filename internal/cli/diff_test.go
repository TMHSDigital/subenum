package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// TestDiffSubcommand: `subenum diff` compares two saved files offline (#310):
// added, missing and (with -records) changed names, exit 4 on differences.
func TestDiffSubcommand(t *testing.T) {
	prev := writeFile(t, "prev.jsonl", strings.Join([]string{
		`{"subdomain":"www.example.com","records":[{"type":"A","value":"192.0.2.1"}]}`,
		`{"subdomain":"old.example.com","records":[{"type":"A","value":"192.0.2.2"}]}`,
		`{"subdomain":"cdn.example.com","records":[{"type":"CNAME","value":"a.cdn.test"},{"type":"A","value":"192.0.2.3"}]}`,
		`{"type":"summary","verdict":"complete"}`,
	}, "\n")+"\n")
	cur := writeFile(t, "cur.csv", "subdomain,type,value\n"+
		"WWW.example.com.,A,192.0.2.9\n"+
		"new.example.com,A,192.0.2.4\n"+
		"cdn.example.com,CNAME,b.cdn.test\n")
	run := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := runWith(runArgs{args: append([]string{"diff"}, args...), stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr})
		return code, stdout.String(), stderr.String()
	}

	code, out, errOut := run(prev, cur)
	if want := "+ new.example.com\n- old.example.com\n"; code != exitChanges || out != want {
		t.Fatalf("names only: code %d, stdout %q (stderr %q); want %d, %q", code, out, errOut, exitChanges, want)
	}

	code, out, _ = run("-records", prev, cur)
	if want := "+ new.example.com A=192.0.2.4\n~ cdn.example.com CNAME=b.cdn.test (was CNAME=a.cdn.test A=192.0.2.3)\n~ www.example.com A=192.0.2.9 (was A=192.0.2.1)\n- old.example.com A=192.0.2.2\n"; code != exitChanges || out != want {
		t.Fatalf("-records: code %d, stdout %q; want %q", code, out, want)
	}

	// -type CNAME leaves www's moved address out of the comparison.
	code, out, _ = run("-records", "-type", "CNAME", "-format", "jsonl", prev, cur)
	changes := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		var r struct{ Subdomain, Change string }
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("jsonl line %q: %v", line, err)
		}
		changes[r.Subdomain] = r.Change
	}
	want := map[string]string{"new.example.com": "added", "old.example.com": "missing", "cdn.example.com": "changed"}
	if code != exitChanges || len(changes) != len(want) {
		t.Fatalf("-type CNAME jsonl: code %d, changes %v; want %v", code, changes, want)
	}
	for name, c := range want {
		if changes[name] != c {
			t.Errorf("-type CNAME jsonl: %s is %q, want %q", name, changes[name], c)
		}
	}

	// The same file on both sides: no output, exit 0.
	if code, out, _ := run("-records", prev, prev); code != exitOK || out != "" {
		t.Errorf("identical files: code %d, stdout %q; want 0 and nothing", code, out)
	}

	// -records with a text file falls back to names, and says so.
	text := writeFile(t, "cur.txt", "www.example.com\ncdn.example.com\nold.example.com\n")
	if code, out, errOut := run("-records", prev, text); code != exitOK || out != "" || !strings.Contains(errOut, "comparing names only") {
		t.Errorf("text file: code %d, stdout %q, stderr %q", code, out, errOut)
	}

	for _, args := range [][]string{{prev}, {prev, cur, cur}, {"-format", "xml", prev, cur}, {"-type", "SRV", prev, cur}} {
		if code, _, _ := run(args...); code != exitUsage {
			t.Errorf("diff %v: code %d, want %d", args, code, exitUsage)
		}
	}
	if code, _, _ := run(prev, writeFile(t, "dir", "")+"-does-not-exist"); code != exitFailure {
		t.Errorf("missing file: code %d, want %d", code, exitFailure)
	}
}

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
