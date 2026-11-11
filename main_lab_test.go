package main

import (
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/TMHSDigital/subenum/internal/dns"
)

// labTimingArgs gives lab runs a generous per-query timeout and retries. The
// lab server is in-process, so the CLI's 1 s default is ample on an idle
// machine but not under -race and coverage on a busy CI runner (#167).
var labTimingArgs = []string{"-timeout", "5000", "-attempts", "3"}

// TestE2ELabs runs the shipped -simulate-zone scenarios end to end (#76) and
// checks the answers the Labs page gives for them.
func TestE2ELabs(t *testing.T) {
	const words = "examples/labs/words.txt"
	lab := func(name string) string { return filepath.Join("examples", "labs", name) }
	cases := []struct {
		name string
		args []string
		code int
		want []string
	}{
		{
			name: "lab1 first scan",
			args: []string{"-simulate-zone", lab("lab1-first-scan.zone"), "lab.example"},
			want: []string{"jenkins", "mail", "shop", "vpn", "www"},
		},
		{
			name: "lab1 with CNAME lookups",
			args: []string{"-simulate-zone", lab("lab1-first-scan.zone"), "-type", "A,AAAA,CNAME", "lab.example"},
			want: []string{"blog", "jenkins", "mail", "shop", "vpn", "www"},
		},
		{
			name: "lab2 wildcard stops the scan",
			args: []string{"-simulate-zone", lab("lab2-wildcard.zone"), "lab.example"},
			code: exitFailure,
		},
		{
			name: "lab2 -force filters the wildcard",
			args: []string{"-simulate-zone", lab("lab2-wildcard.zone"), "-force", "lab.example"},
			want: []string{"intranet", "portal", "www"},
		},
		{
			name: "lab4 flat",
			args: []string{"-simulate-zone", lab("lab4-recursive.zone"), "lab.example"},
			want: []string{"corp", "dev", "www"},
		},
		{
			name: "lab4 recursive",
			args: []string{"-simulate-zone", lab("lab4-recursive.zone"), "-recursive", "-depth", "3", "lab.example"},
			want: []string{"admin.staging.dev", "api.dev", "corp", "dev", "git.dev", "staging.dev", "vpn.corp", "www"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			args := append(append([]string{"-progress=false", "-w", words}, labTimingArgs...), c.args...)
			code, out := runCLIMerged(t, args...)
			if code != c.code {
				t.Fatalf("exit %d, want %d\n%s", code, c.code, out)
			}
			// A timed-out wildcard probe makes -force report every word,
			// which is the regression lab 2 exists to catch; name it.
			if strings.Contains(out, "wildcard detection failed") {
				t.Fatalf("wildcard probe failed, so results were not filtered:\n%s", out)
			}
			// Results are bare hostnames; diagnostics share the stream.
			var got []string
			for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
				line = strings.TrimSpace(line)
				if strings.ContainsAny(line, " \t") || !strings.HasSuffix(line, ".lab.example") {
					continue
				}
				got = append(got, strings.TrimSuffix(line, ".lab.example"))
			}
			slices.Sort(got)
			if !slices.Equal(got, c.want) {
				t.Errorf("found %v, want %v", got, c.want)
			}
		})
	}
}

// TestE2ELabVerdicts checks the run-quality verdicts of the failure labs.
func TestE2ELabVerdicts(t *testing.T) {
	for _, c := range []struct {
		zone, verdict string
		args          []string
	}{
		{zone: "lab3-rate-limit.zone", verdict: "unreliable"},
		{zone: "lab3-rate-limit.zone", verdict: "complete", args: []string{"-rate", "30"}},
		{zone: "lab5-failures.zone", verdict: "degraded", args: []string{"-timeout", "200"}},
	} {
		t.Run(c.zone+strings.Join(c.args, ""), func(t *testing.T) {
			stats := filepath.Join(t.TempDir(), "run.json")
			args := append([]string{"-progress=false", "-w", "examples/labs/words.txt", "-stats", stats,
				"-simulate-zone", filepath.Join("examples", "labs", c.zone)}, c.args...)
			if code, out := runCLI(t, "", append(args, "lab.example")...); code != 0 {
				t.Fatalf("exit %d\n%s", code, out)
			}
			data, err := os.ReadFile(stats)
			if err != nil {
				t.Fatal(err)
			}
			var sum struct {
				Verdict string `json:"verdict"`
				Zone    string `json:"zone"`
			}
			if err := json.Unmarshal(data, &sum); err != nil {
				t.Fatal(err)
			}
			if sum.Verdict != c.verdict || !strings.HasSuffix(sum.Zone, c.zone) {
				t.Errorf("verdict %q zone %q, want %q and the zone file", sum.Verdict, sum.Zone, c.verdict)
			}
		})
	}
}

// TestE2EMaxDuration covers #190: a run that hits its time budget still ends
// with a report, a degraded verdict and stopped_by "duration", and a negative
// budget is a usage error.
func TestE2EMaxDuration(t *testing.T) {
	stats := filepath.Join(t.TempDir(), "run.json")
	// -rate 10 with 30 words needs about 3 s; the budget is a third of that.
	code, out := runCLI(t, "", "-progress=false", "-w", "examples/labs/words.txt", "-t", "2", "-rate", "10",
		"-max-duration", "1s", "-stats", stats, "-simulate-zone", filepath.Join("examples", "labs", "lab1-first-scan.zone"), "lab.example")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	data, err := os.ReadFile(stats)
	if err != nil {
		t.Fatal(err)
	}
	var sum struct {
		Verdict string `json:"verdict"`
		Reason  string `json:"reason"`
		Targets []struct {
			Skipped   int64  `json:"skipped_by_cap"`
			StoppedBy string `json:"stopped_by"`
		} `json:"targets"`
	}
	if err := json.Unmarshal(data, &sum); err != nil {
		t.Fatal(err)
	}
	if sum.Verdict != "degraded" || !strings.Contains(sum.Reason, "-max-duration") {
		t.Errorf("verdict %q (%s), want degraded naming -max-duration", sum.Verdict, sum.Reason)
	}
	if len(sum.Targets) != 1 || sum.Targets[0].StoppedBy != "duration" || sum.Targets[0].Skipped == 0 {
		t.Errorf("targets %+v, want one stopped by duration with names skipped", sum.Targets)
	}

	if code, _ := runCLI(t, "", "-simulate", "-max-duration", "-1s", "example.com"); code != exitUsage {
		t.Errorf("negative -max-duration: exit %d, want %d", code, exitUsage)
	}
}

// TestE2EDiffRecords covers #189: with -diff-records a name found again
// with a re-pointed CNAME or a moved address is reported as changed, with
// its previous records, counted in the report and exit code 4. Without the
// flag, or against a text baseline, only names are compared.
func TestE2EDiffRecords(t *testing.T) {
	zone := filepath.Join("examples", "labs", "lab1-first-scan.zone")
	// Lab 1 as it was "last week": blog pointed at the blog host, www had
	// another address, and shop's alias (and the address behind it) is as
	// now, so it must not be flagged.
	baseline := writeFile(t, "previous.jsonl", strings.Join([]string{
		`{"subdomain":"jenkins.lab.example","records":[{"type":"A","value":"192.0.2.40"}]}`,
		`{"subdomain":"mail.lab.example","records":[{"type":"A","value":"192.0.2.20"}]}`,
		`{"subdomain":"www.lab.example","records":[{"type":"A","value":"192.0.2.99"}]}`,
		`{"subdomain":"vpn.lab.example","records":[{"type":"A","value":"192.0.2.30"}]}`,
		`{"subdomain":"blog.lab.example","records":[{"type":"CNAME","value":"blog-host.example.net"}]}`,
		`{"subdomain":"shop.lab.example","records":[{"type":"A","value":"192.0.2.77"},{"type":"CNAME","value":"www.lab.example"}]}`,
		`{"type":"summary","schema":1}`,
	}, "\n")+"\n")
	scanArgs := func(extra ...string) []string {
		args := append([]string{"-progress=false", "-format", "jsonl", "-type", "A,CNAME", "-w", "examples/labs/words.txt"}, labTimingArgs...)
		return append(append(args, extra...), "-simulate-zone", zone, "lab.example")
	}
	type line struct {
		Type      string       `json:"type"`
		Subdomain string       `json:"subdomain"`
		Change    string       `json:"change"`
		Previous  []dns.Record `json:"previous_records"`
		Diff      *struct {
			Changed int `json:"changed"`
		} `json:"diff"`
	}
	parse := func(out string) (changes map[string]line, summary line) {
		changes = map[string]line{}
		for _, raw := range strings.Split(strings.TrimSpace(out), "\n") {
			var l line
			if err := json.Unmarshal([]byte(raw), &l); err != nil {
				t.Fatalf("%v: %s", err, raw)
			}
			if l.Type == "summary" {
				summary = l
			} else {
				changes[l.Subdomain] = l
			}
		}
		return changes, summary
	}

	code, out := runCLI(t, "", scanArgs("-diff", baseline, "-diff-records")...)
	if code != exitChanges {
		t.Fatalf("exit %d, want %d\n%s", code, exitChanges, out)
	}
	changes, summary := parse(out)
	blog, www := changes["blog.lab.example"], changes["www.lab.example"]
	if blog.Change != "changed" || len(blog.Previous) != 1 || blog.Previous[0].Value != "blog-host.example.net" {
		t.Errorf("blog = %+v, want changed from blog-host.example.net", blog)
	}
	if www.Change != "changed" || len(www.Previous) != 1 || www.Previous[0].Value != "192.0.2.99" {
		t.Errorf("www = %+v, want changed from 192.0.2.99", www)
	}
	if _, ok := changes["shop.lab.example"]; ok || len(changes) != 2 {
		t.Errorf("changes %v, want only blog and www (shop's alias is unchanged)", changes)
	}
	if summary.Diff == nil || summary.Diff.Changed != 2 {
		t.Errorf("summary diff %+v, want changed 2", summary.Diff)
	}

	// Without the flag the names match: nothing to report.
	if code, out := runCLI(t, "", scanArgs("-diff", baseline)...); code != exitOK {
		t.Errorf("without -diff-records: exit %d, want %d\n%s", code, exitOK, out)
	}
	// A text baseline has no records to compare.
	text := writeFile(t, "previous.txt", "jenkins.lab.example\nmail.lab.example\nwww.lab.example\nvpn.lab.example\nblog.lab.example\nshop.lab.example\n")
	if code, out := runCLIMerged(t, scanArgs("-diff", text, "-diff-records")...); code != exitOK || !strings.Contains(out, "only names are compared") {
		t.Errorf("text baseline: exit %d, want %d with a note\n%s", code, exitOK, out)
	}
	if code, _ := runCLI(t, "", "-simulate", "-diff-records", "example.com"); code != exitUsage {
		t.Errorf("-diff-records without -diff: exit %d, want %d", code, exitUsage)
	}
}

// TestE2ELabTakeoverHint checks lab 1's dangling CNAME: the external target
// does not exist in the lab, so the result is flagged.
func TestE2ELabTakeoverHint(t *testing.T) {
	args := append([]string{"-progress=false", "-w", "examples/labs/words.txt", "-format", "jsonl"}, labTimingArgs...)
	code, out := runCLI(t, "", append(args,
		"-type", "A,AAAA,CNAME", "-simulate-zone", filepath.Join("examples", "labs", "lab1-first-scan.zone"), "lab.example")...)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		var r struct {
			Subdomain string `json:"subdomain"`
			Takeover  string `json:"takeover_candidate"`
		}
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("%v: %s", err, line)
		}
		if want := map[bool]string{true: "dangling"}[r.Subdomain == "blog.lab.example"]; r.Takeover != want {
			t.Errorf("%s: takeover %q, want %q", r.Subdomain, r.Takeover, want)
		}
	}
}

// TestE2ELabDanglingNS covers #194: in a lab zone, -type NS reports a
// delegated subzone, flags the one whose name server does not exist as
// dangling-ns, and -sarif writes it; MX and TXT records come back too.
func TestE2ELabDanglingNS(t *testing.T) {
	zone := writeFile(t, "ns.zone", strings.Join([]string{
		"@      A    192.0.2.1",
		"mail   MX   10 mx1",
		"mail   TXT  \"v=spf1 -all\"",
		"mx1    A    192.0.2.25",
		"ns1    A    192.0.2.53",
		"ok     NS   ns1",
		"old    NS   ns1.gone-dns.example.",
		"www    A    192.0.2.10",
	}, "\n"))
	words := writeFile(t, "words.txt", "ok\nold\nwww\nmail\n")
	sarif := filepath.Join(t.TempDir(), "takeovers.sarif")
	args := append([]string{"-progress=false", "-format", "jsonl", "-w", words, "-type", "NS,MX,TXT", "-sarif", sarif}, labTimingArgs...)
	code, out := runCLI(t, "", append(args, "-simulate-zone", zone, "lab.example")...)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	takeover := map[string]string{}
	var mail []dns.Record
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		var r struct {
			Type      string       `json:"type"`
			Subdomain string       `json:"subdomain"`
			Records   []dns.Record `json:"records"`
			Takeover  string       `json:"takeover_candidate"`
		}
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("%v: %s", err, line)
		}
		if r.Type != "summary" {
			takeover[r.Subdomain] = r.Takeover
		}
		if r.Subdomain == "mail.lab.example" {
			mail = r.Records
		}
	}
	if want := []dns.Record{{Type: "MX", Value: "10 mx1.lab.example"}, {Type: "TXT", Value: "v=spf1 -all"}}; !slices.Equal(mail, want) {
		t.Errorf("mail records = %v, want %v", mail, want)
	}
	if want := map[string]string{"ok.lab.example": "", "old.lab.example": "dangling-ns", "mail.lab.example": ""}; !maps.Equal(takeover, want) {
		t.Errorf("results = %v, want %v (www has no NS, MX or TXT)", takeover, want)
	}
	data, err := os.ReadFile(sarif)
	if err != nil || !strings.Contains(string(data), `"ruleId": "subenum/dangling-ns"`) {
		t.Errorf("SARIF lacks the dangling-ns result (err %v):\n%s", err, data)
	}
}

func TestE2ELabFlagConflicts(t *testing.T) {
	zone := filepath.Join("examples", "labs", "lab1-first-scan.zone")
	resolvers := writeFile(t, "resolvers.txt", "192.0.2.53\n")
	for _, extra := range [][]string{{"-simulate"}, {"-dns-server", "1.1.1.1:53"}, {"-r", resolvers}} {
		args := append([]string{"-simulate-zone", zone}, extra...)
		if code, _ := runCLI(t, "", append(args, "lab.example")...); code != exitUsage {
			t.Errorf("%v: exit %d, want %d", extra, code, exitUsage)
		}
	}
	bad := writeFile(t, "bad.zone", "www A not-an-ip\n")
	if code, _ := runCLI(t, "", "-simulate-zone", bad, "lab.example"); code != exitFailure {
		t.Errorf("bad zone file: exit %d, want %d", code, exitFailure)
	}
}

// TestE2ELabRefusesEnvAndConfigResolvers covers #106: a resolver list or
// simulation mode from SUBENUM_* or the config file must not turn a lab run
// into one that sends queries off the machine.
func TestE2ELabRefusesEnvAndConfigResolvers(t *testing.T) {
	zone := filepath.Join("examples", "labs", "lab1-first-scan.zone")
	resolvers := writeFile(t, "resolvers.txt", "192.0.2.53\n")
	for _, c := range []struct{ env, value, want string }{
		{"SUBENUM_R", resolvers, "SUBENUM_R"},
		{"SUBENUM_SIMULATE", "true", "SUBENUM_SIMULATE"},
		{"SUBENUM_DNS_SERVER", "192.0.2.1:53", "SUBENUM_DNS_SERVER"},
		{configEnv, writeFile(t, "config.json", `{"r": "`+filepath.ToSlash(resolvers)+`"}`), "config file"},
	} {
		t.Run(c.env, func(t *testing.T) {
			t.Setenv(c.env, c.value)
			code, out := runCLIMerged(t, "-simulate-zone", zone, "lab.example")
			if code != exitUsage || !strings.Contains(out, c.want) {
				t.Errorf("exit %d, want %d naming %q\n%s", code, exitUsage, c.want, out)
			}
			if strings.Contains(out, "Resolver pool") {
				t.Errorf("the resolver pool was loaded:\n%s", out)
			}
		})
	}
}

// TestE2ESARIF covers #129: lab 1's dangling CNAME becomes a SARIF result
// with a rule, a location and a stable fingerprint.
func TestE2ESARIF(t *testing.T) {
	zone := filepath.Join("examples", "labs", "lab1-first-scan.zone")
	path := filepath.Join(t.TempDir(), "takeovers.sarif")
	args := append([]string{"-progress=false"}, labTimingArgs...)
	if code, _ := runCLI(t, "", append(args, "-type", "A,CNAME", "-sarif", path, "-simulate-zone", zone, "lab.example")...); code != 0 {
		t.Fatalf("exit %d", code)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var log struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string                `json:"ruleId"`
				Message   struct{ Text string } `json:"message"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct{ URI string } `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				PartialFingerprints map[string]string `json:"partialFingerprints"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatal(err)
	}
	if log.Version != "2.1.0" || len(log.Runs) != 1 || log.Runs[0].Tool.Driver.Name != "subenum" {
		t.Fatalf("not a SARIF 2.1.0 subenum log:\n%s", data)
	}
	run := log.Runs[0]
	if len(run.Results) != 1 {
		t.Fatalf("got %d results, want lab 1's one dangling CNAME:\n%s", len(run.Results), data)
	}
	r := run.Results[0]
	if r.RuleID != "subenum/dangling-cname" || len(run.Tool.Driver.Rules) != 1 || run.Tool.Driver.Rules[0].ID != r.RuleID {
		t.Errorf("rule %q, rules %+v", r.RuleID, run.Tool.Driver.Rules)
	}
	if len(r.Locations) != 1 || r.Locations[0].PhysicalLocation.ArtifactLocation.URI != "blog.lab.example" || r.PartialFingerprints["subenumTakeover/v1"] == "" {
		t.Errorf("result = %+v", r)
	}
	if !strings.Contains(r.Message.Text, "ghost-lab.example.net") {
		t.Errorf("message %q does not name the CNAME target", r.Message.Text)
	}
}
