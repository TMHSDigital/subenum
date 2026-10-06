package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

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
			args := append([]string{"-progress=false", "-w", words}, c.args...)
			code, out := runCLI(t, "", args...)
			if code != c.code {
				t.Fatalf("exit %d, want %d\n%s", code, c.code, out)
			}
			var got []string
			for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
				if line == "" {
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

// TestE2ELabTakeoverHint checks lab 1's dangling CNAME: the external target
// does not exist in the lab, so the result is flagged.
func TestE2ELabTakeoverHint(t *testing.T) {
	code, out := runCLI(t, "", "-progress=false", "-w", "examples/labs/words.txt", "-format", "jsonl",
		"-type", "A,AAAA,CNAME", "-simulate-zone", filepath.Join("examples", "labs", "lab1-first-scan.zone"), "lab.example")
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
