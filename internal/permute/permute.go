// Package permute generates second-pass candidates from names a scan has
// already found (#72): api.example.com suggests api-dev, dev-api, dev.api,
// api2 and so on, the names most likely to exist next to a known one.
package permute

import (
	"sort"
	"strconv"
	"strings"

	"github.com/TMHSDigital/subenum/internal/wordlist"
)

// Words are combined with each seed label. They are the environment, version
// and role names that most often sit next to an existing host.
var Words = []string{
	"dev", "development", "staging", "stage", "stg", "prod", "production",
	"test", "testing", "qa", "uat", "demo", "beta", "alpha", "preview",
	"internal", "int", "ext", "admin", "api", "app", "web", "old", "new",
	"backup", "v1", "v2", "v3", "us", "eu",
}

// Generate returns permutation prefixes (relative to the apex, like wordlist
// entries) for the seed names. A seed is a name relative to the apex:
// "api" for api.example.com, "api.us" for api.us.example.com; its leftmost
// label is permuted and the rest kept. Candidates in skip, and invalid DNS
// labels, are left out. The result is sorted and duplicate-free.
func Generate(seeds []string, words []string, skip map[string]bool) []string {
	out := map[string]bool{}
	add := func(candidate string) {
		entry, ok := wordlist.Normalize(candidate)
		if ok && !skip[entry] {
			out[entry] = true
		}
	}
	for _, seed := range seeds {
		seed = strings.ToLower(strings.Trim(seed, "."))
		if seed == "" {
			continue
		}
		label, rest, _ := strings.Cut(seed, ".")
		join := func(l string) string {
			if rest == "" {
				return l
			}
			return l + "." + rest
		}
		for _, w := range words {
			if w == label {
				continue
			}
			add(join(w + "-" + label))
			add(join(label + "-" + w))
			add(w + "." + seed) // a new level under the known name
		}
		for _, n := range numbered(label) {
			add(join(n))
		}
	}
	result := make([]string, 0, len(out))
	for c := range out {
		result = append(result, c)
	}
	sort.Strings(result)
	return result
}

// numbered returns number variants of label: api -> api1, api2, api3;
// api2 -> api1, api3, api4; web-01 -> web-00, web-02, web-03.
func numbered(label string) []string {
	i := len(label)
	for i > 0 && label[i-1] >= '0' && label[i-1] <= '9' {
		i--
	}
	base, digits := label[:i], label[i:]
	if digits == "" {
		return []string{label + "1", label + "2", label + "3"}
	}
	n, err := strconv.Atoi(digits)
	if err != nil {
		return nil
	}
	pad := func(v int) string {
		s := strconv.Itoa(v)
		for len(s) < len(digits) {
			s = "0" + s
		}
		return base + s
	}
	var out []string
	if n > 0 {
		out = append(out, pad(n-1))
	}
	return append(out, pad(n+1), pad(n+2))
}
