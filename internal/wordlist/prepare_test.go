package wordlist

import (
	"fmt"
	"math/rand/v2"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// referenceBuild is Build as it was before #182: a regexp per label and
// normalization per target. Prepare and For must agree with it exactly.
func referenceBuild(lines []string, domain string) (entries []string, duplicates, skipped int) {
	labelRE := regexp.MustCompile(`^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$`)
	normalize := func(line string) (string, bool) {
		entry := strings.TrimSuffix(strings.ToLower(SanitizeLine(line)), ".")
		if entry == "" || strings.HasPrefix(entry, "#") {
			return "", false
		}
		for _, label := range strings.Split(entry, ".") {
			if !labelRE.MatchString(label) {
				return "", false
			}
		}
		return entry, true
	}
	apexLen := len(strings.TrimSuffix(domain, "."))
	seen := map[string]struct{}{}
	for _, line := range lines {
		if IsComment(line) {
			continue
		}
		entry, ok := normalize(line)
		if !ok || len(entry)+1+apexLen > maxNameLen {
			skipped++
			continue
		}
		if _, exists := seen[entry]; exists {
			duplicates++
			continue
		}
		seen[entry] = struct{}{}
		entries = append(entries, entry)
	}
	return entries, duplicates, skipped
}

// TestPrepareMatchesReference covers #182: normalizing once and filtering by
// length per target gives the entries, duplicate and skip counts the old
// per-target Build gave, including over-long entries that repeat.
func TestPrepareMatchesReference(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	pieces := []string{"a", "Z", "0", "_", "-", ".", " ", "#", "*", "é", "dev", "api", strings.Repeat("x", 60), strings.Repeat("y", 64)}
	var lines []string
	for range 5000 {
		var b strings.Builder
		for range rng.IntN(8) {
			b.WriteString(pieces[rng.IntN(len(pieces))])
		}
		lines = append(lines, b.String())
	}
	// Long multi-label entries near the 253-character limit, repeated.
	long := strings.Repeat(strings.Repeat("l", 60)+".", 3) + "end"
	lines = append(lines, long, long, strings.ToUpper(long), "www", "WWW", "www.")

	domains := []string{"", "example.com", "example.com.", strings.Repeat("d", 40) + ".example.com", strings.Repeat("d", 63) + "." + strings.Repeat("e", 63) + ".com"}
	p := Prepare(lines)
	for _, domain := range domains {
		wantE, wantD, wantS := referenceBuild(lines, domain)
		gotE, gotD, gotS := p.For(domain)
		if !reflect.DeepEqual(gotE, wantE) || gotD != wantD || gotS != wantS {
			t.Errorf("domain %q: got %d entries, %d dupes, %d skipped; want %d, %d, %d",
				domain, len(gotE), gotD, gotS, len(wantE), wantD, wantS)
		}
	}
}

// TestForResultIsNotAliased checks that appending to one target's entries
// cannot change another's, since For may share its backing array.
func TestForResultIsNotAliased(t *testing.T) {
	p := Prepare([]string{"a", "b", "c"})
	first, _, _ := p.For("example.com")
	_ = append(first, "injected")
	second, _, _ := p.For("example.org")
	if !reflect.DeepEqual(second, []string{"a", "b", "c"}) {
		t.Fatalf("second target's entries = %v", second)
	}
}

func million() []string {
	lines := make([]string, 1_000_000)
	for i := range lines {
		lines[i] = fmt.Sprintf("word%d-api.dev", i)
	}
	return lines
}

// BenchmarkBuild1M measures normalizing a 1M-line wordlist (#182).
func BenchmarkBuild1M(b *testing.B) {
	lines := million()
	b.ReportAllocs()
	for b.Loop() {
		Build(lines, "example.com")
	}
}

// BenchmarkFor1M measures the per-target cost of a prepared 1M-line list.
func BenchmarkFor1M(b *testing.B) {
	p := Prepare(million())
	b.ReportAllocs()
	for b.Loop() {
		p.For("example.com")
	}
}
