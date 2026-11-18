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

// TestForStripsTargetSuffix covers #351: full names pasted into a wordlist
// are used as prefixes under their own target, a prefix the list also holds
// on its own is a duplicate wherever it appears, and other targets and
// entries that only contain the target's text are left alone.
func TestForStripsTargetSuffix(t *testing.T) {
	lines := []string{"api.lab.example", "www", "WWW.Lab.Example.", "dev.api.lab.example", "api.lab.example", "lab.example.org", "xlab.example"}
	p := Prepare(lines)
	for _, domain := range []string{"lab.example", "LAB.example."} {
		entries, dupes, skipped := p.For(domain)
		want := []string{"api", "www", "dev.api", "lab.example.org", "xlab.example"}
		if !reflect.DeepEqual(entries, want) || dupes != 2 || skipped != 0 {
			t.Errorf("For(%q) = %v, %d dupes, %d skipped; want %v, 2, 0", domain, entries, dupes, skipped, want)
		}
		if n := p.Suffixed(domain); n != 3 {
			t.Errorf("Suffixed(%q) = %d, want 3", domain, n)
		}
	}
	for _, domain := range []string{"other.example", ""} {
		if entries, _, _ := p.For(domain); len(entries) != 6 || p.Suffixed(domain) != 0 {
			t.Errorf("For(%q) changed entries: %v", domain, entries)
		}
	}
}

// TestLimitTo covers -hosts (#351): each target gets the prefixes of the
// names under it, a name under a nested target goes to that target only, and
// names under no target are counted, never used.
func TestLimitTo(t *testing.T) {
	lines := []string{"www.a.example", "x.a.example", "api.x.a.example", "WWW.A.Example.", "other.example", "a.example", "www", "b.a.example.org"}
	p := Prepare(lines)
	p.LimitTo([]string{"A.example.", "x.a.example"})
	for domain, want := range map[string][]string{
		"a.example":   {"www", "x"},
		"x.a.example": {"api"},
	} {
		entries, dupes, _ := p.For(domain)
		if !reflect.DeepEqual(entries, want) {
			t.Errorf("For(%q) = %v, want %v", domain, entries, want)
		}
		if domain == "a.example" && dupes != 1 {
			t.Errorf("For(%q) duplicates = %d, want 1", domain, dupes)
		}
	}
	// other.example, a.example itself, www and b.a.example.org.
	if n := p.Outside(); n != 4 {
		t.Errorf("Outside() = %d, want 4", n)
	}
}

// TestPrepareIndexAcrossGrowth covers #248: the entry index keeps finding
// earlier entries while its table doubles many times, so repeats seen long
// after their first occurrence (in another case) still count as duplicates,
// and first-occurrence order is kept.
func TestPrepareIndexAcrossGrowth(t *testing.T) {
	rng := rand.New(rand.NewPCG(3, 4))
	const unique = 200_000 // the table starts at 1<<10 slots and doubles about 9 times
	var lines []string
	for i := range unique {
		lines = append(lines, fmt.Sprintf("w%d", i))
		// Repeat a random earlier entry, upper-cased, about one time in three.
		if rng.IntN(3) == 0 {
			lines = append(lines, strings.ToUpper(fmt.Sprintf("w%d", rng.IntN(i+1))))
		}
	}
	wantE, wantD, wantS := referenceBuild(lines, "example.com")
	gotE, gotD, gotS := Prepare(lines).For("example.com")
	if !reflect.DeepEqual(gotE, wantE) || gotD != wantD || gotS != wantS {
		t.Fatalf("got %d entries, %d dupes, %d skipped; want %d, %d, %d", len(gotE), gotD, gotS, len(wantE), wantD, wantS)
	}
	if len(gotE) != unique || gotD == 0 {
		t.Fatalf("got %d entries and %d duplicates; want %d entries and some duplicates", len(gotE), gotD, unique)
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
