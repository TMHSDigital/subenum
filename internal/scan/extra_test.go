package scan

import (
	"maps"
	"testing"
)

// TestExtraIsIndexedAfterEntries covers #365 item 2: Extra is tried after
// Entries as if appended to them, so a scan given the two apart finds what
// the joined list finds, counts the same, resumes at the same positions, and
// a recursive scan tries Extra under each found name too.
func TestExtraIsIndexedAfterEntries(t *testing.T) {
	all := append(makeEntries(300), "dev.p1", "p1.p2")
	for _, recursive := range []bool{false, true} {
		t.Run(map[bool]string{false: "flat", true: "recursive"}[recursive], func(t *testing.T) {
			joined := Config{
				Domain: "example.com", Entries: all, Concurrency: 8,
				Simulate: true, HitRate: 10, Seed: 7, Attempts: 1,
				Recursive: recursive, Depth: 2,
			}
			split := joined
			split.Entries, split.Extra = all[:250:250], all[250:]

			want, wantStats := runCollect(t, joined, 0)
			got, gotStats := runCollect(t, split, 0)
			if !maps.Equal(got, want) {
				t.Errorf("split lists found %d names, joined %d", len(got), len(want))
			}
			if gotStats.RootDone != wantStats.RootDone || gotStats.Skipped != wantStats.Skipped || gotStats.NXDomain != wantStats.NXDomain {
				t.Errorf("stats differ: split %+v, joined %+v", gotStats, wantStats)
			}

			// A resume position past Entries lands in Extra.
			joined.ResumeFrom, split.ResumeFrom = 260, 260
			want, _ = runCollect(t, joined, 0)
			got, _ = runCollect(t, split, 0)
			if !maps.Equal(got, want) {
				t.Errorf("resumed in Extra: split found %d names, joined %d", len(got), len(want))
			}

			// A cap counts the untested candidates alike, multi-label
			// entries in Extra included (countUnbuiltRepeats).
			joined.ResumeFrom, split.ResumeFrom = 0, 0
			joined.MaxQueries, split.MaxQueries = 200, 200
			_, wantStats = runCollect(t, joined, 0)
			_, gotStats = runCollect(t, split, 0)
			if gotStats.Skipped != wantStats.Skipped || gotStats.Excluded != wantStats.Excluded {
				t.Errorf("capped: split skipped %d excluded %d, joined %d %d",
					gotStats.Skipped, gotStats.Excluded, wantStats.Skipped, wantStats.Excluded)
			}
		})
	}
}
