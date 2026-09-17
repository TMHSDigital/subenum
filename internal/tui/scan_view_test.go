package tui

import (
	"strings"
	"testing"

	"github.com/TMHSDigital/subenum/internal/scan"
)

func TestScanViewSummaryIncludesStats(t *testing.T) {
	m := newScanViewModel(100, 24, false)
	m, _ = m.Update(doneMsg{
		processed: 200,
		total:     200,
		found:     12,
		stats: scan.Stats{
			Found:    12,
			NXDomain: 180,
			Timeout:  5,
			Refused:  3,
			Other:    0,
		},
	})
	view := m.View()
	for _, want := range []string{
		"found 12",
		"nxdomain 180",
		"timeout 5",
		"refused 3",
		"other 0",
		"wildcard-filtered",
	} {
		if !strings.Contains(view, want) {
			t.Errorf("view missing %q:\n%s", want, view)
		}
	}
}
