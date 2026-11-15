package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/TMHSDigital/subenum/internal/scan"
)

// TestScanViewShortTerminal covers #37: a terminal shorter than the chrome must
// not produce a negative viewport height or panic.
func TestScanViewShortTerminal(t *testing.T) {
	for _, h := range []int{0, 3, 8} {
		m := newScanViewModel(0, h, false)
		m, _ = m.Update(tea.WindowSizeMsg{Width: 10, Height: h})
		if m.viewport.Height() < 1 || m.viewport.Width() < 1 || m.progress.Width() < 1 {
			t.Errorf("height %d: viewport %dx%d, progress %d", h, m.viewport.Width(), m.viewport.Height(), m.progress.Width())
		}
		_ = m.View()
	}
}

// TestScanViewNoticesDoNotOverflow covers #43: many wildcard notices are capped
// and the viewport shrinks to make room, so the status line stays on screen.
func TestScanViewNoticesDoNotOverflow(t *testing.T) {
	const width, height = 120, 30
	m := newScanViewModel(width, height, false)
	for i := 0; i < 50; i++ {
		m, _ = m.Update(eventMsg{scan.Event{Kind: scan.EventNotice, Message: "wildcard DNS at x.example.com; skipping recursive expansion"}})
	}
	m, _ = m.Update(eventMsg{scan.Event{Kind: scan.EventDone, Processed: 1, Total: 1}})
	view := m.View()
	if got := lipgloss.Height(view); got > height {
		t.Errorf("view is %d lines on a %d-line terminal", got, height)
	}
	if !strings.Contains(view, "+47 earlier notices") {
		t.Errorf("expected collapsed notice count in view:\n%s", view)
	}
	if !strings.Contains(view, "Done - processed") {
		t.Error("status line missing from view")
	}
}

// TestScanViewFillsTerminalExactly checks the chrome arithmetic both ways: with
// and without notices, the finished view uses the full height and no more.
func TestScanViewFillsTerminalExactly(t *testing.T) {
	const width, height = 100, 30
	for _, notices := range []int{0, 1, 5} {
		m := newScanViewModel(width, height, false)
		for i := 0; i < notices; i++ {
			m, _ = m.Update(eventMsg{scan.Event{Kind: scan.EventNotice, Message: "notice"}})
		}
		m, _ = m.Update(eventMsg{scan.Event{Kind: scan.EventDone, Processed: 1, Total: 1}})
		if got := lipgloss.Height(m.View()); got != height {
			t.Errorf("%d notices: view is %d lines, want exactly %d", notices, got, height)
		}
	}
}

// TestScanViewFilter covers #221: / types a name filter (q and r included),
// t shows takeover candidates only, esc clears, the hint counts what is
// shown, and ctrl+c is never swallowed by the filter.
func TestScanViewFilter(t *testing.T) {
	m := newScanViewModel(120, 24, false)
	for _, r := range []scan.Result{
		{Subdomain: "api.example.com"},
		{Subdomain: "qr-api.example.com", Takeover: "dangling"},
		{Subdomain: "www.example.com"},
	} {
		m, _ = m.Update(eventMsg{scan.Event{Kind: scan.EventResult, Result: r}})
	}
	content := func() string { return m.viewport.View() }
	key := m.handleFilterKey // bound to &m, so it sees every change

	if !key(typeText("/")) || !m.typing {
		t.Fatal("/ did not start the filter")
	}
	for _, k := range []tea.KeyPressMsg{typeText("q"), typeText("r"), keyBackspace, typeText("r-")} {
		if !key(k) {
			t.Fatalf("key %v not taken while typing", k)
		}
	}
	if m.filter != "qr-" || !strings.Contains(content(), "qr-api.example.com") || strings.Contains(content(), "www.example.com") {
		t.Fatalf("filter %q shows:\n%s", m.filter, content())
	}
	if key(keyCtrlC) {
		t.Error("ctrl+c was swallowed by the filter")
	}
	key(keyEnter)
	if m.typing || m.filter != "qr-" || !strings.Contains(m.View(), "showing 1 of 3") {
		t.Errorf("after enter: typing %v filter %q, hint:\n%s", m.typing, m.filter, m.View())
	}
	key(keyEsc)
	if m.filtered() || !strings.Contains(content(), "www.example.com") {
		t.Errorf("esc did not clear the filter:\n%s", content())
	}
	key(typeText("t"))
	if !m.takeoverOnly || strings.Contains(content(), "www.example.com") || !strings.Contains(content(), "qr-api.example.com") {
		t.Errorf("t did not narrow to takeover candidates:\n%s", content())
	}
	if key(typeText("x")) {
		t.Error("a plain key was taken while not typing")
	}
}

// TestScanViewLargeResultSetBounded covers the #43 render-cost fix: the
// buffer is capped and content is refreshed lazily past the live limit.
func TestScanViewLargeResultSetBounded(t *testing.T) {
	m := newScanViewModel(80, 24, false)
	for i := 0; i < maxResultLines+500; i++ {
		m, _ = m.Update(eventMsg{scan.Event{Kind: scan.EventResult, Result: scan.Result{Subdomain: "h.example.com"}}})
	}
	if len(m.results) > maxResultLines {
		t.Errorf("results buffer = %d, want <= %d", len(m.results), maxResultLines)
	}
	if !m.dirty {
		t.Error("large result sets should defer rendering until the next tick")
	}
	m, _ = m.Update(eventMsg{scan.Event{Kind: scan.EventProgress, Processed: 1, Total: 2}})
	if m.dirty {
		t.Error("progress tick should flush pending results")
	}
	if !strings.Contains(m.viewport.View(), "h.example.com") {
		t.Error("viewport missing results after refresh")
	}
}

func TestExpandHome(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home dir")
	}
	if got, want := expandHome("~/lists/w.txt"), filepath.Join(home, "lists", "w.txt"); got != want {
		t.Errorf("expandHome = %q, want %q", got, want)
	}
	if got := expandHome("rel/w.txt"); got != "rel/w.txt" {
		t.Errorf("relative path changed: %q", got)
	}
	if got := expandHome("~user/w.txt"); got != "~user/w.txt" {
		t.Errorf("~user form should be left alone: %q", got)
	}
}

// TestScanViewShowsVerdict covers #312: the finished screen names the
// run-quality verdict with its reason, adds the skipped and retried counts
// when there are any, and still fills an 80x24 terminal exactly.
func TestScanViewShowsVerdict(t *testing.T) {
	const width, height = 80, 24
	cases := []struct {
		name    string
		stats   scan.Stats
		aborted bool
		want    []string
		absent  []string
	}{
		{
			name:   "complete",
			stats:  scan.Stats{Found: 2, NXDomain: 8},
			want:   []string{"Verdict: complete - all 10 lookups got a definitive answer", "Done - processed"},
			absent: []string{" - skipped", " - retried", " - takeover", "back-offs"},
		},
		{
			name:   "degraded by the time budget",
			stats:  scan.Stats{Found: 2, NXDomain: 8, Skipped: 40, Expired: true, Retried: 6, Recovered: 2, Takeover: 1, RateBackoffs: 3},
			want:   []string{"Verdict: degraded - time budget (", "40 candidates not tested", "skipped 40", "retried 6 (recovered 2)", "takeover 1", "rate back-offs 3"},
			absent: []string{"{max_duration}"},
		},
		{
			name:  "unreliable",
			stats: scan.Stats{Found: 1, NXDomain: 4, Timeout: 5},
			want:  []string{"Verdict: unreliable - 5 of 10 lookups failed"},
		},
		{
			name:    "interrupted",
			stats:   scan.Stats{Found: 2, NXDomain: 8},
			aborted: true,
			want:    []string{"Verdict: degraded - interrupted after 10 lookups", "Aborted - processed"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newScanViewModel(width, height, false)
			m.aborted = tc.aborted
			m, _ = m.Update(eventMsg{scan.Event{Kind: scan.EventDone, Processed: 10, Total: 50, Found: tc.stats.Found, Stats: tc.stats}})
			view := m.View()
			for _, want := range tc.want {
				if !strings.Contains(view, want) {
					t.Errorf("view missing %q:\n%s", want, view)
				}
			}
			for _, absent := range tc.absent {
				if strings.Contains(view, absent) {
					t.Errorf("view has %q:\n%s", absent, view)
				}
			}
			if got := lipgloss.Height(view); got != height {
				t.Errorf("view is %d lines, want exactly %d", got, height)
			}
		})
	}

	// A scan that stopped before testing a candidate has nothing to grade.
	m := newScanViewModel(width, height, false)
	m, _ = m.Update(eventMsg{scan.Event{Kind: scan.EventDone, Stopped: true}})
	if view := m.View(); strings.Contains(view, "Verdict:") {
		t.Errorf("stopped scan shows a verdict:\n%s", view)
	}
}

// TestScanViewCountersFitWidth covers #343: with every counter set the
// finished counters are wider than 80 columns, so they wrap between
// counters, and the view still fills an 80x24 terminal exactly, measured in
// terminal rows rather than newlines.
func TestScanViewCountersFitWidth(t *testing.T) {
	const width, height = 80, 24
	stats := scan.Stats{Found: 12345, NXDomain: 987654, Timeout: 4321, Refused: 321, Other: 21, WildcardFiltered: 4567,
		Skipped: 40000, Retried: 600, Recovered: 200, Takeover: 7, RateBackoffs: 3}
	for _, aborted := range []bool{false, true} {
		m := newScanViewModel(width, height, false)
		m.aborted = aborted
		m, _ = m.Update(eventMsg{scan.Event{Kind: scan.EventDone, Processed: 1009876, Total: 1049876, Found: stats.Found, Stats: stats}})
		view := m.View()
		lines := strings.Split(view, "\n")
		for _, line := range lines {
			if w := lipgloss.Width(line); w > width {
				t.Errorf("aborted %v: a %d-column line on an %d-column terminal: %q", aborted, w, width, line)
			}
		}
		if len(lines) != height {
			t.Errorf("aborted %v: view is %d lines, want exactly %d:\n%s", aborted, len(lines), height, view)
		}
		flat := strings.ReplaceAll(view, "\n", " - ")
		for _, want := range []string{"wildcard-filtered 4567", "retried 600 (recovered 200)", "rate back-offs 3"} {
			if !strings.Contains(flat, want) {
				t.Errorf("aborted %v: counter %q split or missing:\n%s", aborted, want, view)
			}
		}
	}
}

// TestScanViewAbortAfterNoAbortWarning covers #343: with No Abort and
// Permute on, ctrl+c during the permutation pass after the main pass's
// reliability warning is an abort, not a failure.
func TestScanViewAbortAfterNoAbortWarning(t *testing.T) {
	m := newScanViewModel(120, 30, false)
	m.permute = true
	m, _ = m.Update(eventMsg{scan.Event{Kind: scan.EventError, Message: "warning: 30% of 200 queries failed"}})
	m, _ = m.Update(eventMsg{scan.Event{Kind: scan.EventDone, Processed: 200, Total: 200}})
	if m.done || m.main == nil {
		t.Fatal("the main pass did not hand over to the permutation pass")
	}
	m.perm = &permutationPass{seeds: 1, candidates: 90}
	m.aborted = true
	m, _ = m.Update(eventMsg{scan.Event{Kind: scan.EventDone, Stopped: true}})
	if !m.done || m.failed() {
		t.Fatalf("done %v failed %v, want an abort:\n%s", m.done, m.failed(), m.View())
	}
	if view := m.View(); strings.Contains(view, "Failed:") || !strings.Contains(view, "Aborted - processed") {
		t.Errorf("abort shown as a failure:\n%s", view)
	}
}

func TestScanViewSummaryIncludesStats(t *testing.T) {
	m := newScanViewModel(100, 24, false)
	m, _ = m.Update(eventMsg{scan.Event{
		Kind:      scan.EventDone,
		Processed: 200,
		Total:     200,
		Found:     12,
		Stats: scan.Stats{
			Found:    12,
			NXDomain: 180,
			Timeout:  5,
			Refused:  3,
			Other:    0,
		},
	}})
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
