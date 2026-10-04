package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/TMHSDigital/subenum/internal/scan"
)

// TestScanViewShortTerminal covers #37: a terminal shorter than the chrome must
// not produce a negative viewport height or panic.
func TestScanViewShortTerminal(t *testing.T) {
	for _, h := range []int{0, 3, 8} {
		m := newScanViewModel(0, h, false)
		m, _ = m.Update(tea.WindowSizeMsg{Width: 10, Height: h})
		if m.viewport.Height < 1 || m.viewport.Width < 1 || m.progress.Width < 1 {
			t.Errorf("height %d: viewport %dx%d, progress %d", h, m.viewport.Width, m.viewport.Height, m.progress.Width)
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
		m, _ = m.Update(wildcardMsg{text: "wildcard DNS at x.example.com; skipping recursive expansion"})
	}
	m, _ = m.Update(doneMsg{processed: 1, total: 1})
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

// TestScanViewLargeResultSetBounded covers the #43 render-cost fix: the
// buffer is capped and content is refreshed lazily past the live limit.
func TestScanViewLargeResultSetBounded(t *testing.T) {
	m := newScanViewModel(80, 24, false)
	for i := 0; i < maxResultLines+500; i++ {
		m, _ = m.Update(resultMsg{domain: "h.example.com"})
	}
	if len(m.results) > maxResultLines {
		t.Errorf("results buffer = %d, want <= %d", len(m.results), maxResultLines)
	}
	if !m.dirty {
		t.Error("large result sets should defer rendering until the next tick")
	}
	m, _ = m.Update(progressMsg{processed: 1, total: 2})
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
