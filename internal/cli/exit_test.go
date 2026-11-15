package cli

import "testing"

// TestExitCodePrecedence covers #158's exit-code ladder: signal, then file
// error, then partial -dL failure, then failure, then -diff changes.
func TestExitCodePrecedence(t *testing.T) {
	for _, c := range []struct {
		name string
		e    runEnding
		want int
	}{
		{"clean run", runEnding{targets: 1}, exitOK},
		{"changes", runEnding{targets: 1, changes: 3}, exitChanges},
		{"failure beats changes", runEnding{targets: 1, anyFailed: true, changes: 3}, exitFailure},
		{"partial -dL failure", runEnding{targets: 3, failedTargets: 1, anyFailed: true, changes: 1}, exitPartial},
		{"every target failed", runEnding{targets: 3, failedTargets: 3, anyFailed: true}, exitFailure},
		{"one target is never partial", runEnding{targets: 1, failedTargets: 1, anyFailed: true}, exitFailure},
		{"file error beats partial", runEnding{targets: 3, failedTargets: 1, fileErr: true}, exitFailure},
		{"SIGINT beats everything", runEnding{signal: 130, targets: 3, failedTargets: 1, fileErr: true, anyFailed: true, changes: 2}, 130},
		{"SIGTERM", runEnding{signal: 143, targets: 1}, 143},
	} {
		if got := c.e.exitCode(); got != c.want {
			t.Errorf("%s: exit %d, want %d", c.name, got, c.want)
		}
	}
}
