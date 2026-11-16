package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestE2EExpiredMainPassDefersPermutation(t *testing.T) {
	t.Parallel()
	words := writeFile(t, "words.txt", "www\nmail\n")
	seeds := writeFile(t, "seeds.txt", "api.example.com\n")
	state := filepath.Join(t.TempDir(), "state.json")
	// An already-spent budget is deterministic even on a slow runner. An
	// explicit seed ensures the old gate still tries to build a second pass.
	code, stdout, stderr := runCLIStreams(t, "-simulate", "-seed", "7", "-hit-rate", "100",
		"-permute", "-w", words, "-seeds", seeds, "-format", "jsonl", "-progress=false",
		"-max-duration", "1ns", "-state", state, "example.com")
	if code != exitOK {
		t.Fatalf("budget stop: exit %d\n%s", code, stderr)
	}
	_, summary := jsonlRecords(t, stdout)
	if len(summary.Targets) != 1 || summary.Targets[0].StoppedBy != "duration" {
		t.Fatalf("expected a duration stop, got %+v", summary)
	}
	if summary.Targets[0].Permutation != nil || strings.Contains(stderr, "Permutation pass for") {
		t.Errorf("expired main pass started permutation: %+v\n%s", summary.Targets[0].Permutation, stderr)
	}
	data, err := os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	var saved resumeState
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatal(err)
	}
	if len(saved.Targets) != 1 || saved.Targets[0].Done || saved.Targets[0].Permute != nil {
		t.Errorf("state should leave the permutation pass unstarted: %+v", saved.Targets)
	}

	// The deferred pass must still run after resuming the main pass.
	code, stdout, stderr = runCLIStreams(t, "-resume", state, "-max-duration", "0")
	if code != exitOK {
		t.Fatalf("resume: exit %d\n%s", code, stderr)
	}
	_, summary = jsonlRecords(t, stdout)
	if len(summary.Targets) != 1 || summary.Targets[0].Permutation == nil || summary.Targets[0].Permutation.Found == 0 || summary.Verdict != "complete" {
		t.Errorf("resumed scan did not finish the deferred pass: %+v", summary)
	}
}
