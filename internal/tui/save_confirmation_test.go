package tui

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"

	"github.com/TMHSDigital/subenum/internal/output"
)

func TestTUISaveConfirmsExistingFiles(t *testing.T) {
	for _, target := range []string{"scan output", "another file"} {
		t.Run(target, func(t *testing.T) {
			redirectConfig(t)
			path := filepath.Join(t.TempDir(), "out.json")
			m := runTUIModel(t, path, output.FormatJSON, []string{"A"})
			press := func(keys ...tea.KeyPressMsg) {
				t.Helper()
				for _, key := range keys {
					next, _ := m.updateScan(key)
					m = next.(Model)
				}
			}
			press(typeText("/"), typeText("www"), keyEnter, typeText("s"))
			if target == "another file" {
				path = filepath.Join(t.TempDir(), "existing.json")
				if err := os.WriteFile(path, []byte("KEEP EXISTING FILE"), 0o600); err != nil {
					t.Fatal(err)
				}
				for range []rune(m.scanView.savePath) {
					press(keyBackspace)
				}
				press(typeText(path))
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			unchanged := func() {
				t.Helper()
				got, err := os.ReadFile(path)
				if err != nil || string(got) != string(before) {
					t.Fatalf("save changed the existing file before confirmation: %q, err %v", got, err)
				}
			}
			press(keyEnter)
			unchanged()
			if !m.scanView.saving || !strings.Contains(m.scanView.doneHint(), "overwrite") {
				t.Fatalf("missing overwrite confirmation: %s", m.scanView.doneHint())
			}

			// Editing and restoring the same path cancels the previous
			// confirmation; escape and reopening the prompt do so as well.
			press(keyBackspace, typeText("n"), keyEnter)
			unchanged()
			press(keyEsc, typeText("s"), keyEnter)
			unchanged()
			press(keyEnter)
			if m.scanView.saving {
				t.Fatal("confirmed save left the prompt open")
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var results []output.Result
			if err := json.Unmarshal(data, &results); err != nil {
				t.Fatal(err)
			}
			if len(results) != 1 || results[0].Subdomain != "www.example.com" {
				t.Fatalf("confirmed save should contain the filtered result: %s", data)
			}
		})
	}
}
