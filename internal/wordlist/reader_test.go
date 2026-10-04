package wordlist

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestSanitizeLine(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"api", "api"},
		{"  api  ", "api"},
		{"\tmail\t", "mail"},
		{"", ""},
		{"   ", ""},
		{"\t\r\n", ""},
		{"www", "www"},
	}

	for _, tt := range tests {
		got := SanitizeLine(tt.in)
		if got != tt.want {
			t.Errorf("SanitizeLine(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestLoadWordlist(t *testing.T) {
	content := "api\nwww\n  mail  \napi\n\n  \nwww\nftp\n"
	tmp, err := os.CreateTemp("", "wordlist-test-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.WriteString(content); err != nil {
		t.Fatal(err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatal(err)
	}

	entries, dupes, skipped, err := LoadWordlist(tmp.Name(), "example.com")
	if err != nil {
		t.Fatalf("LoadWordlist returned error: %v", err)
	}

	want := []string{"api", "www", "mail", "ftp"}
	if len(entries) != len(want) {
		t.Fatalf("got %d entries, want %d", len(entries), len(want))
	}
	for i, w := range want {
		if entries[i] != w {
			t.Errorf("entry[%d] = %q, want %q", i, entries[i], w)
		}
	}
	if dupes != 2 {
		t.Errorf("got %d duplicates, want 2", dupes)
	}
	if skipped != 0 {
		t.Errorf("got %d skipped, want 0", skipped)
	}
}

func TestLoadWordlistFileNotFound(t *testing.T) {
	_, _, _, err := LoadWordlist("/nonexistent/path/wordlist.txt", "example.com")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "wl.txt")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestLoadWordlistNormalizes covers #33: comments are ignored, case variants
// deduplicate, and entries that cannot form a valid name are skipped instead of
// being sent as queries.
func TestLoadWordlistNormalizes(t *testing.T) {
	p := writeTemp(t, "# comment\nWWW\nfoo bar\n*.x\nwww\n  # indented comment\n_dmarc\ndev.API\nbad-\na..b\n")
	entries, dupes, skipped, err := LoadWordlist(p, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"www", "_dmarc", "dev.api"}
	if !reflect.DeepEqual(entries, want) {
		t.Errorf("entries = %q, want %q", entries, want)
	}
	if dupes != 1 {
		t.Errorf("duplicates = %d, want 1 (www vs WWW)", dupes)
	}
	if skipped != 4 {
		t.Errorf("skipped = %d, want 4 (foo bar, *.x, bad-, a..b)", skipped)
	}
}

func TestLoadWordlistSkipsOverlongNames(t *testing.T) {
	label := strings.Repeat("a", 63)
	long := strings.Join([]string{label, label, label, label}, ".") // 255 chars on its own
	p := writeTemp(t, "ok\n"+strings.Repeat("b", 64)+"\n"+long+"\n")
	entries, _, skipped, err := LoadWordlist(p, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(entries, []string{"ok"}) || skipped != 2 {
		t.Errorf("entries = %q, skipped = %d; want [ok], 2", entries, skipped)
	}
}

func TestNormalize(t *testing.T) {
	tests := []struct {
		in   string
		want string
		ok   bool
	}{
		{"API", "api", true},
		{" mail. ", "mail", true},
		{"_domainkey", "_domainkey", true},
		{"-lead", "", false},
		{"*", "", false},
		{"#x", "", false},
		{"", "", false},
	}
	for _, tt := range tests {
		got, ok := Normalize(tt.in)
		if got != tt.want || ok != tt.ok {
			t.Errorf("Normalize(%q) = %q, %v; want %q, %v", tt.in, got, ok, tt.want, tt.ok)
		}
	}
}
