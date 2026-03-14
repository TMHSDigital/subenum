package wordlist

import (
	"os"
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

	entries, dupes, err := LoadWordlist(tmp.Name())
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
}

func TestLoadWordlistFileNotFound(t *testing.T) {
	_, _, err := LoadWordlist("/nonexistent/path/wordlist.txt")
	if err == nil {
		t.Error("expected error for missing file")
	}
}
