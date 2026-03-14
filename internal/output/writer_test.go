package output

import (
	"bufio"
	"os"
	"strings"
	"testing"
)

func TestWriterResult(t *testing.T) {
	tmp, err := os.CreateTemp("", "output-test-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())

	bw := bufio.NewWriter(tmp)
	w := New(bw, false)

	domains := []string{"www.example.com", "api.example.com", "mail.example.com"}
	for _, d := range domains {
		w.Result(d)
	}
	bw.Flush()
	tmp.Close()

	content, err := os.ReadFile(tmp.Name())
	if err != nil {
		t.Fatal(err)
	}

	for _, d := range domains {
		if !strings.Contains(string(content), d) {
			t.Errorf("expected output file to contain %q\nGot:\n%s", d, content)
		}
	}
}
