package labzone

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// FuzzParse: any scenario text parses or fails without panicking, and a
// zone that parses answers any name (#259).
func FuzzParse(f *testing.F) {
	labs, _ := filepath.Glob(filepath.Join("..", "..", "examples", "labs", "*.zone"))
	for _, p := range labs {
		if b, err := os.ReadFile(p); err == nil {
			f.Add(string(b))
		}
	}
	f.Add("$DELAY 20ms\n$REFUSE-ABOVE 50\n@ A 192.0.2.1\nmail MX 10 mx1\n@ TXT \"v=spf1 -all\"\nslow TIMEOUT\n*.dev A 192.0.2.9\n")
	f.Add("www CNAME www\nx NS ns1.gone.example.\n$DELAY -1s\nbad AAAA 192.0.2.1\n")
	f.Fuzz(func(_ *testing.T, text string) {
		z, err := Parse(strings.NewReader(text))
		if err != nil {
			return
		}
		for _, name := range []string{"", "www", "a.dev", "slow", "mail", "nope.x"} {
			_ = z.Answer(name, "lab.example")
		}
	})
}
