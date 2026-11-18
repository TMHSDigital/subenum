package dns

import "testing"

func TestEscapeTXT(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"v=spf1 include:_spf.example.com -all", "v=spf1 include:_spf.example.com -all"},
		{"café ✓", "café ✓"},
		{"\x1b]0;owned\x07", `\027]0;owned\007`},
		{"a\nfake.example.com A=1.2.3.4", `a\010fake.example.com A=1.2.3.4`},
		{"cr\rtab\t", `cr\013tab\009`},
		{`back\slash`, `back\092slash`},
		{"bad\xffbyte", `bad\255byte`},
		{"rtl" + string(rune(0x202e)) + "override", `rtl\226\128\174override`},
	} {
		if got := EscapeTXT(tc.in); got != tc.want {
			t.Errorf("EscapeTXT(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
