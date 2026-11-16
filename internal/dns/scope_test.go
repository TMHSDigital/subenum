package dns

import "testing"

func TestAddressScope(t *testing.T) {
	for _, tc := range []struct{ addr, want string }{
		{"127.0.0.1", ScopeLoopback},
		{"127.10.0.5", ScopeLoopback},
		{"::1", ScopeLoopback},
		{"0.0.0.0", ScopeUnspecified},
		{"::", ScopeUnspecified},
		{"169.254.169.254", ScopeLinkLocal},
		{"fe80::1", ScopeLinkLocal},
		{"10.0.0.1", ScopePrivate},
		{"172.16.0.1", ScopePrivate},
		{"172.31.255.255", ScopePrivate},
		{"192.168.1.1", ScopePrivate},
		{"fd00::1", ScopePrivate},
		{"::ffff:192.168.1.1", ScopePrivate},
		{"100.64.0.1", ScopeCGNAT},
		{"100.127.255.255", ScopeCGNAT},
		{"100.128.0.1", ""},
		{"172.32.0.1", ""},
		{"8.8.8.8", ""},
		{"192.0.2.1", ""},
		{"2001:db8::1", ""},
		{"target.example.com", ""},
		{"", ""},
	} {
		if got := AddressScope(tc.addr); got != tc.want {
			t.Errorf("AddressScope(%q) = %q, want %q", tc.addr, got, tc.want)
		}
	}
}

func TestInternalScope(t *testing.T) {
	for _, tc := range []struct {
		name    string
		records []Record
		want    string
	}{
		{"none", nil, ""},
		{"public", []Record{{Type: "A", Value: "192.0.2.1"}, {Type: "AAAA", Value: "2001:db8::1"}}, ""},
		{"private v4", []Record{{Type: "A", Value: "192.0.2.1"}, {Type: "A", Value: "10.1.2.3"}}, ScopePrivate},
		{"private v6", []Record{{Type: "AAAA", Value: "fd12::1"}}, ScopePrivate},
		{"loopback wins", []Record{{Type: "A", Value: "10.1.2.3"}, {Type: "A", Value: "127.0.0.1"}}, ScopeLoopback},
		{"link-local over private", []Record{{Type: "A", Value: "10.1.2.3"}, {Type: "AAAA", Value: "fe80::1"}}, ScopeLinkLocal},
		{"cname value ignored", []Record{{Type: "CNAME", Value: "10.0.0.1"}}, ""},
	} {
		if got := InternalScope(tc.records); got != tc.want {
			t.Errorf("%s: InternalScope = %q, want %q", tc.name, got, tc.want)
		}
	}
}
