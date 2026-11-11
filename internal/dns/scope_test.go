package dns

import "testing"

// TestAddressScope covers #218: every range the issue lists, in both
// families, and the public addresses that must stay unscoped.
func TestAddressScope(t *testing.T) {
	tests := []struct {
		addr string
		want string
	}{
		// IPv4 private ranges (RFC 1918).
		{"10.0.0.1", ScopePrivate},
		{"10.255.255.254", ScopePrivate},
		{"172.16.0.1", ScopePrivate},
		{"172.31.255.254", ScopePrivate},
		{"192.168.0.1", ScopePrivate},
		// IPv4 loopback.
		{"127.0.0.1", ScopeLoopback},
		{"127.255.255.254", ScopeLoopback},
		// IPv4 link-local.
		{"169.254.1.1", ScopeLinkLocal},
		// Carrier-grade NAT.
		{"100.64.0.1", ScopeCGNAT},
		{"100.127.255.254", ScopeCGNAT},
		// IPv6 unique local, loopback and link-local.
		{"fc00::1", ScopePrivate},
		{"fd00::1", ScopePrivate},
		{"::1", ScopeLoopback},
		{"fe80::1", ScopeLinkLocal},
		// An IPv4-mapped IPv6 address is judged as the IPv4 address it carries.
		{"::ffff:10.0.0.1", ScopePrivate},
		// Public addresses stay unscoped, including the neighbours of the
		// ranges above.
		{"8.8.8.8", ""},
		{"1.1.1.1", ""},
		{"93.184.216.34", ""},
		{"172.15.255.255", ""},
		{"172.32.0.1", ""},
		{"100.63.255.254", ""},
		{"100.128.0.1", ""},
		{"169.253.1.1", ""},
		{"2606:2800:220:1:248:1893:25c8:1946", ""},
		// Anything that is not an address has no scope.
		{"", ""},
		{"not-an-ip", ""},
		{"example.com", ""},
	}
	for _, tc := range tests {
		if got := AddressScope(tc.addr); got != tc.want {
			t.Errorf("AddressScope(%q) = %q, want %q", tc.addr, got, tc.want)
		}
	}
}

// TestInternalScope covers #218: the scope of the first internal address
// among a result's A and AAAA records.
func TestInternalScope(t *testing.T) {
	tests := []struct {
		name    string
		records []Record
		want    string
	}{
		{"no records", nil, ""},
		{"public addresses only", []Record{{Type: "A", Value: "93.184.216.34"}, {Type: "AAAA", Value: "2606:2800:220:1:248:1893:25c8:1946"}}, ""},
		{"private address", []Record{{Type: "A", Value: "10.0.0.1"}}, ScopePrivate},
		{"loopback address", []Record{{Type: "A", Value: "127.0.0.1"}}, ScopeLoopback},
		{"link-local address", []Record{{Type: "A", Value: "169.254.1.1"}}, ScopeLinkLocal},
		{"cgnat address", []Record{{Type: "A", Value: "100.64.0.1"}}, ScopeCGNAT},
		{"ipv6 private address", []Record{{Type: "AAAA", Value: "fd00::1"}}, ScopePrivate},
		{
			"the first internal address wins",
			[]Record{{Type: "A", Value: "93.184.216.34"}, {Type: "A", Value: "127.0.0.1"}, {Type: "A", Value: "10.0.0.1"}},
			ScopeLoopback,
		},
		{
			"a CNAME record is not an address",
			[]Record{{Type: "CNAME", Value: "10.0.0.1"}, {Type: "A", Value: "93.184.216.34"}},
			"",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := InternalScope(tc.records); got != tc.want {
				t.Errorf("InternalScope(%v) = %q, want %q", tc.records, got, tc.want)
			}
		})
	}
}
