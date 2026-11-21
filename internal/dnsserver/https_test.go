package dnsserver

import (
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// httpsQuery builds a type 65 query for name.
func httpsQuery(t *testing.T, name string) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 7, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name + "."), Type: dnsmessage.TypeHTTPS, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

// TestAnswerHTTPS covers #438: the server answers HTTPS queries with
// AliasMode and ServiceMode records, with their alpn and port parameters,
// and a name without them gets NODATA; malformed values are skipped.
func TestAnswerHTTPS(t *testing.T) {
	srv, err := Listen(Options{}, func(q Query) Reply {
		switch q.Name {
		case "alias.example.test":
			return Reply{HTTPS: []string{"0 edge.example.net"}}
		case "svc.example.test":
			return Reply{HTTPS: []string{"1 . alpn=h2,h3 port=443", "x . alpn=h2", "1 . bogus=1"}}
		}
		return Reply{A: []string{"192.0.2.1"}}
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)

	answers := func(name string) (dnsmessage.RCode, []dnsmessage.SVCBResource) {
		var msg dnsmessage.Message
		if err := msg.Unpack(udpExchange(t, srv.Addr, httpsQuery(t, name))); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var out []dnsmessage.SVCBResource
		for _, rr := range msg.Answers {
			if h, ok := rr.Body.(*dnsmessage.HTTPSResource); ok {
				out = append(out, h.SVCBResource)
			}
		}
		return msg.RCode, out
	}

	if rc, recs := answers("alias.example.test"); rc != dnsmessage.RCodeSuccess || len(recs) != 1 || recs[0].Priority != 0 || recs[0].Target.String() != "edge.example.net." {
		t.Errorf("alias: %v %+v", rc, recs)
	}
	rc, recs := answers("svc.example.test")
	if rc != dnsmessage.RCodeSuccess || len(recs) != 1 || recs[0].Priority != 1 || recs[0].Target.String() != "." {
		t.Fatalf("svc: %v %+v", rc, recs)
	}
	if v, ok := recs[0].GetParam(dnsmessage.SVCParamALPN); !ok || string(v) != "\x02h2\x02h3" {
		t.Errorf("svc alpn = %q", v)
	}
	if v, ok := recs[0].GetParam(dnsmessage.SVCParamPort); !ok || string(v) != "\x01\xbb" {
		t.Errorf("svc port = %q", v)
	}
	if rc, recs := answers("plain.example.test"); rc != dnsmessage.RCodeSuccess || len(recs) != 0 {
		t.Errorf("plain: %v %+v, want NODATA", rc, recs)
	}
}

// TestParseHTTPS covers #438: what ParseHTTPS refuses.
func TestParseHTTPS(t *testing.T) {
	for _, v := range []string{"", "1", "x .", "70000 .", "1 . alpn=", "1 . alpn=h2,,h3", "1 . port=x", "1 . port=70000", "1 . ech=abc", "1 bad..name"} {
		if _, err := ParseHTTPS(v); err == nil {
			t.Errorf("ParseHTTPS(%q) accepted", v)
		}
	}
	if _, err := ParseHTTPS("0 edge.example.net."); err != nil {
		t.Errorf("AliasMode: %v", err)
	}
}
