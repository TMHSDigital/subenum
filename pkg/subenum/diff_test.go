package subenum_test

import (
	"slices"
	"testing"

	"github.com/TMHSDigital/subenum/pkg/subenum"
)

func TestDiff(t *testing.T) {
	a := func(v string) subenum.Record { return subenum.Record{Type: "A", Value: v} }
	cname := func(v string) subenum.Record { return subenum.Record{Type: "CNAME", Value: v} }
	previous := []subenum.Result{
		{Name: "www.example.com", Records: []subenum.Record{a("192.0.2.1")}},
		{Name: "old.example.com", Records: []subenum.Record{a("192.0.2.2")}},
		{Name: "cdn.example.com", Records: []subenum.Record{cname("app.cdn.example"), a("192.0.2.3")}},
		{Name: "blog.example.com", Records: []subenum.Record{cname("blog.host.example")}},
		{Name: "listed.example.com"}, // from a plain name list: no records
	}
	current := []subenum.Result{
		{Name: "WWW.example.com.", Records: []subenum.Record{a("192.0.2.1")}},
		{Name: "new.example.com", Records: []subenum.Record{a("192.0.2.4")}},
		{Name: "cdn.example.com", Records: []subenum.Record{cname("app.cdn.example"), a("192.0.2.99")}},
		{Name: "blog.example.com", Records: []subenum.Record{cname("unclaimed.example")}},
		{Name: "listed.example.com", Records: []subenum.Record{a("192.0.2.5")}},
	}
	got := subenum.Diff(previous, current, []string{"A", "AAAA", "CNAME"})
	if !slices.Equal(got.Added, []string{"new.example.com"}) {
		t.Errorf("Added = %q", got.Added)
	}
	if !slices.Equal(got.Removed, []string{"old.example.com"}) {
		t.Errorf("Removed = %q", got.Removed)
	}
	if len(got.Changed) != 1 || got.Changed[0].Name != "blog.example.com" ||
		got.Changed[0].Previous[0].Value != "blog.host.example" || got.Changed[0].Current[0].Value != "unclaimed.example" {
		t.Errorf("Changed = %+v, want only blog.example.com re-pointed", got.Changed)
	}
}

func TestDiffTypes(t *testing.T) {
	prev := []subenum.Result{{Name: "mail.example.com", Records: []subenum.Record{{Type: "A", Value: "192.0.2.1"}, {Type: "MX", Value: "10 mx.example.com"}}}}
	cur := []subenum.Result{{Name: "mail.example.com", Records: []subenum.Record{{Type: "A", Value: "192.0.2.1"}}}}
	if got := subenum.Diff(prev, cur, []string{"A"}); len(got.Changed) != 0 {
		t.Errorf("types A: Changed = %+v, want none (MX was not looked up this time)", got.Changed)
	}
	if got := subenum.Diff(prev, cur, nil); len(got.Changed) != 1 {
		t.Errorf("nil types: Changed = %+v, want mail.example.com", got.Changed)
	}
}

func TestDiffEmpty(t *testing.T) {
	got := subenum.Diff(nil, nil, nil)
	if got.Added != nil || got.Removed != nil || got.Changed != nil {
		t.Errorf("Diff(nil, nil) = %+v, want zero Changes", got)
	}
}
