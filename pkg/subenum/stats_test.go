package subenum

import (
	"reflect"
	"testing"

	"github.com/TMHSDigital/subenum/internal/dns"
	"github.com/TMHSDigital/subenum/internal/scan"
)

// engineOnlyStats are scan.Stats fields the library deliberately keeps to
// itself.
var engineOnlyStats = map[string]bool{
	"RootDone": true, // the CLI's -resume point
}

// bump changes v away from its current value, whatever its kind.
func bump(t *testing.T, v reflect.Value) {
	t.Helper()
	switch v.Kind() {
	case reflect.Int64:
		v.SetInt(v.Int() + 1)
	case reflect.Bool:
		v.SetBool(!v.Bool())
	case reflect.Slice:
		v.Set(reflect.Append(v, reflect.ValueOf(dns.Record{Type: "A", Value: "192.0.2.1"})))
	default:
		t.Fatalf("no way to bump a %s field; extend bump", v.Type())
	}
}

// TestStatsCoversEveryEngineField is the drift guard of #162: a field added
// to scan.Stats or Stats without updating stats fails here.
func TestStatsCoversEveryEngineField(t *testing.T) {
	zero := stats(scan.Stats{})
	var all scan.Stats
	st := reflect.TypeOf(all)
	for i := range st.NumField() {
		name := st.Field(i).Name
		bump(t, reflect.ValueOf(&all).Elem().Field(i))
		if engineOnlyStats[name] {
			continue
		}
		var one scan.Stats
		bump(t, reflect.ValueOf(&one).Elem().Field(i))
		if reflect.DeepEqual(stats(one), zero) {
			t.Errorf("scan.Stats.%s does not reach subenum.Stats; map it in stats() or list it in engineOnlyStats", name)
		}
	}
	got := reflect.ValueOf(stats(all))
	for i := range got.NumField() {
		if got.Field(i).IsZero() {
			t.Errorf("subenum.Stats.%s is never set from scan.Stats", got.Type().Field(i).Name)
		}
	}
}
