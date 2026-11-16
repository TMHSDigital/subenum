package scan

import (
	"reflect"
	"testing"
)

// TestAddCountsCoversEveryField is the drift guard of #367, as
// TestMergeStatsCoversEveryField is for the CLI's resume merge: a field added
// to Stats must be summed by AddCounts or named here as one it leaves to the
// caller, and AddCounts must keep every field of its receiver.
func TestAddCountsCoversEveryField(t *testing.T) {
	notSummed := map[string]bool{"RootDone": true, "Aborted": true, "Expired": true, "Wildcard": true,
		"Fingerprint": true, "FinalRate": true, "Repeat": true, "Pending": true}
	st := reflect.TypeFor[Stats]()
	for i := range st.NumField() {
		name := st.Field(i).Name
		var one Stats
		v := reflect.ValueOf(&one).Elem().Field(i)
		switch v.Kind() {
		case reflect.Int64:
			v.SetInt(1)
		case reflect.Bool:
			v.SetBool(true)
		case reflect.Slice:
			v.Set(reflect.Append(reflect.MakeSlice(v.Type(), 0, 1), reflect.New(v.Type().Elem()).Elem()))
		case reflect.Struct:
			v.Field(0).SetInt(1)
		default:
			t.Fatalf("Stats.%s: unhandled kind %s", name, v.Kind())
		}
		if got := one.AddCounts(Stats{}); !reflect.DeepEqual(got, one) {
			t.Errorf("AddCounts changes the receiver's Stats.%s: %+v", name, got)
		}
		summed := !reflect.DeepEqual(Stats{}.AddCounts(one), Stats{})
		if summed == notSummed[name] {
			t.Errorf("AddCounts sums Stats.%s: %v, want %v", name, summed, !notSummed[name])
		}
	}
}
