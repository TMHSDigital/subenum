package output

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
)

// TestSchemasMatchStructs covers #433: the JSON Schema files the site
// publishes list exactly the JSON fields of Result and Summary, nested
// objects included, so a field added, renamed or removed in the code fails
// here until docs/schemas (and docs/output.md) follow.
func TestSchemasMatchStructs(t *testing.T) {
	for file, typ := range map[string]reflect.Type{
		"result.v1.json": reflect.TypeFor[Result](),
		"stats.v1.json":  reflect.TypeFor[Summary](),
	} {
		data, err := os.ReadFile(filepath.Join("..", "..", "docs", "schemas", file))
		if err != nil {
			t.Fatal(err)
		}
		var schema map[string]any
		if err := json.Unmarshal(data, &schema); err != nil {
			t.Fatalf("%s is not valid JSON: %v", file, err)
		}
		compareSchema(t, file, "", schema, schema, typ)
	}
}

// compareSchema checks that node (an object schema) has exactly typ's JSON
// fields as properties, then recurses into the fields that are objects or
// arrays of objects.
func compareSchema(t *testing.T, file, path string, root, node map[string]any, typ reflect.Type) {
	t.Helper()
	node = resolveRef(t, root, node)
	props, _ := node["properties"].(map[string]any)
	fields := jsonFields(typ)
	var want, got []string
	for name := range fields {
		want = append(want, name)
	}
	for name := range props {
		got = append(got, name)
	}
	sort.Strings(want)
	sort.Strings(got)
	if !slices.Equal(want, got) {
		t.Errorf("%s %s: schema properties %v, struct fields %v", file, orRoot(path), got, want)
	}
	for name, ft := range fields {
		prop, ok := props[name].(map[string]any)
		if !ok {
			continue
		}
		prop = resolveRef(t, root, prop)
		for ft.Kind() == reflect.Pointer || ft.Kind() == reflect.Slice {
			ft = ft.Elem()
			if items, ok := prop["items"].(map[string]any); ok {
				prop = resolveRef(t, root, items)
			}
		}
		if isObject(ft) {
			compareSchema(t, file, path+"."+name, root, prop, ft)
		}
	}
}

// jsonFields maps typ's JSON field names to their types, flattening
// embedded structs as encoding/json does.
func jsonFields(typ reflect.Type) map[string]reflect.Type {
	out := map[string]reflect.Type{}
	for f := range typ.Fields() {
		tag := f.Tag.Get("json")
		if f.Anonymous && tag == "" {
			for name, ft := range jsonFields(f.Type) {
				out[name] = ft
			}
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		if name == "-" || !f.IsExported() {
			continue
		}
		if name == "" {
			name = f.Name
		}
		out[name] = f.Type
	}
	return out
}

// isObject reports whether t encodes as a JSON object of its own fields:
// a struct that does not marshal itself (time.Time does).
func isObject(t reflect.Type) bool {
	if t.Kind() != reflect.Struct {
		return false
	}
	return !t.Implements(reflect.TypeFor[json.Marshaler]()) && !reflect.PointerTo(t).Implements(reflect.TypeFor[json.Marshaler]())
}

func resolveRef(t *testing.T, root, node map[string]any) map[string]any {
	t.Helper()
	ref, ok := node["$ref"].(string)
	if !ok {
		return node
	}
	name, ok := strings.CutPrefix(ref, "#/$defs/")
	defs, _ := root["$defs"].(map[string]any)
	def, found := defs[name].(map[string]any)
	if !ok || !found {
		t.Fatalf("unresolvable $ref %q", ref)
	}
	return def
}

func orRoot(path string) string {
	if path == "" {
		return "(top level)"
	}
	return path
}
