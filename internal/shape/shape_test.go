package shape

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestClampPage(t *testing.T) {
	cases := []struct{ page, size, wantNum, wantSize int }{
		{1, 25, 0, 25},
		{0, 0, 0, 25},    // defaults
		{3, 500, 2, 100}, // clamp size to max, page->0-based
		{-5, 10, 0, 10},
	}
	for i, c := range cases {
		gotNum, gotSize := ClampPage(c.page, c.size, 25, 100)
		if gotNum != c.wantNum || gotSize != c.wantSize {
			t.Errorf("case %d: got (%d,%d) want (%d,%d)", i, gotNum, gotSize, c.wantNum, c.wantSize)
		}
	}
}

func TestProjectFull(t *testing.T) {
	items := []json.RawMessage{json.RawMessage(`{"a":1,"b":2}`)}
	got, err := Project(items, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got[0], map[string]any{"a": float64(1), "b": float64(2)}) {
		t.Errorf("full projection = %+v", got[0])
	}
}

func TestProjectFields(t *testing.T) {
	items := []json.RawMessage{json.RawMessage(`{"name":"x","attributes":{"status":"open","noise":1},"drop":true}`)}
	got, err := Project(items, []string{"name", "attributes.status"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"name": "x", "attributes": map[string]any{"status": "open"}}
	if !reflect.DeepEqual(got[0], want) {
		t.Errorf("projection = %+v, want %+v", got[0], want)
	}
}

func TestClampPageBoundary(t *testing.T) {
	// Test that size == max stays max (not clamped)
	gotNum, gotSize := ClampPage(1, 100, 25, 100)
	if gotNum != 0 || gotSize != 100 {
		t.Errorf("size == max: got (%d,%d) want (0,100)", gotNum, gotSize)
	}
	// Test that size == max+1 clamps to max
	gotNum, gotSize = ClampPage(1, 101, 25, 100)
	if gotNum != 0 || gotSize != 100 {
		t.Errorf("size == max+1: got (%d,%d) want (0,100)", gotNum, gotSize)
	}
}

func TestProjectMergeNotOverwrite(t *testing.T) {
	// Test that multiple fields under same parent key merge into one map
	items := []json.RawMessage{json.RawMessage(`{"a":{"b":1,"c":2,"d":3}}`)}
	got, err := Project(items, []string{"a.b", "a.c"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"a": map[string]any{"b": float64(1), "c": float64(2)}}
	if !reflect.DeepEqual(got[0], want) {
		t.Errorf("merge projection = %+v, want %+v", got[0], want)
	}
}

func TestProjectMissingKey(t *testing.T) {
	// Test that fields referencing absent paths don't panic or error
	// When top-level key is missing ("missing"), it's omitted entirely
	// When nested key is missing ("a.absent"), an empty nested map is created ("a":{})
	items := []json.RawMessage{json.RawMessage(`{"a":{"b":1}}`)}
	got, err := Project(items, []string{"missing", "a.absent"})
	if err != nil {
		t.Fatal(err)
	}
	// Top-level missing key is omitted, nested missing key results in empty nested map
	want := map[string]any{"a": map[string]any{}}
	if !reflect.DeepEqual(got[0], want) {
		t.Errorf("missing key projection = %+v, want %+v", got[0], want)
	}
}

func TestProjectNonObjectIntermediate(t *testing.T) {
	// Test that fields like ["a.b"] on {"a":"stringval"} don't panic and omit a
	items := []json.RawMessage{json.RawMessage(`{"a":"stringval"}`)}
	got, err := Project(items, []string{"a.b"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{}
	if !reflect.DeepEqual(got[0], want) {
		t.Errorf("non-object intermediate = %+v, want %+v", got[0], want)
	}
}

func TestProjectInvalidJSON(t *testing.T) {
	// Test that invalid JSON makes Project return non-nil error
	items := []json.RawMessage{json.RawMessage("{not json")}
	_, err := Project(items, []string{"a"})
	if err == nil {
		t.Error("invalid JSON should return error, got nil")
	}
}
