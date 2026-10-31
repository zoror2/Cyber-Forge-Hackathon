package jsonvalue

import "testing"

func TestPointerEscapesAndMissingValues(t *testing.T) {
	v := map[string]any{"": "empty", "a/b": map[string]any{"~key": []any{"first", nil}}, "~1": "ordered escape"}
	for _, tc := range []struct {
		path  string
		want  any
		found bool
	}{
		{"/", "empty", true}, {"/a~1b/~0key/0", "first", true}, {"/a~1b/~0key/1", nil, true},
		{"/~01", "ordered escape", true}, {"/~2", nil, false}, {"/a~", nil, false},
		{"/a~1b/~0key/-", nil, false}, {"/a~1b/~0key/01", nil, false},
		{"/a~1b/~0key/+0", nil, false}, {"/a~1b/~0key/2", nil, false}, {"/missing", nil, false},
	} {
		got, ok := Path(v, tc.path)
		if got != tc.want || ok != tc.found {
			t.Errorf("%q: got %v/%v, want %v/%v", tc.path, got, ok, tc.want, tc.found)
		}
	}
	if got, ok := Path(v, ""); !ok || got == nil {
		t.Fatal("root missing")
	}
}
