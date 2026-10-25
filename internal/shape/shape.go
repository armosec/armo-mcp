package shape

import (
	"encoding/json"
	"strings"
)

func ClampPage(page, size, def, max int) (int, int) {
	if page < 1 {
		page = 1
	}
	if size <= 0 {
		size = def
	}
	if size > max {
		size = max
	}
	return page - 1, size
}

func Project(items []json.RawMessage, fields []string) ([]map[string]any, error) {
	out := make([]map[string]any, 0, len(items))
	for _, raw := range items {
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, err
		}
		if len(fields) == 0 {
			out = append(out, m)
			continue
		}
		projected := map[string]any{}
		for _, f := range fields {
			copyPath(m, projected, strings.Split(f, "."))
		}
		out = append(out, projected)
	}
	return out, nil
}

// copyPath copies the value at dotted path segments from src into dst, creating nested maps as needed.
func copyPath(src, dst map[string]any, segs []string) {
	if len(segs) == 0 {
		return
	}
	key := segs[0]
	val, ok := src[key]
	if !ok {
		return
	}
	if len(segs) == 1 {
		dst[key] = val
		return
	}
	child, ok := val.(map[string]any)
	if !ok {
		return
	}
	nested, ok := dst[key].(map[string]any)
	if !ok {
		nested = map[string]any{}
		dst[key] = nested
	}
	copyPath(child, nested, segs[1:])
}
