package ingest

import (
	"fmt"
	"strconv"
	"strings"
)

func firstStr(f map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := f[k]; ok && v != nil {
			if s, ok := asString(v); ok {
				return strings.TrimSpace(s)
			}
		}
	}
	return ""
}

func firstInt(f map[string]any, keys ...string) int {
	for _, k := range keys {
		if v, ok := f[k]; ok && v != nil {
			switch t := v.(type) {
			case int:
				return t
			case int64:
				return int(t)
			case float64:
				return int(t)
			case string:
				if i, err := strconv.Atoi(strings.TrimSpace(t)); err == nil {
					return i
				}
			}
		}
	}
	return 0
}

func asString(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, true
	case fmt.Stringer:
		return t.String(), true
	}
	return "", false
}

func toTags(v any) []string {
	var raw []string
	switch t := v.(type) {
	case []string:
		raw = t
	case []any:
		for _, e := range t {
			if s, ok := asString(e); ok {
				raw = append(raw, s)
			}
		}
	case string:
		raw = strings.Split(t, ",")
	}
	out := make([]string, 0, len(raw))
	for _, s := range raw {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}
