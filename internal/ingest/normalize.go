package ingest

import (
	"fmt"
	"strings"
	"time"

	"github.com/i5dr0id/sentinel-api/internal/enrich"
	"github.com/i5dr0id/sentinel-api/internal/event"
)

type Normalizer struct {
	geo enrich.Resolver
}

func NewNormalizer(geo enrich.Resolver) *Normalizer { return &Normalizer{geo: geo} }

func (n *Normalizer) Normalize(raw event.RawLog, ts time.Time) *event.NormalizedEvent {
	f := raw.Fields
	if f == nil {
		f = map[string]any{}
	}

	ev := &event.NormalizedEvent{
		ID:        fmt.Sprintf("evt-%d-%d", ts.UnixNano(), hashFields(f)),
		Timestamp: ts,
		Source:    raw.Source,
		Asset:     raw.Asset,
		SrcIP:     firstStr(f, "ip", "src_ip", "client_ip", "remote_addr", "host"),
		SrcPort:   firstInt(f, "port", "src_port", "remote_port"),
		User:      firstStr(f, "user", "username", "account"),
		Message:   firstStr(f, "message", "msg"),
	}

	req := firstStr(f, "request", "request_line", "req")
	if method, path, proto := parseRequestLine(req); method != "" {
		ev.Method = method
		ev.Path = path
		ev.Proto = proto
	} else {
		ev.Method = firstStr(f, "method", "verb")
		ev.Path = firstStr(f, "path", "uri", "endpoint", "url")
	}
	if ev.Path == "" {
		ev.Path = "/"
	}
	ev.Status = firstInt(f, "status", "status_code", "response", "code")
	if ev.Status == 0 {
		ev.Status = firstInt(f, "sc_status")
	}
	ev.Size = firstInt(f, "size", "bytes", "body_bytes_sent")
	ev.UserAgent = firstStr(f, "user_agent", "ua", "agent")
	ev.Referer = firstStr(f, "referer", "referrer")

	for _, k := range []string{"tags", "tag", "labels"} {
		if v, ok := f[k]; ok {
			ev.Tags = toTags(v)
			break
		}
	}

	extra := map[string]string{}
	for k, v := range f {
		switch strings.ToLower(k) {
		case "ip", "src_ip", "client_ip", "remote_addr", "host", "port", "src_port",
			"remote_port", "request", "request_line", "req", "method", "verb", "path",
			"uri", "endpoint", "url", "status", "status_code", "response", "code",
			"sc_status", "size", "bytes", "body_bytes_sent", "user_agent", "ua", "agent", "referer", "referrer", "user",
			"username", "account", "message", "msg", "tags", "tag", "labels", "timestamp", "ts", "time":
			continue
		}
		extra[k] = fmt.Sprintf("%v", v)
	}
	if len(extra) > 0 {
		ev.Extra = extra
	}

	if ip := ev.SrcIP; ip != "" {
		if g, ok := n.geo.Lookup(ip); ok {
			ev.Geo = &g
		}
	}
	return ev
}

func parseRequestLine(req string) (method, path, proto string) {
	req = strings.TrimSpace(req)
	if req == "" {
		return
	}
	parts := strings.Fields(req)
	if len(parts) >= 2 && len(parts[0]) <= 8 && isUpper(parts[0]) {
		method = parts[0]
		path = parts[1]
		if len(parts) >= 3 {
			proto = parts[2]
		}
	}
	return
}

func isUpper(s string) bool {
	for _, r := range s {
		if r < 'A' || r > 'Z' {
			return false
		}
	}
	return len(s) > 0
}

func hashFields(f map[string]any) int {
	h := 0
	for k, v := range f {
		h += len(k) + len(fmt.Sprintf("%v", v))
	}
	return h % 99999
}
