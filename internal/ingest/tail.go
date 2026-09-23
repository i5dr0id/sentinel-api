package ingest

import (
	"bufio"
	"os"
	"strings"

	"github.com/rs/zerolog"

	"github.com/i5dr0id/sentinel-api/internal/event"
)

type Tailer struct {
	paths []string
	asset string
	out   chan<- event.RawLog
	log   *zerolog.Logger
	stop  chan struct{}
}

func NewTailer(paths []string, asset string, out chan<- event.RawLog, log *zerolog.Logger) *Tailer {
	return &Tailer{paths: paths, asset: asset, out: out, log: log}
}

func (t *Tailer) Start() {
	t.stop = make(chan struct{})
	for _, p := range t.paths {
		go t.tailFile(p)
	}
}

func (t *Tailer) Stop() {
	if t.stop != nil {
		close(t.stop)
	}
}

func (t *Tailer) tailFile(path string) {
	f, err := os.Open(path)
	if err != nil {
		t.log.Warn().Err(err).Str("path", path).Msg("tailer: cannot open log file")
		return
	}
	defer f.Close()

	if _, err := f.Seek(0, 2); err != nil {
		return
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for {
		select {
		case <-t.stop:
			return
		default:
			if sc.Scan() {
				if raw, ok := parseLine(sc.Text(), t.asset); ok {
					select {
					case t.out <- raw:
					case <-t.stop:
						return
					}
				}
				continue
			}
			if err := sc.Err(); err != nil {
				return
			}

			if _, err := f.Seek(0, 2); err != nil {
				return
			}
			sc = bufio.NewScanner(f)
			sc.Buffer(make([]byte, 1024*1024), 1024*1024)
		}
	}
}

func parseLine(line, asset string) (event.RawLog, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return event.RawLog{}, false
	}
	if f, ok := parseNginxCombined(line); ok {
		return event.RawLog{Source: event.SourceNginx, Asset: asset, Fields: f}, true
	}
	if f, ok := parseSSHLine(line); ok {
		return event.RawLog{Source: event.SourceSSH, Asset: asset, Fields: f}, true
	}
	return event.RawLog{}, false
}

func parseNginxCombined(line string) (map[string]any, bool) {
	rest := line
	ip := strings.SplitN(rest, " ", 2)[0]
	if ip == "" || len(ip) > 45 || !strings.Contains(rest, `"`) {
		return nil, false
	}
	rest = rest[len(ip)+1:]
	if !strings.HasPrefix(rest, "- ") {
		return nil, false
	}
	rest = rest[2:]

	if i := strings.Index(rest, "["); i >= 0 {
		rest = rest[i:]
	} else {
		return nil, false
	}
	if i := strings.Index(rest, "]"); i >= 0 {
		rest = rest[i+2:]
	} else {
		return nil, false
	}

	var request, status, ua, referer string
	if !quotedToken(rest, &request, &rest) {
		return nil, false
	}
	status = strings.Fields(rest)[0]

	if i := strings.Index(rest, `"`); i >= 0 {
		rest = rest[i:]
	}
	if !quotedToken(rest, &referer, &rest) {
		return nil, false
	}
	if !quotedToken(rest, &ua, &rest) {
		return nil, false
	}
	method, path, proto := parseRequestLine(request)
	f := map[string]any{
		"ip": ip, "request": request, "status": status, "referer": referer,
		"user_agent": ua,
	}
	if method != "" {
		f["method"] = method
		f["path"] = path
		if proto != "" {
			f["proto"] = proto
		}
	}
	return f, true
}

func quotedToken(s string, dst *string, rest *string) bool {
	s = strings.TrimLeft(s, " ")
	if !strings.HasPrefix(s, `"`) {
		return false
	}
	end := strings.Index(s[1:], `"`)
	if end < 0 {
		return false
	}
	*dst = s[1 : 1+end]
	*rest = s[1+end+1:]
	return true
}

func parseSSHLine(line string) (map[string]any, bool) {
	lower := strings.ToLower(line)
	fields := map[string]any{}
	switch {
	case strings.Contains(lower, "failed password for"):
		user := wordAfter(line, "failed password for ")
		ip := wordAfter(line, "from ")
		fields["user"] = strings.TrimSpace(user)
		fields["ip"] = strings.TrimSpace(ip)
		fields["message"] = line
		fields["tags"] = []string{event.TagAuthFailure}
		return fields, true
	case strings.Contains(lower, "invalid user"):
		ip := wordAfter(line, "from ")
		fields["user"] = wordAfter(line, "invalid user ")
		fields["ip"] = strings.TrimSpace(ip)
		fields["message"] = line
		fields["tags"] = []string{event.TagAuthFailure}
		return fields, true
	}
	return nil, false
}

func wordAfter(s, token string) string {
	lower := strings.ToLower(s)
	tk := strings.ToLower(token)
	if i := strings.Index(lower, tk); i >= 0 {
		start := i + len(token)
		w := strings.TrimSpace(s[start:])
		if j := strings.IndexAny(w, " \t"); j >= 0 {
			return w[:j]
		}
		return w
	}
	return ""
}
