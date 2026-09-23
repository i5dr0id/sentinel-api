package detect

import (
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/i5dr0id/sentinel-api/internal/event"
)

type windowEntry struct {
	ts time.Time
	ev *event.NormalizedEvent
}

type Engine struct {
	log *zerolog.Logger

	mu      sync.Mutex
	windows map[string]map[string][]windowEntry
}

func NewEngine(log *zerolog.Logger) *Engine {
	return &Engine{log: log, windows: map[string]map[string][]windowEntry{}}
}

type Emitter func(r *Rule, evs []*event.NormalizedEvent, o Outcome)

func (e *Engine) Process(ev *event.NormalizedEvent, emit Emitter) {
	if emit == nil {
		return
	}
	now := ev.Timestamp
	for _, r := range Rules() {
		if !r.Match(ev) {
			continue
		}
		key := r.Key(ev)
		if key == "" {
			continue
		}
		e.mu.Lock()
		byKey, ok := e.windows[r.ID]
		if !ok {
			byKey = map[string][]windowEntry{}
			e.windows[r.ID] = byKey
		}
		entries := byKey[key]

		cut := now.Add(-r.Window)
		kept := entries[:0]
		for _, ent := range entries {
			if ent.ts.After(cut) {
				kept = append(kept, ent)
			}
		}
		kept = append(kept, windowEntry{ts: now, ev: ev})
		byKey[key] = kept
		e.mu.Unlock()

		evs := make([]*event.NormalizedEvent, 0, len(kept))
		for _, ent := range kept {
			evs = append(evs, ent.ev)
		}
		if o, ok := r.ShouldAlert(evs); ok {
			emit(r, evs, o)
		}
	}
}

func (e *Engine) Drain() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.windows = map[string]map[string][]windowEntry{}
}

func regexpMust(p string) *regexp.Regexp { return regexp.MustCompile(p) }

func itoa(i int) string { return strconv.Itoa(i) }
