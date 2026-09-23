package requests

import (
	"sync"

	"github.com/i5dr0id/sentinel-api/internal/event"
)

type Store interface {
	Append(ev *event.NormalizedEvent)
	Recent(asset string, limit, offset int) []*event.NormalizedEvent
	Snapshot() []*event.NormalizedEvent
}

type Ring struct {
	mu   sync.RWMutex
	cap  int
	buf  []*event.NormalizedEvent
	next int
	full bool
}

func NewRing(capacity int) *Ring {
	if capacity <= 0 {
		capacity = 4096
	}
	return &Ring{cap: capacity, buf: make([]*event.NormalizedEvent, capacity)}
}

func (r *Ring) Append(ev *event.NormalizedEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf[r.next] = ev
	r.next = (r.next + 1) % r.cap
	if r.next == 0 {
		r.full = true
	}
}

func (r *Ring) Snapshot() []*event.NormalizedEvent {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*event.NormalizedEvent, 0, r.lenLocked())
	start := 0
	if r.full {
		start = r.next
	}
	for i := 0; i < r.lenLocked(); i++ {
		out = append(out, r.buf[(start+i)%r.cap])
	}
	return out
}

func (r *Ring) lenLocked() int {
	if r.full {
		return r.cap
	}
	return r.next
}

func (r *Ring) Recent(asset string, limit, offset int) []*event.NormalizedEvent {
	all := r.Snapshot()
	if asset != "" {
		filtered := make([]*event.NormalizedEvent, 0, len(all))
		for _, e := range all {
			if e.Asset == asset {
				filtered = append(filtered, e)
			}
		}
		all = filtered
	}
	if offset > len(all) {
		offset = len(all)
	}
	all = all[:len(all)-offset]
	if limit > 0 && len(all) > limit {
		all = all[len(all)-limit:]
	}
	return all
}

type Hub struct {
	mu   sync.Mutex
	subs map[int]chan *event.NormalizedEvent
	next int
}

func NewHub() *Hub { return &Hub{subs: map[int]chan *event.NormalizedEvent{}} }

func (h *Hub) Subscribe() (int, <-chan *event.NormalizedEvent, func()) {
	h.mu.Lock()
	defer h.mu.Unlock()
	id := h.next
	h.next++
	ch := make(chan *event.NormalizedEvent, 128)
	h.subs[id] = ch
	return id, ch, func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		if c, ok := h.subs[id]; ok {
			delete(h.subs, id)
			close(c)
		}
	}
}

func (h *Hub) Publish(ev *event.NormalizedEvent) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for id, ch := range h.subs {
		select {
		case ch <- ev:
		default:

			select {
			case <-ch:
			default:
			}
			select {
			case ch <- ev:
			default:
				delete(h.subs, id)
				close(ch)
			}
		}
	}
}
