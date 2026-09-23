package edge

import (
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"

	"github.com/i5dr0id/sentinel-api/internal/event"
)

type Kind string

const (
	KindDeny      Kind = "deny"
	KindRateLimit Kind = "rate_limit"
	KindWAF       Kind = "waf"
)

type Policy struct {
	SourceID    string     `json:"source_id"`
	Kind        Kind       `json:"kind"`
	TargetIP    string     `json:"target_ip,omitempty"`
	Enforcement string     `json:"enforcement,omitempty"`
	RatePerSec  float64    `json:"rate_per_sec,omitempty"`
	Burst       int        `json:"burst,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

const (
	defaultRate  = 2.0
	defaultBurst = 5
	wafSourceID  = "waf-managed-ruleset"
)

type bucket struct {
	tokens float64
	last   time.Time
}

type Engine struct {
	log      *zerolog.Logger
	mu       sync.RWMutex
	policies map[string]*Policy
	buckets  map[string]*bucket
	blocked  atomic.Int64
	byReason [3]atomic.Int64
}

func NewEngine(log *zerolog.Logger) *Engine {
	return &Engine{
		log:      log,
		policies: map[string]*Policy{},
		buckets:  map[string]*bucket{},
	}
}

func (e *Engine) Install(p Policy) {
	if p.SourceID == "" {
		return
	}
	if p.RatePerSec <= 0 {
		p.RatePerSec = defaultRate
	}
	if p.Burst <= 0 {
		p.Burst = defaultBurst
	}
	e.mu.Lock()
	e.policies[p.SourceID] = &p
	e.mu.Unlock()
	e.log.Info().Str("source", p.SourceID).Str("kind", string(p.Kind)).
		Str("ip", p.TargetIP).Msg("edge policy installed")
}

func (e *Engine) Remove(sourceID string) {
	e.mu.Lock()
	delete(e.policies, sourceID)
	if sourceID == wafSourceID {
		for k := range e.buckets {
			delete(e.buckets, k)
		}
	}
	e.mu.Unlock()
	e.log.Info().Str("source", sourceID).Msg("edge policy removed")
}

func (e *Engine) Eval(ev *event.NormalizedEvent) bool {
	now := time.Now()

	e.mu.Lock()
	var reason Kind
	if deny := e.matchLocked(KindDeny, ev.SrcIP, now); deny != nil {
		reason = KindDeny
	} else if rate := e.matchLocked(KindRateLimit, ev.SrcIP, now); rate != nil {
		if !e.allowLocked(rate, ev.SrcIP, now) {
			reason = KindRateLimit
		}
	} else if e.matchLocked(KindWAF, "", now) != nil && isAttack(ev) {
		reason = KindWAF
	}
	e.mu.Unlock()

	if reason == "" {
		return false
	}

	switch reason {
	case KindRateLimit:
		ev.Status = 429
	default:
		ev.Status = 403
	}
	ev.Tags = append(ev.Tags, event.TagWAFBlock, "contained:"+string(reason))
	e.blocked.Add(1)
	e.byReason[reasonIndex(reason)].Add(1)
	return true
}

func (e *Engine) matchLocked(kind Kind, ip string, now time.Time) *Policy {
	for _, p := range e.policies {
		if p.Kind != kind {
			continue
		}
		if p.ExpiresAt != nil && now.After(*p.ExpiresAt) {
			continue
		}
		if p.TargetIP == "" || p.TargetIP == ip {
			return p
		}
	}
	return nil
}

func (e *Engine) allowLocked(p *Policy, ip string, now time.Time) bool {
	b, ok := e.buckets[ip]
	if !ok {
		b = &bucket{tokens: float64(p.Burst), last: now}
		e.buckets[ip] = b
	}
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens = math.Min(float64(p.Burst), b.tokens+elapsed*p.RatePerSec)
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

func isAttack(ev *event.NormalizedEvent) bool {
	for _, t := range ev.Tags {
		switch t {
		case event.TagSQLi, event.TagWebshell, event.TagBruteForce, event.TagScan, event.TagAuthFailure:
			return true
		}
	}
	return false
}

func (e *Engine) Blocked() int64 { return e.blocked.Load() }

func (e *Engine) BlockedByReason() map[string]int64 {
	return map[string]int64{
		string(KindDeny):      e.byReason[0].Load(),
		string(KindRateLimit): e.byReason[1].Load(),
		string(KindWAF):       e.byReason[2].Load(),
	}
}

func (e *Engine) ActivePolicies() []Policy {
	e.mu.RLock()
	defer e.mu.RUnlock()
	now := time.Now()
	out := []Policy{}
	for _, p := range e.policies {
		if p.ExpiresAt != nil && now.After(*p.ExpiresAt) {
			continue
		}
		out = append(out, *p)
	}
	return out
}

func reasonIndex(k Kind) int {
	switch k {
	case KindDeny:
		return 0
	case KindRateLimit:
		return 1
	default:
		return 2
	}
}
