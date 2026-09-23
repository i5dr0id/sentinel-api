package server

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"

	"github.com/i5dr0id/sentinel-api/internal/alerts"
	"github.com/i5dr0id/sentinel-api/internal/detect"
	"github.com/i5dr0id/sentinel-api/internal/edge"
	"github.com/i5dr0id/sentinel-api/internal/event"
	"github.com/i5dr0id/sentinel-api/internal/ingest"
	"github.com/i5dr0id/sentinel-api/internal/requests"
)

type Pipeline struct {
	raw     chan event.RawLog
	norm    *ingest.Normalizer
	engine  *detect.Engine
	edge    *edge.Engine
	alerts  *alerts.Service
	ring    requests.Store
	hub     *requests.Hub
	log     *zerolog.Logger
	events  atomic.Uint64
	started time.Time
	ctx     context.Context
	cancel  context.CancelFunc
	rate    *rateWindow
}

func newPipeline(raw chan event.RawLog, norm *ingest.Normalizer, engine *detect.Engine,
	edge *edge.Engine, svc *alerts.Service, ring requests.Store, hub *requests.Hub, log *zerolog.Logger) *Pipeline {
	ctx, cancel := context.WithCancel(context.Background())
	return &Pipeline{
		raw: raw, norm: norm, engine: engine, edge: edge, alerts: svc, ring: ring, hub: hub,
		log: log, started: time.Now(), ctx: ctx, cancel: cancel, rate: newRateWindow(60),
	}
}

func (p *Pipeline) Ingest() chan<- event.RawLog { return p.raw }

func (p *Pipeline) Start() {
	go func() {
		for {
			select {
			case <-p.ctx.Done():
				return
			case raw := <-p.raw:
				now := time.Now()
				ev := p.norm.Normalize(raw, now)
				p.events.Add(1)
				p.rate.add(now)

				if !p.edge.Eval(ev) {
					p.engine.Process(ev, p.alerts.Emitter())
				}
				p.ring.Append(ev)
				p.hub.Publish(ev)
			}
		}
	}()
}

func (p *Pipeline) Stop() { p.cancel() }

func (p *Pipeline) EventsTotal() uint64   { return p.events.Load() }
func (p *Pipeline) EventsPerSec() float64 { return p.rate.avg() }
func (p *Pipeline) Uptime() time.Duration { return time.Since(p.started) }

type rateWindow struct {
	idx  int
	last time.Time
	vals [60]uint64
}

func newRateWindow(size int) *rateWindow { return &rateWindow{vals: [60]uint64{}} }

func (r *rateWindow) add(t time.Time) {
	sec := t.Unix()
	if r.last.IsZero() || sec != r.last.Unix() {
		if !r.last.IsZero() {
			r.idx = (r.idx + 1) % len(r.vals)
		}
		r.last = t.Truncate(time.Second)
	}
	r.vals[r.idx]++
}

func (r *rateWindow) avg() float64 {
	var sum uint64
	for _, v := range r.vals {
		sum += v
	}
	return float64(sum) / float64(len(r.vals))
}
