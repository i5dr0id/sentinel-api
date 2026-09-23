package server

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"

	"github.com/i5dr0id/sentinel-api/internal/alerts"
	"github.com/i5dr0id/sentinel-api/internal/config"
	"github.com/i5dr0id/sentinel-api/internal/containment"
	"github.com/i5dr0id/sentinel-api/internal/edge"
	"github.com/i5dr0id/sentinel-api/internal/event"
	"github.com/i5dr0id/sentinel-api/internal/requests"
)

type Handlers struct {
	cfg      *config.Config
	log      *zerolog.Logger
	svc      *alerts.Service
	ctr      *containment.Service
	edge     *edge.Engine
	ring     requests.Store
	hub      *requests.Hub
	pipeline *Pipeline
}

func (h *Handlers) Health(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"status":  "ok",
		"uptime":  int64(h.pipeline.Uptime().Seconds()),
		"events":  h.pipeline.EventsTotal(),
		"store":   h.cfg.Store.Kind,
		"sim":     h.cfg.Sim.Enabled,
		"version": "0.1.0",
	})
}

func (h *Handlers) Summary(c *fiber.Ctx) error {
	counts, err := h.svc.Counts()
	if err != nil {
		return fiberErr(c, http.StatusInternalServerError, err)
	}
	mttr, mttrN, _ := h.svc.MTTR()

	assets := make([]fiber.Map, 0, len(h.cfg.Assets))
	for _, name := range h.cfg.Assets {
		active := 0
		all, _ := h.svc.List(alerts.Filter{Asset: name, Limit: 500})
		for _, a := range all {
			if a.Status.IsActive() {
				active++
			}
		}
		assets = append(assets, fiber.Map{"name": name, "alerts": active})
	}

	timeline := h.alertTimeline(30)

	activeContainment := 0
	for _, c := range h.ctr.List("") {
		if c.Status == containment.StatusActive {
			activeContainment++
		}
	}

	return c.JSON(fiber.Map{
		"assets":         assets,
		"counts":         counts,
		"mttr_minutes":   mttr.Minutes(),
		"mttr_sample":    mttrN,
		"active_threats": counts.TotalActive,
		"live":           true,
		"events_total":   h.pipeline.EventsTotal(),
		"events_per_sec": h.pipeline.EventsPerSec(),
		"alert_timeline": timeline,
		"containment": fiber.Map{
			"active":    activeContainment,
			"blocked":   h.edge.Blocked(),
			"by_reason": h.edge.BlockedByReason(),
		},
		"started_at": h.pipeline.started.Format(time.RFC3339),
	})
}

func (h *Handlers) alertTimeline(minutes int) []fiber.Map {
	all, err := h.svc.List(alerts.Filter{Limit: 500})
	if err != nil {
		return nil
	}
	now := time.Now()
	out := make([]fiber.Map, minutes)
	for i := 0; i < minutes; i++ {
		out[i] = fiber.Map{"t": now.Add(-time.Duration(minutes-1-i) * time.Minute).Format("15:04"), "total": 0, "critical": 0}
	}
	idx := func(ts time.Time) int {
		d := int(now.Sub(ts).Minutes())
		if d < 0 {
			return -1
		}
		return minutes - 1 - d
	}
	for _, a := range all {
		if i := idx(a.StartedAt); i >= 0 && i < minutes {
			out[i]["total"] = out[i]["total"].(int) + 1
			if a.Severity == event.SeverityCritical {
				out[i]["critical"] = out[i]["critical"].(int) + 1
			}
		}
	}
	return out
}

func (h *Handlers) Assets(c *fiber.Ctx) error {
	return c.JSON(h.cfg.Assets)
}

func (h *Handlers) ListAlerts(c *fiber.Ctx) error {
	f := alerts.Filter{
		Status:   alerts.Status(c.Query("status")),
		Severity: event.Severity(c.Query("severity")),
		Asset:    c.Query("asset"),
		Assignee: c.Query("assignee"),
		RuleID:   c.Query("rule"),
		Query:    c.Query("q"),
		Limit:    c.QueryInt("limit", 50),
		Offset:   c.QueryInt("offset", 0),
	}
	out, err := h.svc.List(f)
	if err != nil {
		return fiberErr(c, http.StatusInternalServerError, err)
	}
	return c.JSON(fiber.Map{"items": out, "count": len(out)})
}

func (h *Handlers) GetAlert(c *fiber.Ctx) error {
	a, err := h.svc.Get(c.Params("id"))
	if err != nil {
		return fiberErr(c, http.StatusNotFound, alerts.ErrNotFound)
	}
	return c.JSON(a)
}

func (h *Handlers) AlertEvents(c *fiber.Ctx) error {
	related := h.svc.RelatedEvents(c.Params("id"), h.ring.Snapshot(), 100)
	return c.JSON(fiber.Map{"items": related, "count": len(related)})
}

func (h *Handlers) Assign(c *fiber.Ctx) error {
	var body struct {
		Assignee string `json:"assignee"`
		Actor    string `json:"actor"`
	}
	if err := json.Unmarshal(c.Body(), &body); err != nil {
		return fiberErr(c, http.StatusBadRequest, err)
	}
	if body.Assignee == "" {
		return fiberErr(c, http.StatusBadRequest, fmt.Errorf("assignee is required"))
	}
	if body.Actor == "" {
		body.Actor = "console"
	}
	a, err := h.svc.Assign(c.Params("id"), body.Assignee, body.Actor)
	if err != nil {
		return fiberErr(c, http.StatusBadRequest, err)
	}
	return c.JSON(a)
}

func (h *Handlers) SetStatus(c *fiber.Ctx) error {
	var body struct {
		Status string `json:"status"`
		Actor  string `json:"actor"`
	}
	if err := json.Unmarshal(c.Body(), &body); err != nil {
		return fiberErr(c, http.StatusBadRequest, err)
	}
	if body.Actor == "" {
		body.Actor = "console"
	}
	a, err := h.svc.SetStatus(c.Params("id"), alerts.Status(body.Status), body.Actor)
	if err != nil {
		return fiberErr(c, http.StatusBadRequest, err)
	}
	return c.JSON(a)
}

func (h *Handlers) Action(c *fiber.Ctx) error {
	var body struct {
		Action string `json:"action"`
		Note   string `json:"note"`
		Actor  string `json:"actor"`
	}
	if err := json.Unmarshal(c.Body(), &body); err != nil {
		return fiberErr(c, http.StatusBadRequest, err)
	}
	if body.Actor == "" {
		body.Actor = "console"
	}
	a, err := h.svc.Action(c.Params("id"), alerts.ActionType(body.Action), body.Note, body.Actor)
	if err != nil {
		return fiberErr(c, http.StatusBadRequest, err)
	}
	return c.JSON(a)
}

func (h *Handlers) ListRequests(c *fiber.Ctx) error {
	limit := c.QueryInt("limit", 50)
	if limit > 500 {
		limit = 500
	}
	items := h.ring.Recent(c.Query("asset"), limit, c.QueryInt("offset", 0))
	return c.JSON(fiber.Map{"items": items, "count": len(items)})
}

func (h *Handlers) StreamRequests(c *fiber.Ctx) error {
	c.Set("Content-Type", "text/event-stream")
	c.Set("Cache-Control", "no-cache")
	c.Set("Connection", "keep-alive")
	c.Set("X-Accel-Buffering", "no")

	asset := c.Query("asset")
	ctx := c.Context()

	c.Context().SetBodyStreamWriter(func(w *bufio.Writer) {
		_, ch, close := h.hub.Subscribe()
		defer close()
		heartbeat := time.NewTicker(15 * time.Second)
		defer heartbeat.Stop()
		for {
			select {
			case ev := <-ch:
				if asset != "" && ev.Asset != asset {
					continue
				}
				data, err := json.Marshal(ev)
				if err != nil {
					continue
				}
				if _, err := fmt.Fprintf(w, "event: request\ndata: %s\n\n", data); err != nil {
					return
				}
				w.Flush()
			case <-heartbeat.C:
				if _, err := fmt.Fprintf(w, ": keepalive\n\n"); err != nil {
					return
				}
				w.Flush()
			case <-ctx.Done():
				return
			}
		}
	})
	return nil
}

func (h *Handlers) Metrics(c *fiber.Ctx) error {
	window := c.QueryInt("window", 30)
	if window > 120 {
		window = 120
	}
	asset := c.Query("asset")

	snap := h.ring.Snapshot()
	now := time.Now()
	buckets := make([]fiber.Map, window)
	for i := 0; i < window; i++ {
		buckets[i] = fiber.Map{
			"t":        now.Add(-time.Duration(window-1-i) * time.Minute).Format("15:04"),
			"requests": 0, "errors": 0, "blocked": 0,
		}
	}
	bidx := func(ts time.Time) int {
		d := int(now.Sub(ts).Minutes())
		if d < 0 {
			return -1
		}
		return window - 1 - d
	}
	for _, e := range snap {
		if asset != "" && e.Asset != asset {
			continue
		}
		if i := bidx(e.Timestamp); i >= 0 && i < window {
			b := buckets[i]
			b["requests"] = b["requests"].(int) + 1
			if e.Status >= 400 {
				b["errors"] = b["errors"].(int) + 1
			}
			if e.HasTag(event.TagWAFBlock) || e.Status == 403 {
				b["blocked"] = b["blocked"].(int) + 1
			}
		}
	}
	return c.JSON(fiber.Map{"window_minutes": window, "series": buckets})
}

type ingestRequest struct {
	Source event.Source   `json:"source"`
	Asset  string         `json:"asset"`
	Fields map[string]any `json:"fields"`
}

func (h *Handlers) Ingest(c *fiber.Ctx) error {
	if h.cfg.IngestToken != "" && c.Get("Authorization") != "Bearer "+h.cfg.IngestToken {
		return fiberErr(c, http.StatusUnauthorized, fmt.Errorf("unauthorized"))
	}

	body := c.Body()
	accepted := 0
	parse := func(raw json.RawMessage) {
		var req ingestRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			return
		}
		if req.Source == "" {
			return
		}
		select {
		case h.pipeline.Ingest() <- event.RawLog{Source: req.Source, Asset: req.Asset, Fields: req.Fields}:
			accepted++
		default:
			h.log.Warn().Msg("ingest: pipeline full, dropped log")
		}
	}

	trimmed := strings.TrimSpace(string(body))
	switch {
	case strings.HasPrefix(trimmed, "["):
		var list []json.RawMessage
		if err := json.Unmarshal([]byte(trimmed), &list); err != nil {
			return fiberErr(c, http.StatusBadRequest, err)
		}
		for _, item := range list {
			parse(item)
		}
	case strings.Contains(trimmed, "\n"):
		for _, line := range strings.Split(trimmed, "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			parse(json.RawMessage(line))
		}
	default:
		parse(json.RawMessage(trimmed))
	}
	return c.JSON(fiber.Map{"accepted": accepted})
}

func fiberErr(c *fiber.Ctx, status int, err error) error {
	return c.Status(status).JSON(fiber.Map{"error": err.Error()})
}
