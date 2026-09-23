package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/i5dr0id/sentinel-api/internal/alerts"
	"github.com/i5dr0id/sentinel-api/internal/analysis"
	"github.com/i5dr0id/sentinel-api/internal/containment"
	"github.com/i5dr0id/sentinel-api/internal/edge"
)

func (h *Handlers) alertsForSource(a *alerts.Alert) []*alerts.Alert {
	all, err := h.svc.List(alerts.Filter{Limit: 500})
	if err != nil {
		return nil
	}
	out := []*alerts.Alert{}
	for _, x := range all {
		if (a.SrcIP != "" && x.SrcIP == a.SrcIP) || (a.SrcIP == "" && x.Asset == a.Asset) {
			out = append(out, x)
		}
	}
	return out
}

func (h *Handlers) AlertChain(c *fiber.Ctx) error {
	a, err := h.svc.Get(c.Params("id"))
	if err != nil {
		return fiberErr(c, http.StatusNotFound, alerts.ErrNotFound)
	}
	chain := analysis.BuildChain(h.alertsForSource(a))
	return c.JSON(chain)
}

func (h *Handlers) AlertIOCs(c *fiber.Ctx) error {
	a, err := h.svc.Get(c.Params("id"))
	if err != nil {
		return fiberErr(c, http.StatusNotFound, alerts.ErrNotFound)
	}
	iocs := analysis.ExtractIOCs(a, h.svc.RelatedEvents(a.ID, h.ring.Snapshot(), 100))
	return c.JSON(fiber.Map{"items": iocs, "count": len(iocs)})
}

func (h *Handlers) ListIncidents(c *fiber.Ctx) error {
	all, err := h.svc.List(alerts.Filter{Limit: 500})
	if err != nil {
		return fiberErr(c, http.StatusInternalServerError, err)
	}
	incidents := analysis.GroupIncidents(all, time.Now())
	for i := range incidents {
		incidents[i].Contained = h.incidentContained(incidents[i])
	}
	return c.JSON(fiber.Map{"items": incidents, "count": len(incidents)})
}

func (h *Handlers) GetIncident(c *fiber.Ctx) error {
	all, err := h.svc.List(alerts.Filter{Limit: 500})
	if err != nil {
		return fiberErr(c, http.StatusInternalServerError, err)
	}
	inc, ok := analysis.IncidentByID(all, c.Params("id"), time.Now())
	if !ok {
		return fiberErr(c, http.StatusNotFound, fmt.Errorf("incident not found"))
	}
	inc.Contained = h.incidentContained(inc)
	return c.JSON(inc)
}

func (h *Handlers) incidentContained(inc *analysis.Incident) bool {
	if inc.SrcIP == "" {
		return false
	}
	for _, ctr := range h.ctr.List(inc.SrcIP) {
		if ctr.Status == containment.StatusActive {
			return true
		}
	}
	return false
}

func (h *Handlers) IncidentAssign(c *fiber.Ctx) error {
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
	inc, err := h.incidentFrom(c.Params("id"))
	if err != nil {
		return fiberErr(c, http.StatusNotFound, err)
	}
	for _, id := range inc.AlertIDs {
		if _, err := h.svc.Assign(id, body.Assignee, body.Actor); err != nil {
			h.log.Warn().Err(err).Str("alert", id).Msg("incident assign skipped")
		}
	}
	inc, _ = analysis.IncidentByID(h.allAlerts(), inc.ID, time.Now())
	inc.Contained = h.incidentContained(inc)
	return c.JSON(inc)
}

func (h *Handlers) IncidentContain(c *fiber.Ctx) error {
	var body struct {
		Type        string `json:"type"`
		Direction   string `json:"direction"`
		Duration    string `json:"duration"`
		Enforcement string `json:"enforcement"`
		Note        string `json:"note"`
		Actor       string `json:"actor"`
	}
	if err := json.Unmarshal(c.Body(), &body); err != nil {
		return fiberErr(c, http.StatusBadRequest, err)
	}
	if body.Actor == "" {
		body.Actor = "console"
	}
	if body.Duration == "" {
		body.Duration = "24h"
	}

	inc, err := h.incidentFrom(c.Params("id"))
	if err != nil {
		return fiberErr(c, http.StatusNotFound, err)
	}

	action := actionForControl(containment.Type(body.Type))
	seen := map[string]bool{}
	for _, id := range inc.AlertIDs {
		a, err := h.svc.Get(id)
		if err != nil {
			continue
		}
		if a.SrcIP != "" && !seen[a.SrcIP] {
			seen[a.SrcIP] = true
			ctr, err := h.ctr.Deploy(containment.Type(body.Type), a.SrcIP, body.Direction,
				body.Duration, body.Enforcement, body.Note, inc.AlertIDs)
			if err != nil {
				h.log.Warn().Err(err).Str("ip", a.SrcIP).Msg("containment deploy skipped")
				continue
			}
			h.edge.Install(edgePolicyFor(ctr))
		}
		if _, err := h.svc.Action(id, action, body.Note, body.Actor); err != nil {
			h.log.Warn().Err(err).Str("alert", id).Msg("incident contain action skipped")
		}
	}

	inc, _ = analysis.IncidentByID(h.allAlerts(), inc.ID, time.Now())
	inc.Contained = h.incidentContained(inc)
	return c.JSON(inc)
}

func actionForControl(t containment.Type) alerts.ActionType {
	switch t {
	case containment.TypeBlockIP:
		return alerts.ActionBlockIP
	case containment.TypeRateLimit, containment.TypeWAFRule:
		return alerts.ActionMitigate
	default:
		return alerts.ActionMitigate
	}
}

func (h *Handlers) incidentFrom(id string) (*analysis.Incident, error) {
	all := h.allAlerts()
	inc, ok := analysis.IncidentByID(all, id, time.Now())
	if !ok {
		return nil, fmt.Errorf("incident not found")
	}
	return inc, nil
}

func (h *Handlers) allAlerts() []*alerts.Alert {
	all, err := h.svc.List(alerts.Filter{Limit: 500})
	if err != nil {
		return nil
	}
	return all
}

func (h *Handlers) ListContainment(c *fiber.Ctx) error {
	items := h.ctr.List(c.Query("target_ip"))
	return c.JSON(fiber.Map{"items": items, "count": len(items)})
}

func (h *Handlers) DeployContainment(c *fiber.Ctx) error {
	var body struct {
		Type        containment.Type `json:"type"`
		TargetIP    string           `json:"target_ip"`
		Direction   string           `json:"direction"`
		Duration    string           `json:"duration"`
		Enforcement string           `json:"enforcement"`
		Note        string           `json:"note"`
		AlertIDs    []string         `json:"alert_ids"`
	}
	if err := json.Unmarshal(c.Body(), &body); err != nil {
		return fiberErr(c, http.StatusBadRequest, err)
	}
	if body.Direction == "" {
		body.Direction = "Inbound"
	}
	if body.Duration == "" {
		body.Duration = "24h"
	}
	ctr, err := h.ctr.Deploy(body.Type, body.TargetIP, body.Direction, body.Duration,
		body.Enforcement, body.Note, body.AlertIDs)
	if err != nil {
		return fiberErr(c, http.StatusBadRequest, err)
	}
	h.edge.Install(edgePolicyFor(ctr))
	for _, id := range body.AlertIDs {
		if _, err := h.svc.Action(id, actionForControl(ctr.Type), body.Note, "console"); err != nil {
			h.log.Warn().Err(err).Str("alert", id).Msg("containment action skipped")
		}
	}
	return c.JSON(ctr)
}

func (h *Handlers) RevokeContainment(c *fiber.Ctx) error {
	ctr, err := h.ctr.Revoke(c.Params("id"))
	if err != nil {
		return fiberErr(c, http.StatusBadRequest, err)
	}
	h.edge.Remove(ctr.ID)
	return c.JSON(ctr)
}

func edgePolicyFor(c *containment.Containment) edge.Policy {
	p := edge.Policy{
		SourceID:    c.ID,
		TargetIP:    c.TargetIP,
		Enforcement: c.Enforcement,
		ExpiresAt:   c.ExpiresAt,
	}
	switch c.Type {
	case containment.TypeBlockIP:
		p.Kind = edge.KindDeny
	case containment.TypeRateLimit:
		p.Kind = edge.KindRateLimit
	case containment.TypeWAFRule:
		p.Kind = edge.KindWAF
	default:
		p.Kind = edge.KindDeny
	}
	return p
}
