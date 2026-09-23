package alerts

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/i5dr0id/sentinel-api/internal/detect"
	"github.com/i5dr0id/sentinel-api/internal/event"
)

type Store interface {
	Create(*Alert) error
	Get(id string) (*Alert, error)
	Update(*Alert) error
	List(Filter) ([]*Alert, error)
	FindOpen(ruleID, ruleKey string) (*Alert, error)
	Counts() (Counts, error)
	MTTR() (time.Duration, int, error)
}

var (
	ErrNotFound      = errors.New("alert not found")
	ErrBadTransition = errors.New("invalid status transition")
	ErrUnknownAction = errors.New("unknown action")
)

type Service struct {
	store Store
	log   *zerolog.Logger
	mu    sync.Mutex
	now   func() time.Time
}

func NewService(store Store, log *zerolog.Logger) *Service {
	return &Service{store: store, log: log, now: time.Now}
}

func (s *Service) Emitter() detect.Emitter {
	return func(r *detect.Rule, evs []*event.NormalizedEvent, o detect.Outcome) {
		s.Ingest(r, evs, o)
	}
}

func (s *Service) Ingest(r *detect.Rule, evs []*event.NormalizedEvent, o detect.Outcome) {
	s.mu.Lock()
	defer s.mu.Unlock()

	first := evs[0]
	last := evs[len(evs)-1]

	existing, err := s.store.FindOpen(r.ID, r.Key(first))
	if err != nil && !errors.Is(err, ErrNotFound) {
		s.log.Error().Err(err).Str("rule", r.ID).Msg("find open alert")
	}

	eventIDs := make([]string, 0, len(evs))
	for _, e := range evs {
		eventIDs = append(eventIDs, e.ID)
	}

	if existing != nil {
		existing.Merge(r, first, last, evs, o, eventIDs)
		if err := s.store.Update(existing); err != nil {
			s.log.Error().Err(err).Str("alert", existing.ID).Msg("update alert")
		}
		return
	}

	alert := &Alert{
		ID:          newID(),
		RuleID:      r.ID,
		RuleKey:     r.Key(first),
		Title:       r.Name,
		Severity:    r.Severity,
		Status:      StatusOpen,
		Confidence:  r.Confidence,
		MITRE:       r.MITRE,
		Description: r.Description,
		Asset:       first.Asset,
		SrcIP:       first.SrcIP,
		Geo:         first.Geo,
		EventIDs:    eventIDs,
		StartedAt:   first.Timestamp,
		LastSeenAt:  last.Timestamp,
		CreatedAt:   s.now(),
	}
	alert.ApplyOutcome(o)
	if err := s.store.Create(alert); err != nil {
		s.log.Error().Err(err).Str("rule", r.ID).Msg("create alert")
	}
}

func (a *Alert) Merge(r *detect.Rule, first, last *event.NormalizedEvent, evs []*event.NormalizedEvent, o detect.Outcome, eventIDs []string) {
	a.LastSeenAt = last.Timestamp
	a.Severity = maxSeverity(a.Severity, r.Severity)
	a.Confidence = minFloat(0.99, a.Confidence+0.02)
	a.Asset = first.Asset
	a.SrcIP = first.SrcIP
	if first.Geo != nil && !first.Geo.IsZero() {
		a.Geo = first.Geo
	}
	merged := append(a.EventIDs, eventIDs...)
	if len(merged) > 200 {
		merged = merged[len(merged)-200:]
	}
	a.EventIDs = merged
	a.ApplyOutcome(o)
}

func (a *Alert) ApplyOutcome(o detect.Outcome) {
	a.Count = o.Count
	if o.Blocked > a.BlockedCount {
		a.BlockedCount = o.Blocked
	}
	if o.UniquePaths > a.UniquePaths {
		a.UniquePaths = o.UniquePaths
	}
	if o.DistinctAssets > a.DistinctAssets {
		a.DistinctAssets = o.DistinctAssets
	}
}

func (s *Service) Assign(id, assignee, actor string) (*Alert, error) {
	if assignee == "" {
		return nil, errors.New("assignee required")
	}
	a, err := s.store.Get(id)
	if err != nil {
		return nil, err
	}
	if a.Status == StatusResolved {
		return nil, ErrBadTransition
	}
	from := string(a.Status)
	a.Assignee = assignee
	t := s.now()
	a.AssignedAt = &t
	if a.Status == StatusOpen {
		a.Status = StatusAssigned
	}
	a.appendAction(actor, ActionAssign, from, string(a.Status), "assigned to "+assignee)
	if err := s.store.Update(a); err != nil {
		return nil, err
	}
	return a, nil
}

func (s *Service) SetStatus(id string, status Status, actor string) (*Alert, error) {
	a, err := s.store.Get(id)
	if err != nil {
		return nil, err
	}
	if a.Status == StatusResolved {
		return nil, ErrBadTransition
	}
	switch status {
	case StatusAssigned:
		if a.Assignee == "" {
			return nil, errors.New("assignee required before ASSIGNED")
		}
	case StatusInProgress, StatusOpen:
	default:
		return nil, ErrBadTransition
	}
	from := string(a.Status)
	a.Status = status
	t := s.now()
	a.StatusChangedAt = &t
	a.appendAction(actor, ActionStart, from, string(status), "")
	if err := s.store.Update(a); err != nil {
		return nil, err
	}
	return a, nil
}

func (s *Service) Action(id string, action ActionType, note, actor string) (*Alert, error) {
	a, err := s.store.Get(id)
	if err != nil {
		return nil, err
	}
	now := s.now()
	from := string(a.Status)

	switch action {
	case ActionInvestigate, ActionAcknowledge, ActionRespond:
		if a.RespondedAt == nil {
			a.RespondedAt = &now
		}
	case ActionBlockIP, ActionWhitelist:
		if a.RespondedAt == nil {
			a.RespondedAt = &now
		}
		if a.Extra == nil {
			a.Extra = map[string]any{}
		}
		a.Extra["ip_action"] = string(action)
		a.Extra["ip_action_at"] = now.Format(time.RFC3339)
	case ActionMitigate, ActionResolve:
		a.Status = StatusResolved
		a.Resolution = ResolutionMitigated
		t := now
		a.ResolvedAt = &t
		a.RespondedAt = firstOr(a.RespondedAt, &t)
	case ActionFalsePos:
		a.Status = StatusResolved
		a.Resolution = ResolutionFalsePositive
		t := now
		a.ResolvedAt = &t
		a.RespondedAt = firstOr(a.RespondedAt, &t)
	case ActionComment:

	default:
		return nil, ErrUnknownAction
	}
	a.StatusChangedAt = &now
	a.appendAction(actor, action, from, string(a.Status), note)
	if err := s.store.Update(a); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *Alert) appendAction(actor string, action ActionType, from, to, note string) {
	a.Actions = append(a.Actions, ActionLog{
		At: time.Now(), Actor: actor, Action: action,
		FromState: from, ToState: to, Note: note,
	})
}

func (s *Service) Get(id string) (*Alert, error) { return s.store.Get(id) }

func (s *Service) List(f Filter) ([]*Alert, error) {
	if f.Limit <= 0 {
		f.Limit = 50
	}
	return s.store.List(f)
}

func (s *Service) Counts() (Counts, error) { return s.store.Counts() }

func (s *Service) MTTR() (time.Duration, int, error) { return s.store.MTTR() }

func (s *Service) RelatedEvents(id string, recent []*event.NormalizedEvent, max int) []*event.NormalizedEvent {
	a, err := s.store.Get(id)
	if err != nil {
		return nil
	}
	want := map[string]struct{}{}
	for _, eid := range a.EventIDs {
		want[eid] = struct{}{}
	}
	out := []*event.NormalizedEvent{}
	for i := len(recent) - 1; i >= 0 && len(out) < max; i-- {
		if _, ok := want[recent[i].ID]; ok {
			out = append(out, recent[i])
		}
	}

	if len(out) == 0 {
		for i := len(recent) - 1; i >= 0 && len(out) < max; i-- {
			e := recent[i]
			if (a.SrcIP != "" && e.SrcIP == a.SrcIP) || (a.Asset != "" && e.Asset == a.Asset) {
				out = append(out, e)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Timestamp.Before(out[j].Timestamp) })
	return out
}

func (s *Service) SeedDemo() error {
	now := s.now()
	type seed struct {
		rule, title, severity, srcIP, asset, assignee, resolution string
		mitre                                                     []string
		conf                                                      float64
		createdMin, resolvedMin                                   float64
		status                                                    Status
	}
	seeds := []seed{
		{"port-scan", "Sequential Port Scan", "HIGH", "203.0.113.5", "api-gw-01", "", "no_action", []string{"T1046"}, 0.87, 27, 12, StatusResolved},
		{"sqli", "SQLi Pattern", "CRITICAL", "198.51.100.45", "api-gw-01", "@s.johnson", "mitigated", []string{"T1190"}, 0.91, 18, 8, StatusResolved},
		{"auth-brute", "Credential Brute Force", "HIGH", "45.55.2.9", "auth-svc-01", "", "mitigated", []string{"T1110"}, 0.9, 38, 20, StatusResolved},
		{"waf-block-spike", "WAF Block Spike", "MEDIUM", "185.220.101.30", "www-01", "@j.smith", "false_positive", []string{"T1190"}, 0.85, 18, 5, StatusResolved},
	}
	for _, sp := range seeds {
		created := now.Add(-time.Duration(sp.createdMin) * time.Minute)
		resolved := now.Add(-time.Duration(sp.resolvedMin) * time.Minute)
		a := &Alert{
			ID: newID(), RuleID: sp.rule, RuleKey: sp.srcIP + "|" + sp.asset,
			Title: sp.title, Severity: event.Severity(sp.severity), Status: StatusResolved,
			Confidence: sp.conf, MITRE: sp.mitre, Asset: sp.asset, SrcIP: sp.srcIP,
			Count: 20, UniquePaths: 12, StartedAt: created, LastSeenAt: created,
			Assignee: sp.assignee, Resolution: Resolution(sp.resolution),
			CreatedAt: created, RespondedAt: &resolved, ResolvedAt: &resolved,
			Actions: []ActionLog{{At: resolved, Actor: "system", Action: ActionMitigate, FromState: string(StatusOpen), ToState: string(StatusResolved)}},
		}
		if err := s.store.Create(a); err != nil {
			return err
		}
	}
	return nil
}

func newID() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "ALT-" + time.Now().Format("150405.000")
	}
	return "ALT-" + hex.EncodeToString(b)
}

func maxSeverity(a, b event.Severity) event.Severity {
	if a.Rank() >= b.Rank() {
		return a
	}
	return b
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func firstOr(p, fallback *time.Time) *time.Time {
	if p != nil {
		return p
	}
	return fallback
}
