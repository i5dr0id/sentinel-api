package alerts

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/i5dr0id/sentinel-api/internal/detect"
	"github.com/i5dr0id/sentinel-api/internal/event"
)

type testStore struct {
	mu   sync.Mutex
	byID map[string]*Alert
}

func newTestStore() *testStore { return &testStore{byID: map[string]*Alert{}} }

func (t *testStore) Create(a *Alert) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.byID[a.ID] = a
	return nil
}
func (t *testStore) Get(id string) (*Alert, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	a, ok := t.byID[id]
	if !ok {
		return nil, ErrNotFound
	}
	return a, nil
}
func (t *testStore) Update(a *Alert) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.byID[a.ID]; !ok {
		return ErrNotFound
	}
	t.byID[a.ID] = a
	return nil
}
func (t *testStore) List(f Filter) ([]*Alert, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := []*Alert{}
	for _, a := range t.byID {
		out = append(out, a)
	}
	return out, nil
}
func (t *testStore) FindOpen(ruleID, ruleKey string) (*Alert, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, a := range t.byID {
		if a.RuleID == ruleID && a.RuleKey == ruleKey && a.Status.IsActive() {
			return a, nil
		}
	}
	return nil, ErrNotFound
}
func (t *testStore) Counts() (Counts, error) { return Counts{}, nil }
func (t *testStore) MTTR() (time.Duration, int, error) {
	var total time.Duration
	var n int
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, a := range t.byID {
		if d, ok := a.TTRespond(); ok {
			total += d
			n++
		}
	}
	if n == 0 {
		return 0, 0, nil
	}
	return total / time.Duration(n), n, nil
}

var _ Store = (*testStore)(nil)
var _ = errors.Is

func TestLifecycle(t *testing.T) {
	s := NewService(newTestStore(), nil)
	s.now = func() time.Time { return time.Date(2026, 8, 14, 10, 0, 0, 0, time.UTC) }

	rule := detect.Rules()[0]
	evs := []*event.NormalizedEvent{
		{ID: "e1", Timestamp: time.Now(), Source: event.SourceGateway, Asset: "api-gw-01", SrcIP: "1.2.3.4", Path: "/admin", Status: 403},
		{ID: "e2", Timestamp: time.Now(), Source: event.SourceGateway, Asset: "api-gw-01", SrcIP: "1.2.3.4", Path: "/manage", Status: 404},
	}
	s.Ingest(rule, evs, detect.Outcome{Count: 2, UniquePaths: 2})

	alerts, _ := s.List(Filter{Limit: 10})
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	a := alerts[0]
	if a.Status != StatusOpen || !a.IsUnassigned() {
		t.Fatalf("expected open/unassigned, got %s/%q", a.Status, a.Assignee)
	}
	if a.MITRE[0] != "T1595.001" {
		t.Errorf("unexpected mitre mapping: %v", a.MITRE)
	}

	s.Ingest(rule, evs, detect.Outcome{Count: 2, UniquePaths: 2})
	alerts, _ = s.List(Filter{Limit: 10})
	if len(alerts) != 1 {
		t.Fatalf("expected merge (1 alert), got %d", len(alerts))
	}

	a, err := s.Assign(a.ID, "@j.smith", "console")
	if err != nil {
		t.Fatal(err)
	}
	if a.Status != StatusAssigned || a.Assignee != "@j.smith" {
		t.Errorf("expected ASSIGNED @j.smith, got %s %q", a.Status, a.Assignee)
	}

	if _, err := s.SetStatus(a.ID, StatusInProgress, "console"); err != nil {
		t.Fatal(err)
	}

	a, err = s.Action(a.ID, ActionRespond, "blocked source IP at edge", "console")
	if err != nil {
		t.Fatal(err)
	}
	if a.RespondedAt == nil {
		t.Error("expected responded_at set")
	}

	a, err = s.Action(a.ID, ActionMitigate, "rule deployed", "console")
	if err != nil {
		t.Fatal(err)
	}
	if a.Status != StatusResolved || a.ResolvedAt == nil {
		t.Errorf("expected RESOLVED, got %s", a.Status)
	}

	if _, err := s.SetStatus(a.ID, StatusOpen, "console"); err != ErrBadTransition {
		t.Errorf("expected ErrBadTransition, got %v", err)
	}

	mttr, n, _ := s.MTTR()
	if n != 1 {
		t.Errorf("expected 1 sample, got %d", n)
	}
	_ = mttr
}

func TestMTTRAverage(t *testing.T) {
	s := NewService(newTestStore(), nil)
	base := time.Date(2026, 8, 14, 10, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return base }

	rule := detect.Rules()[0]
	evs := []*event.NormalizedEvent{{ID: "e1", Timestamp: base, Source: event.SourceGateway, Asset: "a", SrcIP: "1.1.1.1", Path: "/x", Status: 404}}
	s.Ingest(rule, evs, detect.Outcome{Count: 1, UniquePaths: 1})
	a, _ := s.List(Filter{Limit: 1})
	if len(a) != 1 {
		t.Fatal("expected alert")
	}
	s.now = func() time.Time { return base.Add(5 * time.Minute) }
	if _, err := s.Action(a[0].ID, ActionRespond, "", "console"); err != nil {
		t.Fatal(err)
	}
	mttr, n, _ := s.MTTR()
	if n != 1 {
		t.Fatalf("expected 1 sample, got %d", n)
	}
	if mttr.Minutes() != 5 {
		t.Errorf("expected MTTR 5m, got %v", mttr)
	}
}
