package store

import (
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/i5dr0id/sentinel-api/internal/alerts"
	"github.com/i5dr0id/sentinel-api/internal/event"
)

type MemoryStore struct {
	mu      sync.RWMutex
	byID    map[string]*alerts.Alert
	created []*alerts.Alert
}

func NewMemory() *MemoryStore {
	return &MemoryStore{byID: map[string]*alerts.Alert{}}
}

func (m *MemoryStore) Create(a *alerts.Alert) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.byID[a.ID]; ok {
		return errors.New("duplicate alert id")
	}
	m.byID[a.ID] = a
	m.created = append(m.created, a)
	return nil
}

func (m *MemoryStore) Get(id string) (*alerts.Alert, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	a, ok := m.byID[id]
	if !ok {
		return nil, alerts.ErrNotFound
	}
	return a, nil
}

func (m *MemoryStore) Update(a *alerts.Alert) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.byID[a.ID]; !ok {
		return alerts.ErrNotFound
	}
	m.byID[a.ID] = a
	return nil
}

func (m *MemoryStore) List(f alerts.Filter) ([]*alerts.Alert, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := []*alerts.Alert{}
	for _, a := range m.created {
		if f.Status != "" && a.Status != f.Status {
			continue
		}
		if f.Severity != "" && a.Severity != f.Severity {
			continue
		}
		if f.Asset != "" && a.Asset != f.Asset {
			continue
		}
		if f.Assignee != "" && a.Assignee != f.Assignee {
			continue
		}
		if f.RuleID != "" && a.RuleID != f.RuleID {
			continue
		}
		if f.Query != "" {
			q := strings.ToLower(f.Query)
			hay := strings.ToLower(a.Title + " " + a.SrcIP + " " + a.Asset + " " + strings.Join(a.MITRE, " "))
			if !strings.Contains(hay, q) {
				continue
			}
		}
		out = append(out, a)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Status.IsActive() != out[j].Status.IsActive() {
			return out[i].Status.IsActive()
		}
		if out[i].Severity.Rank() != out[j].Severity.Rank() {
			return out[i].Severity.Rank() > out[j].Severity.Rank()
		}
		return out[i].LastSeenAt.After(out[j].LastSeenAt)
	})
	if f.Offset > len(out) {
		f.Offset = len(out)
	}
	out = out[f.Offset:]
	if f.Limit > 0 && len(out) > f.Limit {
		out = out[:f.Limit]
	}
	return out, nil
}

func (m *MemoryStore) FindOpen(ruleID, ruleKey string) (*alerts.Alert, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, a := range m.created {
		if a.RuleID == ruleID && a.RuleKey == ruleKey && a.Status.IsActive() {
			return a, nil
		}
	}
	return nil, alerts.ErrNotFound
}

func (m *MemoryStore) Counts() (alerts.Counts, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c := alerts.Counts{
		BySeverity: map[event.Severity]int{
			event.SeverityCritical: 0, event.SeverityHigh: 0,
			event.SeverityMedium: 0, event.SeverityLow: 0,
		},
	}
	for _, a := range m.created {
		c.BySeverity[a.Severity]++
		switch a.Severity {
		case event.SeverityCritical:
			c.Critical++
		case event.SeverityHigh:
			c.High++
		case event.SeverityMedium:
			c.Medium++
		case event.SeverityLow:
			c.Low++
		}
		if a.Status.IsActive() {
			c.TotalActive++
		} else {
			c.Resolved++
		}
		switch a.Status {
		case alerts.StatusOpen:
			c.Open++
		case alerts.StatusAssigned:
			c.Assigned++
		case alerts.StatusInProgress:
			c.InProgress++
		}
		if a.IsUnassigned() {
			c.Unassigned++
		}
	}
	return c, nil
}

func (m *MemoryStore) MTTR() (time.Duration, int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var total time.Duration
	var n int
	for _, a := range m.created {
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
