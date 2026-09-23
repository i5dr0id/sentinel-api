package containment

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

type Type string

const (
	TypeBlockIP   Type = "block_ip"
	TypeRateLimit Type = "rate_limit"
	TypeWAFRule   Type = "waf_rule"
)

type Status string

const (
	StatusActive  Status = "ACTIVE"
	StatusRevoked Status = "REVOKED"
	StatusExpired Status = "EXPIRED"
)

type Containment struct {
	ID          string     `json:"id"`
	Type        Type       `json:"type"`
	TargetIP    string     `json:"target_ip"`
	Direction   string     `json:"direction"`
	Duration    string     `json:"duration"`
	Enforcement string     `json:"enforcement"`
	Status      Status     `json:"status"`
	AlertIDs    []string   `json:"alert_ids"`
	Note        string     `json:"note,omitempty"`
	DeployedAt  time.Time  `json:"deployed_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
}

var (
	ErrNotFound    = errors.New("containment not found")
	ErrInvalidType = errors.New("invalid containment type")
	ErrInvalidIP   = errors.New("target IP is required")
	ErrInvalidDur  = errors.New("invalid duration")
	ErrNotActive   = errors.New("containment is not active")
)

type Service struct {
	log   *zerolog.Logger
	mu    sync.RWMutex
	items map[string]*Containment
}

func NewService(log *zerolog.Logger) *Service {
	return &Service{log: log, items: map[string]*Containment{}}
}

func (s *Service) Deploy(t Type, targetIP, direction, duration, enforcement, note string, alertIDs []string) (*Containment, error) {
	switch t {
	case TypeBlockIP, TypeRateLimit, TypeWAFRule:
	default:
		return nil, ErrInvalidType
	}
	if targetIP == "" {
		return nil, ErrInvalidIP
	}
	d, permanent, err := ParseDuration(duration)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	c := &Containment{
		ID:          newID(),
		Type:        t,
		TargetIP:    targetIP,
		Direction:   direction,
		Duration:    duration,
		Enforcement: enforcement,
		Status:      StatusActive,
		AlertIDs:    append([]string{}, alertIDs...),
		Note:        note,
		DeployedAt:  now,
	}
	if !permanent {
		exp := now.Add(d)
		c.ExpiresAt = &exp
	}

	s.mu.Lock()
	s.items[c.ID] = c
	s.mu.Unlock()

	s.log.Info().Str("id", c.ID).Str("type", string(t)).
		Str("target", targetIP).Str("status", string(c.Status)).Msg("containment deployed")
	return c, nil
}

func (s *Service) Get(id string) (*Containment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.items[id]
	if !ok {
		return nil, ErrNotFound
	}
	s.resolve(c)
	return c, nil
}

func (s *Service) List(targetIP string) []*Containment {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Containment, 0, len(s.items))
	for _, c := range s.items {
		if targetIP != "" && c.TargetIP != targetIP {
			continue
		}
		s.resolve(c)
		out = append(out, c)
	}
	sortByDeployedDesc(out)
	return out
}

func (s *Service) Revoke(id string) (*Containment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.items[id]
	if !ok {
		return nil, ErrNotFound
	}
	if c.Status != StatusActive {
		return nil, ErrNotActive
	}
	now := time.Now()
	c.Status = StatusRevoked
	c.RevokedAt = &now
	s.log.Info().Str("id", id).Str("target", c.TargetIP).Msg("containment revoked")
	return c, nil
}

func (s *Service) resolve(c *Containment) {
	if c.Status == StatusActive && c.ExpiresAt != nil && time.Now().After(*c.ExpiresAt) {
		c.Status = StatusExpired
	}
}

func ParseDuration(raw string) (time.Duration, bool, error) {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" || s == "permanent" || s == "0" {
		return 0, true, nil
	}
	if strings.HasSuffix(s, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil {
			return 0, false, ErrInvalidDur
		}
		return time.Duration(n) * 24 * time.Hour, false, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, false, ErrInvalidDur
	}
	return d, false, nil
}

func sortByDeployedDesc(items []*Containment) {
	for i := 1; i < len(items); i++ {
		for j := i; j > 0 && items[j].DeployedAt.After(items[j-1].DeployedAt); j-- {
			items[j], items[j-1] = items[j-1], items[j]
		}
	}
}

func newID() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "CTR-" + strconv.FormatInt(time.Now().UnixNano(), 16)[:12]
	}
	return "CTR-" + hex.EncodeToString(b)
}
