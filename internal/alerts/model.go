package alerts

import (
	"time"

	"github.com/i5dr0id/sentinel-api/internal/event"
)

type Status string

const (
	StatusOpen       Status = "OPEN"
	StatusAssigned   Status = "ASSIGNED"
	StatusInProgress Status = "IN_PROGRESS"
	StatusResolved   Status = "RESOLVED"
)

func (s Status) IsActive() bool { return s != StatusResolved }

type ActionType string

const (
	ActionAssign      ActionType = "assign"
	ActionUnassign    ActionType = "unassign"
	ActionStart       ActionType = "start"
	ActionAcknowledge ActionType = "acknowledge"
	ActionRespond     ActionType = "respond"
	ActionInvestigate ActionType = "investigate"
	ActionBlockIP     ActionType = "block_ip"
	ActionWhitelist   ActionType = "whitelist"
	ActionResolve     ActionType = "resolve"
	ActionMitigate    ActionType = "mitigate"
	ActionFalsePos    ActionType = "false_positive"
	ActionComment     ActionType = "comment"
)

type Resolution string

const (
	ResolutionMitigated     Resolution = "mitigated"
	ResolutionFalsePositive Resolution = "false_positive"
	ResolutionBenign        Resolution = "benign"
	ResolutionNoAction      Resolution = "no_action"
)

type ActionLog struct {
	At        time.Time  `json:"at"`
	Actor     string     `json:"actor"`
	Action    ActionType `json:"action"`
	Note      string     `json:"note,omitempty"`
	FromState string     `json:"from_state,omitempty"`
	ToState   string     `json:"to_state,omitempty"`
}

type Alert struct {
	ID              string         `json:"id"`
	RuleID          string         `json:"rule_id"`
	RuleKey         string         `json:"rule_key"`
	Title           string         `json:"title"`
	Severity        event.Severity `json:"severity"`
	Status          Status         `json:"status"`
	Confidence      float64        `json:"confidence"`
	MITRE           []string       `json:"mitre"`
	Description     string         `json:"description"`
	Asset           string         `json:"asset"`
	SrcIP           string         `json:"src_ip"`
	Geo             *event.Geo     `json:"geo,omitempty"`
	Count           int            `json:"count"`
	BlockedCount    int            `json:"blocked_count"`
	UniquePaths     int            `json:"unique_paths"`
	DistinctAssets  int            `json:"distinct_assets"`
	EventIDs        []string       `json:"event_ids"`
	StartedAt       time.Time      `json:"started_at"`
	LastSeenAt      time.Time      `json:"last_seen_at"`
	Assignee        string         `json:"assignee,omitempty"`
	AssignedAt      *time.Time     `json:"assigned_at,omitempty"`
	StatusChangedAt *time.Time     `json:"status_changed_at,omitempty"`
	RespondedAt     *time.Time     `json:"responded_at,omitempty"`
	ResolvedAt      *time.Time     `json:"resolved_at,omitempty"`
	Resolution      Resolution     `json:"resolution,omitempty"`
	Actions         []ActionLog    `json:"actions"`
	Extra           map[string]any `json:"extra,omitempty"`
	CreatedAt       time.Time      `json:"created_at"`
}

func (a *Alert) IsUnassigned() bool { return a.Status == StatusOpen && a.Assignee == "" }

func (a *Alert) TTRespond() (time.Duration, bool) {
	if a.RespondedAt == nil && a.ResolvedAt == nil {
		return 0, false
	}
	end := a.RespondedAt
	if end == nil {
		end = a.ResolvedAt
	}
	return end.Sub(a.CreatedAt), true
}

type Counts struct {
	TotalActive int                    `json:"total_active"`
	Open        int                    `json:"open"`
	Assigned    int                    `json:"assigned"`
	InProgress  int                    `json:"in_progress"`
	Resolved    int                    `json:"resolved"`
	Unassigned  int                    `json:"unassigned"`
	BySeverity  map[event.Severity]int `json:"by_severity"`
	Critical    int                    `json:"critical"`
	High        int                    `json:"high"`
	Medium      int                    `json:"medium"`
	Low         int                    `json:"low"`
}

type Filter struct {
	Status   Status
	Severity event.Severity
	Asset    string
	Assignee string
	RuleID   string
	Query    string
	Limit    int
	Offset   int
}
