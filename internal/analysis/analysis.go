package analysis

import (
	"crypto/sha1"
	"encoding/hex"
	"sort"
	"time"

	"github.com/i5dr0id/sentinel-api/internal/alerts"
	"github.com/i5dr0id/sentinel-api/internal/event"
)

type Phase string

const (
	PhaseRecon            Phase = "reconnaissance"
	PhaseInitialAccess    Phase = "initial_access"
	PhaseExecution        Phase = "execution"
	PhasePersistence      Phase = "persistence"
	PhaseDefenseEvasion   Phase = "defense_evasion"
	PhaseCredentialAccess Phase = "credential_access"
	PhaseDiscovery        Phase = "discovery"
	PhaseLateralMovement  Phase = "lateral_movement"
	PhaseCollection       Phase = "collection"
	PhaseC2               Phase = "command_and_control"
	PhaseExfiltration     Phase = "exfiltration"
	PhaseImpact           Phase = "impact"
)

var PhaseOrder = []Phase{
	PhaseRecon,
	PhaseInitialAccess,
	PhaseExecution,
	PhasePersistence,
	PhaseDefenseEvasion,
	PhaseCredentialAccess,
	PhaseDiscovery,
	PhaseLateralMovement,
	PhaseCollection,
	PhaseC2,
	PhaseExfiltration,
	PhaseImpact,
}

var phaseLabels = map[Phase]string{
	PhaseRecon:            "Reconnaissance",
	PhaseInitialAccess:    "Initial access",
	PhaseExecution:        "Execution",
	PhasePersistence:      "Persistence",
	PhaseDefenseEvasion:   "Defense evasion",
	PhaseCredentialAccess: "Credential access",
	PhaseDiscovery:        "Discovery",
	PhaseLateralMovement:  "Lateral movement",
	PhaseCollection:       "Collection",
	PhaseC2:               "Command & control",
	PhaseExfiltration:     "Exfiltration",
	PhaseImpact:           "Impact",
}

func (p Phase) Label() string {
	if l, ok := phaseLabels[p]; ok {
		return l
	}
	return string(p)
}

func PhaseForTechnique(technique string) Phase {
	switch technique {
	case "T1595.001", "T1595", "T1083", "T1046", "T1595.002", "T1057":
		return PhaseRecon
	case "T1190", "T1133", "T1566", "T1189", "T1200":
		return PhaseInitialAccess
	case "T1059", "T1203", "T1106":
		return PhaseExecution
	case "T1505.003", "T1505", "T1543", "T1574":
		return PhasePersistence
	case "T1078.004", "T1078", "T1562", "T1027":
		return PhaseDefenseEvasion
	case "T1110", "T1111", "T1558", "T1003":
		return PhaseCredentialAccess
	case "T1087", "T1016", "T1018", "T1033", "T1082":
		return PhaseDiscovery
	case "T1021", "T1563", "T1570":
		return PhaseLateralMovement
	case "T1005", "T1213", "T1560":
		return PhaseCollection
	case "T1071", "T1105", "T1573":
		return PhaseC2
	case "T1041", "T1567", "T1020":
		return PhaseExfiltration
	case "T1486", "T1489", "T1490":
		return PhaseImpact
	default:
		return PhaseInitialAccess
	}
}

type ChainPhase struct {
	Phase        Phase           `json:"phase"`
	Label        string          `json:"label"`
	Covered      bool            `json:"covered"`
	Alerts       []*alerts.Alert `json:"alerts"`
	Count        int             `json:"count"`
	BlockedCount int             `json:"blocked_count"`
	Severity     event.Severity  `json:"severity"`
	FirstSeen    time.Time       `json:"first_seen"`
	LastSeen     time.Time       `json:"last_seen"`
}

type Chain struct {
	SrcIP        string         `json:"src_ip,omitempty"`
	Asset        string         `json:"asset,omitempty"`
	TotalAlerts  int            `json:"total_alerts"`
	MaxSeverity  event.Severity `json:"max_severity"`
	ReachedPhase Phase          `json:"reached_phase"`
	StartedAt    time.Time      `json:"started_at"`
	LastSeenAt   time.Time      `json:"last_seen_at"`
	Phases       []ChainPhase   `json:"phases"`
}

func BuildChain(alertList []*alerts.Alert) *Chain {
	byPhase := map[Phase][]*alerts.Alert{}
	for _, a := range alertList {
		p := PhaseForTechnique(a.RuleID)
		byPhase[p] = append(byPhase[p], a)
	}

	chain := &Chain{Phases: []ChainPhase{}}
	for _, p := range PhaseOrder {
		group := byPhase[p]
		if len(group) == 0 {
			continue
		}
		cp := ChainPhase{Phase: p, Label: p.Label(), Covered: true, Count: len(group)}
		for _, a := range group {
			cp.Alerts = append(cp.Alerts, a)
			cp.BlockedCount += a.BlockedCount
			if sevRank(a.Severity) > sevRank(cp.Severity) {
				cp.Severity = a.Severity
			}
			if cp.FirstSeen.IsZero() || a.StartedAt.Before(cp.FirstSeen) {
				cp.FirstSeen = a.StartedAt
			}
			if a.LastSeenAt.After(cp.LastSeen) {
				cp.LastSeen = a.LastSeenAt
			}
		}
		chain.Phases = append(chain.Phases, cp)
		chain.TotalAlerts += len(group)
	}
	if len(chain.Phases) > 0 {
		chain.ReachedPhase = chain.Phases[len(chain.Phases)-1].Phase
		chain.MaxSeverity = maxSeverity(chain.Phases)
		chain.StartedAt = chain.Phases[0].FirstSeen
		chain.LastSeenAt = chain.Phases[len(chain.Phases)-1].LastSeen
	}
	if len(alertList) > 0 {
		chain.SrcIP = alertList[0].SrcIP
		chain.Asset = alertList[0].Asset
	}
	return chain
}

func maxSeverity(phases []ChainPhase) event.Severity {
	var s event.Severity
	for _, p := range phases {
		if sevRank(p.Severity) > sevRank(s) {
			s = p.Severity
		}
	}
	return s
}

func sevRank(s event.Severity) int {
	switch s {
	case event.SeverityCritical:
		return 4
	case event.SeverityHigh:
		return 3
	case event.SeverityMedium:
		return 2
	case event.SeverityLow:
		return 1
	default:
		return 0
	}
}

type IOC struct {
	Type       string   `json:"type"`
	Value      string   `json:"value"`
	Count      int      `json:"count"`
	Confidence float64  `json:"confidence"`
	Tags       []string `json:"tags,omitempty"`
}

func ExtractIOCs(a *alerts.Alert, evs []*event.NormalizedEvent) []IOC {
	out := []IOC{}
	if a.SrcIP != "" {
		out = append(out, IOC{Type: "ipv4", Value: a.SrcIP, Count: a.Count, Confidence: a.Confidence, Tags: []string{"source"}})
	}
	uaCounts := map[string]int{}
	pathCounts := map[string]int{}
	asnSet := map[string]struct{}{}
	for _, e := range evs {
		if e.UserAgent != "" {
			uaCounts[e.UserAgent]++
		}
		if e.Path != "" {
			pathCounts[e.Path]++
		}
		if e.Geo != nil && e.Geo.ASN != "" {
			asnSet["AS"+e.Geo.ASN] = struct{}{}
		}
	}
	if a.Geo != nil && a.Geo.ASN != "" {
		asnSet["AS"+a.Geo.ASN] = struct{}{}
	}
	for ua, n := range uaCounts {
		out = append(out, IOC{Type: "user_agent", Value: ua, Count: n, Confidence: toolConfidence(ua)})
	}
	for p, n := range pathCounts {
		out = append(out, IOC{Type: "path", Value: p, Count: n, Confidence: 0.6, Tags: []string{"targeted"}})
	}
	for asn := range asnSet {
		out = append(out, IOC{Type: "asn", Value: asn, Count: 1, Confidence: 0.8, Tags: []string{"infrastructure"}})
	}
	sortIOCs(out)
	return out
}

func toolConfidence(ua string) float64 {
	switch {
	case containsFold(ua, "dirbuster"), containsFold(ua, "gobuster"), containsFold(ua, "nikto"),
		containsFold(ua, "sqlmap"), containsFold(ua, "zgrab"), containsFold(ua, "nmap"):
		return 0.95
	default:
		return 0.7
	}
}

func containsFold(s, sub string) bool {
	return len(s) >= len(sub) && contains(sub, s)
}

func contains(s, sub string) bool {
	return len(sub) > 0 && indexFold(s, sub) >= 0
}

func indexFold(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if eqFold(s[i:i+len(sub)], sub) {
			return i
		}
	}
	return -1
}

func eqFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

func sortIOCs(out []IOC) {
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return typeRank(out[i].Type) < typeRank(out[j].Type)
		}
		return out[i].Count > out[j].Count
	})
}

func typeRank(t string) int {
	switch t {
	case "ipv4":
		return 0
	case "user_agent":
		return 1
	case "asn":
		return 2
	default:
		return 3
	}
}

const (
	TTRTarget = 15 * time.Minute
	TTMTarget = 2 * time.Hour
)

type SLAMetrics struct {
	TTRTarget   string    `json:"ttr_target"`
	TTMTarget   string    `json:"ttm_target"`
	TTRDeadline time.Time `json:"ttr_deadline"`
	TTMDeadline time.Time `json:"ttm_deadline"`
	TTRAssigned bool      `json:"ttr_assigned"`
	TTMBreached bool      `json:"ttm_breached"`
	TTRBreached bool      `json:"ttr_breached"`
	Contained   bool      `json:"contained"`
}

type Incident struct {
	ID         string         `json:"id"`
	SrcIP      string         `json:"src_ip,omitempty"`
	Asset      string         `json:"asset,omitempty"`
	Severity   event.Severity `json:"severity"`
	Status     alerts.Status  `json:"status"`
	AlertIDs   []string       `json:"alert_ids"`
	Count      int            `json:"count"`
	Assets     []string       `json:"assets"`
	Techniques []string       `json:"techniques"`
	Chain      *Chain         `json:"chain"`
	FirstSeen  time.Time      `json:"first_seen"`
	LastSeen   time.Time      `json:"last_seen"`
	SLA        SLAMetrics     `json:"sla"`
	Contained  bool           `json:"contained"`
}

func GroupIncidents(alertList []*alerts.Alert, now time.Time) []*Incident {
	groups := map[string][]*alerts.Alert{}
	var order []string
	for _, a := range alertList {
		key := incidentKey(a)
		if _, ok := groups[key]; !ok {
			order = append(order, key)
		}
		groups[key] = append(groups[key], a)
	}

	out := make([]*Incident, 0, len(order))
	for _, key := range order {
		group := groups[key]
		if !hasActive(group) {
			continue
		}
		inc := buildIncident(group, now)
		out = append(out, inc)
	}
	sort.Slice(out, func(i, j int) bool {
		if sevRank(out[i].Severity) != sevRank(out[j].Severity) {
			return sevRank(out[i].Severity) > sevRank(out[j].Severity)
		}
		return out[i].LastSeen.After(out[j].LastSeen)
	})
	return out
}

func IncidentByID(alertList []*alerts.Alert, id string, now time.Time) (*Incident, bool) {
	for _, inc := range GroupIncidents(alertList, now) {
		if inc.ID == id {
			return inc, true
		}
	}
	return nil, false
}

func incidentKey(a *alerts.Alert) string {
	if a.SrcIP != "" {
		return "ip:" + a.SrcIP
	}
	return "asset:" + a.Asset
}

func hasActive(group []*alerts.Alert) bool {
	for _, a := range group {
		if a.Status.IsActive() {
			return true
		}
	}
	return false
}

func buildIncident(group []*alerts.Alert, now time.Time) *Incident {
	inc := &Incident{
		ID:         IncidentID(incidentKey(group[0])),
		AlertIDs:   []string{},
		Assets:     []string{},
		Techniques: []string{},
	}
	techSet := map[string]struct{}{}
	assetSet := map[string]struct{}{}
	for _, a := range group {
		inc.AlertIDs = append(inc.AlertIDs, a.ID)
		if sevRank(a.Severity) > sevRank(inc.Severity) {
			inc.Severity = a.Severity
		}
		if inc.SrcIP == "" && a.SrcIP != "" {
			inc.SrcIP = a.SrcIP
		}
		if inc.Asset == "" && a.Asset != "" {
			inc.Asset = a.Asset
		}
		assetSet[a.Asset] = struct{}{}
		techSet[a.RuleID] = struct{}{}
		if inc.FirstSeen.IsZero() || a.StartedAt.Before(inc.FirstSeen) {
			inc.FirstSeen = a.StartedAt
		}
		if a.LastSeenAt.After(inc.LastSeen) {
			inc.LastSeen = a.LastSeenAt
		}
		if inc.Status != alerts.StatusResolved && a.Status != alerts.StatusResolved {
			switch a.Status {
			case alerts.StatusInProgress:
				inc.Status = alerts.StatusInProgress
			case alerts.StatusAssigned:
				if inc.Status != alerts.StatusInProgress {
					inc.Status = alerts.StatusAssigned
				}
			default:
				if inc.Status == "" {
					inc.Status = alerts.StatusOpen
				}
			}
		}
	}
	for a := range assetSet {
		inc.Assets = append(inc.Assets, a)
	}
	for t := range techSet {
		inc.Techniques = append(inc.Techniques, t)
	}
	inc.Count = len(group)
	inc.Chain = BuildChain(group)

	inc.SLA = SLAMetrics{
		TTRTarget:   TTRTarget.String(),
		TTMTarget:   TTMTarget.String(),
		TTRDeadline: inc.FirstSeen.Add(TTRTarget),
		TTMDeadline: inc.FirstSeen.Add(TTMTarget),
	}
	for _, a := range group {
		if a.Status == alerts.StatusAssigned || a.Status == alerts.StatusInProgress || a.Status == alerts.StatusResolved {
			inc.SLA.TTRAssigned = true
		}
		if a.ResolvedAt != nil {
			inc.SLA.Contained = true
		}
	}
	if !inc.SLA.TTRAssigned && now.After(inc.SLA.TTRDeadline) {
		inc.SLA.TTRBreached = true
	}
	if !inc.SLA.Contained && now.After(inc.SLA.TTMDeadline) {
		inc.SLA.TTMBreached = true
	}
	return inc
}

func IncidentID(key string) string {
	sum := sha1.Sum([]byte(key))
	return "INC-" + hex.EncodeToString(sum[:])[:6]
}
