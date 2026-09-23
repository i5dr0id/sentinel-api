package analysis

import (
	"testing"
	"time"

	"github.com/i5dr0id/sentinel-api/internal/alerts"
	"github.com/i5dr0id/sentinel-api/internal/event"
)

func alert(id, ip, rule string, sev event.Severity, start, last time.Time) *alerts.Alert {
	return &alerts.Alert{
		ID:         id,
		SrcIP:      ip,
		Asset:      "api-gw-01",
		RuleID:     rule,
		Severity:   sev,
		Count:      10,
		Status:     alerts.StatusOpen,
		StartedAt:  start,
		LastSeenAt: last,
	}
}

func TestPhaseForTechnique(t *testing.T) {
	cases := map[string]Phase{
		"T1595.001": PhaseRecon,
		"T1083":     PhaseRecon,
		"T1046":     PhaseRecon,
		"T1190":     PhaseInitialAccess,
		"T1505.003": PhasePersistence,
		"T1110":     PhaseCredentialAccess,
	}
	for tech, want := range cases {
		if got := PhaseForTechnique(tech); got != want {
			t.Errorf("PhaseForTechnique(%s) = %s, want %s", tech, got, want)
		}
	}
}

func TestBuildChainOrdersPhases(t *testing.T) {
	now := time.Now()
	recon := alert("a1", "1.2.3.4", "T1046", event.SeverityMedium, now, now.Add(time.Second))
	access := alert("a2", "1.2.3.4", "T1190", event.SeverityCritical, now.Add(time.Minute), now.Add(90*time.Second))
	persist := alert("a3", "1.2.3.4", "T1505.003", event.SeverityHigh, now.Add(2*time.Minute), now.Add(150*time.Second))

	chain := BuildChain([]*alerts.Alert{persist, access, recon})
	if len(chain.Phases) != 3 {
		t.Fatalf("expected 3 phases, got %d", len(chain.Phases))
	}
	if chain.Phases[0].Phase != PhaseRecon || chain.Phases[1].Phase != PhaseInitialAccess || chain.Phases[2].Phase != PhasePersistence {
		t.Errorf("chain not in kill-chain order: %v", chain.Phases)
	}
	if chain.MaxSeverity != event.SeverityCritical {
		t.Errorf("MaxSeverity = %s, want CRITICAL", chain.MaxSeverity)
	}
	if chain.TotalAlerts != 3 {
		t.Errorf("TotalAlerts = %d, want 3", chain.TotalAlerts)
	}
	if chain.ReachedPhase != PhasePersistence {
		t.Errorf("ReachedPhase = %s, want persistence", chain.ReachedPhase)
	}
}

func TestGroupIncidentsRollsUpBySource(t *testing.T) {
	now := time.Now()
	recon := alert("a1", "9.9.9.9", "T1046", event.SeverityMedium, now.Add(-10*time.Minute), now.Add(-5*time.Minute))
	access := alert("a2", "9.9.9.9", "T1190", event.SeverityHigh, now.Add(-4*time.Minute), now.Add(-time.Minute))
	other := alert("a3", "7.7.7.7", "T1110", event.SeverityCritical, now.Add(-2*time.Minute), now)

	incs := GroupIncidents([]*alerts.Alert{other, access, recon}, now)
	if len(incs) != 2 {
		t.Fatalf("expected 2 incidents, got %d", len(incs))
	}
	byIP := map[string]*Incident{}
	for _, inc := range incs {
		byIP[inc.SrcIP] = inc
	}
	main := byIP["9.9.9.9"]
	if main == nil {
		t.Fatal("missing incident for 9.9.9.9")
	}
	if main.Count != 2 || len(main.AlertIDs) != 2 {
		t.Errorf("incident count = %d, want 2", main.Count)
	}
	if main.Severity != event.SeverityHigh {
		t.Errorf("severity = %s, want HIGH", main.Severity)
	}

	if main.SLA.TTRBreached {
		t.Error("TTR breached too early")
	}
	if len(main.Chain.Phases) != 2 {
		t.Errorf("chain phases = %d, want 2", len(main.Chain.Phases))
	}
}

func TestGroupIncidentsSkipsResolvedOnly(t *testing.T) {
	now := time.Now()
	done := alert("a1", "5.5.5.5", "T1190", event.SeverityHigh, now.Add(-time.Hour), now.Add(-30*time.Minute))
	done.Status = alerts.StatusResolved
	if incs := GroupIncidents([]*alerts.Alert{done}, now); len(incs) != 0 {
		t.Errorf("resolved-only group should be excluded, got %d incidents", len(incs))
	}
}
