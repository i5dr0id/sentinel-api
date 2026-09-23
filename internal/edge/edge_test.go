package edge

import (
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/i5dr0id/sentinel-api/internal/event"
)

func testEngine() *Engine {
	log := zerolog.Nop()
	return NewEngine(&log)
}

func ev(ip string, tags ...string) *event.NormalizedEvent {
	return &event.NormalizedEvent{ID: "e", SrcIP: ip, Method: "GET", Path: "/", Status: 200, Tags: tags}
}

func TestDenyBlocksSource(t *testing.T) {
	e := testEngine()
	exp := time.Now().Add(time.Hour)
	e.Install(Policy{SourceID: "c1", Kind: KindDeny, TargetIP: "32.122.195.63", ExpiresAt: &exp})

	blocked := ev("32.122.195.63")
	if !e.Eval(blocked) {
		t.Fatal("denied source should be contained")
	}
	if blocked.Status != 403 {
		t.Errorf("status = %d, want 403", blocked.Status)
	}
	if !blocked.HasTag("contained:deny") {
		t.Error("expected contained:deny tag")
	}
	pass := ev("8.8.8.8")
	if e.Eval(pass) {
		t.Error("unrelated source should pass")
	}
	if e.Blocked() != 1 {
		t.Errorf("blocked = %d, want 1", e.Blocked())
	}
}

func TestExpiredPolicyIsInert(t *testing.T) {
	e := testEngine()
	exp := time.Now().Add(-time.Second)
	e.Install(Policy{SourceID: "c1", Kind: KindDeny, TargetIP: "1.1.1.1", ExpiresAt: &exp})
	if e.Eval(ev("1.1.1.1")) {
		t.Error("expired deny policy should not block")
	}
}

func TestRateLimitThrottles(t *testing.T) {
	e := testEngine()
	e.Install(Policy{SourceID: "c2", Kind: KindRateLimit, TargetIP: "9.9.9.9", RatePerSec: 1, Burst: 2})

	allowed := 0
	for i := 0; i < 5; i++ {
		if !e.Eval(ev("9.9.9.9")) {
			allowed++
		}
	}
	if allowed != 2 {
		t.Errorf("burst window allowed %d, want 2", allowed)
	}

	if e.Eval(ev("1.2.3.4")) {
		t.Error("unrelated source should pass rate limit")
	}
}

func TestWAFRulesetBlocksAttackTraffic(t *testing.T) {
	e := testEngine()
	e.Install(Policy{SourceID: wafSourceID, Kind: KindWAF})

	if !e.Eval(ev("5.5.5.5", event.TagSQLi)) {
		t.Error("sqli traffic should be blocked under managed ruleset")
	}
	if e.Eval(ev("5.5.5.5")) {
		t.Error("benign traffic should pass under managed ruleset")
	}
}

func TestRevokeUninstalls(t *testing.T) {
	e := testEngine()
	exp := time.Now().Add(time.Hour)
	e.Install(Policy{SourceID: "c1", Kind: KindDeny, TargetIP: "1.1.1.1", ExpiresAt: &exp})
	e.Remove("c1")
	if e.Eval(ev("1.1.1.1")) {
		t.Error("removed policy should not block")
	}
	if len(e.ActivePolicies()) != 0 {
		t.Error("expected no active policies after revoke")
	}
}

func TestBlockedByReason(t *testing.T) {
	e := testEngine()
	exp := time.Now().Add(time.Hour)
	e.Install(Policy{SourceID: "c1", Kind: KindDeny, TargetIP: "1.1.1.1", ExpiresAt: &exp})
	e.Eval(ev("1.1.1.1"))
	got := e.BlockedByReason()
	if got["deny"] != 1 {
		t.Errorf("deny = %d, want 1", got["deny"])
	}
}
