package containment

import (
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func testSvc() *Service {
	log := zerolog.Nop()
	return NewService(&log)
}

func TestDeployActiveAndList(t *testing.T) {
	s := testSvc()
	c, err := s.Deploy(TypeBlockIP, "32.122.195.63", "Inbound", "24h", "Edge firewall (api-gw-01)", "block", []string{"ALT-1"})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if c.Status != StatusActive {
		t.Errorf("status = %s, want ACTIVE", c.Status)
	}
	if c.ExpiresAt == nil || !c.ExpiresAt.After(time.Now()) {
		t.Error("expected future expiry")
	}
	items := s.List("")
	if len(items) != 1 || items[0].ID != c.ID {
		t.Fatalf("list = %+v, want 1 item", items)
	}
	if got := s.List("1.1.1.1"); len(got) != 0 {
		t.Error("filter by target ip failed")
	}
}

func TestPermanentDuration(t *testing.T) {
	s := testSvc()
	c, err := s.Deploy(TypeRateLimit, "8.8.8.8", "Inbound", "permanent", "edge", "", nil)
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if c.ExpiresAt != nil {
		t.Error("permanent control should not expire")
	}
}

func TestRevokeLifecycle(t *testing.T) {
	s := testSvc()
	c, _ := s.Deploy(TypeWAFRule, "1.2.3.4", "Inbound", "24h", "edge", "", nil)
	revoked, err := s.Revoke(c.ID)
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if revoked.Status != StatusRevoked || revoked.RevokedAt == nil {
		t.Error("revoke did not update lifecycle")
	}
	if _, err := s.Revoke(c.ID); err != ErrNotActive {
		t.Errorf("second revoke err = %v, want ErrNotActive", err)
	}
}

func TestValidation(t *testing.T) {
	s := testSvc()
	if _, err := s.Deploy("bogus", "1.2.3.4", "Inbound", "24h", "", "", nil); err != ErrInvalidType {
		t.Errorf("bad type err = %v, want ErrInvalidType", err)
	}
	if _, err := s.Deploy(TypeBlockIP, "", "Inbound", "24h", "", "", nil); err != ErrInvalidIP {
		t.Errorf("empty ip err = %v, want ErrInvalidIP", err)
	}
	if _, err := s.Deploy(TypeBlockIP, "1.2.3.4", "Inbound", "nope", "", "", nil); err != ErrInvalidDur {
		t.Errorf("bad duration err = %v, want ErrInvalidDur", err)
	}
}

func TestParseDuration(t *testing.T) {
	if d, perm, err := ParseDuration("7d"); err != nil || perm || d != 7*24*time.Hour {
		t.Errorf("7d = %v %v %v", d, perm, err)
	}
	if _, perm, err := ParseDuration("permanent"); err != nil || !perm {
		t.Errorf("permanent = %v %v", perm, err)
	}
}
