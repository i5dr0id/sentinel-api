package ingest

import (
	"testing"
	"time"

	"github.com/i5dr0id/sentinel-api/internal/enrich"
	"github.com/i5dr0id/sentinel-api/internal/event"
)

func newNorm() *Normalizer { return NewNormalizer(enrich.Default(nil)) }

func TestNormalizeNginxRequestLine(t *testing.T) {
	n := newNorm()
	ev := n.Normalize(event.RawLog{
		Source: event.SourceGateway, Asset: "api-gw-01",
		Fields: map[string]any{
			"ip": "32.122.195.63", "request": "GET /administrator HTTP/1.1",
			"status": 404, "user_agent": "DirBuster/1.0",
		},
	}, time.Now())
	if ev.Method != "GET" || ev.Path != "/administrator" || ev.Proto != "HTTP/1.1" {
		t.Errorf("parseRequestLine failed: %+v", ev)
	}
	if ev.Status != 404 {
		t.Errorf("expected 404, got %d", ev.Status)
	}
	if ev.Geo == nil || ev.Geo.ASN != "14061" {
		t.Errorf("expected DigitalOcean ASN enrichment, got %+v", ev.Geo)
	}
	if ev.Geo.CountryCode != "NL" {
		t.Errorf("expected NL geo, got %s", ev.Geo.CountryCode)
	}
}

func TestNormalizePrivateIPNoGeo(t *testing.T) {
	n := newNorm()
	ev := n.Normalize(event.RawLog{
		Source: event.SourceSSH, Asset: "bastion",
		Fields: map[string]any{"ip": "10.0.0.5", "message": "Failed password for root", "tags": []string{event.TagAuthFailure}},
	}, time.Now())
	if ev.Geo != nil {
		t.Errorf("private IP must not be geolocated, got %+v", ev.Geo)
	}
	if !ev.HasTag(event.TagAuthFailure) {
		t.Error("tags not normalized")
	}
}

func TestParseNginxCombinedLine(t *testing.T) {
	line := `192.168.1.1 - - [14/Aug/2026:10:00:00 +0000] "POST /api/v1/payments HTTP/1.1" 401 32 "https://example.com" "Mozilla/5.0 (compatible; GoBuster/3.5)"`
	f, ok := parseNginxCombined(line)
	if !ok {
		t.Fatal("line not parsed")
	}
	if f["ip"] != "192.168.1.1" || f["status"] != "401" {
		t.Errorf("bad parse: %+v", f)
	}
	if f["method"] != "POST" || f["path"] != "/api/v1/payments" {
		t.Errorf("bad request parse: %+v", f)
	}
}

func TestParseSSHLine(t *testing.T) {
	line := `Aug 14 23:18:01 bastion sshd[1234]: Failed password for root from 45.55.2.9 port 5222 ssh2`
	f, ok := parseSSHLine(line)
	if !ok {
		t.Fatal("ssh line not parsed")
	}
	if f["ip"] != "45.55.2.9" || f["user"] != "root" {
		t.Errorf("bad ssh parse: %+v", f)
	}
}
