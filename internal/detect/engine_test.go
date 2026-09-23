package detect

import (
	"testing"
	"time"

	"github.com/i5dr0id/sentinel-api/internal/event"
)

func mkEvent(src event.Source, ip, asset, path string, status int) *event.NormalizedEvent {
	return &event.NormalizedEvent{
		ID: "evt", Timestamp: time.Now(), Source: src, Asset: asset, SrcIP: ip,
		Path: path, Status: status, UserAgent: "Mozilla/5.0 (compatible; DirBuster/1.0)",
	}
}

func TestDirEnumFires(t *testing.T) {
	e := NewEngine(nil)
	fired := false
	paths := []string{"/administrator", "/manage", "/wp-admin", "/login", "/backup",
		"/phpmyadmin", "/.git/HEAD", "/console", "/admin", "/.env", "/private", "/internal"}
	for _, p := range paths {
		e.Process(mkEvent(event.SourceGateway, "32.122.195.63", "api-gw-01", p, 404), func(r *Rule, _ []*event.NormalizedEvent, o Outcome) {
			if r.ID == "dir-enum" {
				fired = true
				if o.UniquePaths < 8 {
					t.Errorf("expected >=8 unique paths, got %d", o.UniquePaths)
				}
			}
		})
	}
	if !fired {
		t.Fatal("dir-enum rule did not fire")
	}
}

func TestDirEnumDoesNotFireOnLegit(t *testing.T) {
	e := NewEngine(nil)
	fired := false
	paths := []string{"/", "/dashboard", "/api/v1/payments", "/api/v1/wallets", "/api/v1/rates", "/health"}
	for _, p := range paths {
		e.Process(mkEvent(event.SourceGateway, "41.60.12.7", "api-gw-01", p, 200), func(r *Rule, _ []*event.NormalizedEvent, o Outcome) {
			if r.ID == "dir-enum" {
				fired = true
			}
		})
	}
	if fired {
		t.Fatal("dir-enum rule fired on legitimate traffic")
	}
}

func TestSQLiFires(t *testing.T) {
	e := NewEngine(nil)
	fired := false
	payloads := []string{"1' OR 1=1--", "' UNION SELECT username,password FROM users--", "1 AND SLEEP(5)"}
	for _, p := range payloads {
		ev := mkEvent(event.SourceGateway, "198.51.100.45", "api-gw-01", "/api/v1/payments?ref="+p, 200)
		ev.Tags = []string{event.TagSQLi}
		e.Process(ev, func(r *Rule, _ []*event.NormalizedEvent, o Outcome) {
			if r.ID == "sqli" {
				fired = true
			}
		})
	}
	if !fired {
		t.Fatal("sqli rule did not fire")
	}
}

func TestWindowPrunes(t *testing.T) {
	e := NewEngine(nil)
	var fires int
	emit := func(r *Rule, _ []*event.NormalizedEvent, _ Outcome) {
		if r.ID == "waf-block-spike" {
			fires++
		}
	}
	base := time.Now()

	for i := 0; i < 12; i++ {
		ev := mkEvent(event.SourceCloudflare, "185.220.101.30", "www-01", "/wp-login.php", 403)
		ev.Timestamp = base.Add(-70 * time.Second)
		ev.Tags = []string{event.TagWAFBlock}
		e.Process(ev, emit)
	}

	fires = 0
	fresh := mkEvent(event.SourceCloudflare, "185.220.101.30", "www-01", "/wp-login.php", 403)
	fresh.Tags = []string{event.TagWAFBlock}
	e.Process(fresh, emit)
	if fires != 0 {
		t.Fatalf("expected stale window to prune (0 fires), got %d", fires)
	}
}
