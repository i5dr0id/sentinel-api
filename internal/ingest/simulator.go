package ingest

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/rs/zerolog"

	"github.com/i5dr0id/sentinel-api/internal/config"
	"github.com/i5dr0id/sentinel-api/internal/event"
)

type Simulator struct {
	cfg    config.SimConfig
	assets []string
	out    chan<- event.RawLog
	log    *zerolog.Logger
	rnd    *rand.Rand

	stop chan struct{}
}

func NewSimulator(cfg config.SimConfig, assets []string, out chan<- event.RawLog, log *zerolog.Logger) *Simulator {
	return &Simulator{cfg: cfg, assets: assets, out: out, log: log, rnd: rand.New(rand.NewSource(time.Now().UnixNano()))}
}

func (s *Simulator) Start() {
	s.stop = make(chan struct{})
	go s.seed()
	go s.loop()
}

func (s *Simulator) Stop() {
	if s.stop != nil {
		close(s.stop)
	}
}

func (s *Simulator) emit(raw event.RawLog) {
	select {
	case s.out <- raw:
	case <-s.stop:
	}
}

func (s *Simulator) pause() {
	time.Sleep(time.Duration(s.rnd.Int63n(80)+15) * time.Millisecond)
}

func (s *Simulator) seed() {
	if !s.cfg.Enabled {
		return
	}
	s.log.Info().Msg("simulator: seeding traffic history")

	attacker := "32.122.195.63"
	paths := []string{"/administrator", "/manage", "/wp-admin", "/admin", "/backup", "/backup.zip",
		"/phpmyadmin", "/wp-login.php", "/config.php", "/.git/HEAD", "/server-status", "/login",
		"/admin/login", "/api/admin", "/uploads", "/.env", "/private", "/internal", "/logs",
		"/console", "/shell.php", "/xmlrpc.php", "/wp-json", "/api/config", "/jenkins"}

	for i := 0; i < 31; i++ {
		status := 404
		size := 302
		if i%10 == 0 {
			status = 403
			size = 512
		}
		if i == 27 {
			status = 200
			size = 118
		}
		s.emit(event.RawLog{
			Source: event.SourceGateway, Asset: "api-gw-01",
			Fields: map[string]any{
				"ip": attacker, "method": "GET", "path": paths[i%len(paths)],
				"status": status, "user_agent": "Mozilla/5.0 (compatible; DirBuster/1.0)",
				"size": size, "tags": []string{event.TagScan},
			},
		})
		s.pause()
	}

	scanIP := "203.0.113.5"
	for i := 0; i < 24; i++ {
		s.emit(event.RawLog{
			Source: event.SourceGateway, Asset: s.assets[i%len(s.assets)],
			Fields: map[string]any{
				"ip": scanIP, "method": "GET", "path": "/", "status": 404,
				"port": 8080 + i, "user_agent": "Mozilla/5.0 zgrab/0.4",
				"tags": []string{event.TagScan},
			},
		})
		s.pause()
	}

	for _, payload := range sqliPayloads {
		s.emit(event.RawLog{
			Source: event.SourceGateway, Asset: "api-gw-01",
			Fields: map[string]any{
				"ip": "198.51.100.45", "method": "GET",
				"path": "/api/v1/payments?ref=" + payload, "status": 200,
				"user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
				"tags":       []string{event.TagSQLi},
			},
		})
		s.pause()
	}

	wafIP := "185.220.101.30"
	for i := 0; i < 12; i++ {
		s.emit(event.RawLog{
			Source: event.SourceCloudflare, Asset: "www-01",
			Fields: map[string]any{
				"ip": wafIP, "method": "GET", "path": "/wp-login.php?action=register", "status": 403,
				"user_agent": "Mozilla/5.0 (compatible; Nikto/2.5)", "tags": []string{event.TagWAFBlock},
			},
		})
		s.pause()
	}

	for i := 0; i < 14; i++ {
		s.emit(event.RawLog{
			Source: event.SourceSSH, Asset: "auth-svc-01",
			Fields: map[string]any{
				"ip": "45.55.2.9", "user": rootOrAdmin(i), "port": 5222,
				"message": "Failed password for " + rootOrAdmin(i) + " from 45.55.2.9 port 5222 ssh2",
				"tags":    []string{event.TagAuthFailure},
			},
		})
		s.pause()
	}

	s.emit(event.RawLog{
		Source: event.SourceGateway, Asset: "www-01",
		Fields: map[string]any{
			"ip": "104.223.8.19", "method": "POST", "path": "/wp-content/uploads/shell.php",
			"status": 403, "user_agent": "Mozilla/5.0 (compatible; curl)",
			"tags": []string{event.TagWebshell},
		},
	})
	s.pause()

	for i := 0; i < 9; i++ {
		s.emit(event.RawLog{
			Source: event.SourceApp, Asset: "Internal-DB-01",
			Fields: map[string]any{
				"message": fmt.Sprintf("slow query took %dms: SELECT * FROM payments WHERE amount > 0", 9000+i*500),
				"status":  200, "tags": []string{event.TagDbQuery},
			},
		})
		s.pause()
	}

	for i := 0; i < 60; i++ {
		s.emit(s.legitRequest())
		s.pause()
	}
	s.log.Info().Msg("simulator: seed complete, entering live mode")
}

func (s *Simulator) loop() {
	if !s.cfg.Enabled {
		return
	}
	interval := time.Duration(float64(time.Second) / maxFloat(s.cfg.Rate, 1))
	if interval < time.Millisecond {
		interval = time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	burstCountdown := 0
	for {
		select {
		case <-s.stop:
			return
		case <-ticker.C:

			attack := s.rnd.Float64() < 0.16
			if burstCountdown > 0 {
				s.attackEvent()
				burstCountdown--
			} else if attack {

				for i := 0; i < 3+s.rnd.Intn(6); i++ {
					s.attackEvent()
				}
				if s.rnd.Float64() < 0.35 {
					burstCountdown = 4 + s.rnd.Intn(10)
				}
			} else {
				s.emit(s.legitRequest())
			}
		}
	}
}

var attackerPool = []string{
	"32.122.195.63", "203.0.113.5", "198.51.100.45", "185.220.101.30",
	"104.223.8.19", "45.55.2.9", "89.187.164.7", "91.108.4.12",
}

func (s *Simulator) attackEvent() {
	switch s.rnd.Intn(8) {
	case 0, 1:
		status := 404
		if s.rnd.Intn(3) == 0 {
			status = 403
		}
		s.emit(event.RawLog{
			Source: event.SourceGateway, Asset: rndPick(s.rnd, s.assets),
			Fields: map[string]any{
				"ip": attackerPool[0], "method": "GET", "path": rndPick(s.rnd, enumPaths),
				"status": status, "user_agent": "Mozilla/5.0 (compatible; GoBuster/3.5)",
				"tags": []string{event.TagScan},
			},
		})
	case 2:
		s.emit(event.RawLog{
			Source: event.SourceGateway, Asset: rndPick(s.rnd, s.assets),
			Fields: map[string]any{
				"ip": "198.51.100.45", "method": "GET", "path": "/api/v1/payments?ref=" + rndPick(s.rnd, sqliPayloads),
				"status": 200, "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
				"tags": []string{event.TagSQLi},
			},
		})
	case 3:
		s.emit(event.RawLog{
			Source: event.SourceCloudflare, Asset: rndPick(s.rnd, s.assets),
			Fields: map[string]any{
				"ip": "185.220.101.30", "method": "GET", "path": rndPick(s.rnd, enumPaths), "status": 403,
				"user_agent": "Mozilla/5.0 (compatible; Nikto/2.5)", "tags": []string{event.TagWAFBlock},
			},
		})
	case 4:
		u := rootOrAdmin(s.rnd.Intn(8))
		s.emit(event.RawLog{
			Source: event.SourceSSH, Asset: "auth-svc-01",
			Fields: map[string]any{
				"ip": "45.55.2.9", "user": u, "port": 5200 + s.rnd.Intn(80),
				"message": "Failed password for " + u + " from 45.55.2.9 port ssh2",
				"tags":    []string{event.TagAuthFailure},
			},
		})
	case 5:
		s.emit(event.RawLog{
			Source: event.SourceGateway, Asset: "www-01",
			Fields: map[string]any{
				"ip": "104.223.8.19", "method": "POST",
				"path":   rndPick(s.rnd, []string{"/wp-content/uploads/shell.php", "/uploads/x.php", "/cgi-bin/cmd.sh", "/images/logo.jsp"}),
				"status": 403, "user_agent": "Mozilla/5.0 (compatible; curl)",
				"tags": []string{event.TagWebshell},
			},
		})
	case 6:
		s.emit(event.RawLog{
			Source: event.SourceApp, Asset: "Internal-DB-01",
			Fields: map[string]any{
				"message": fmt.Sprintf("slow query took %dms: SELECT ... FROM payments", 8000+s.rnd.Intn(9000)),
				"status":  s.rnd.Intn(2), "tags": []string{event.TagDbQuery},
			},
		})
	default:
		s.emit(event.RawLog{
			Source: event.SourceGateway, Asset: rndPick(s.rnd, s.assets),
			Fields: map[string]any{
				"ip": "203.0.113.5", "method": "GET", "path": "/", "status": 404,
				"port": 8000 + s.rnd.Intn(1024), "user_agent": "Mozilla/5.0 zgrab/0.4",
				"tags": []string{event.TagScan},
			},
		})
	}
}

var enumPaths = []string{
	"/administrator", "/manage", "/wp-admin", "/admin", "/backup", "/backup.zip",
	"/phpmyadmin", "/wp-login.php", "/config.php", "/.git/HEAD", "/server-status",
	"/login", "/admin/login", "/api/admin", "/uploads", "/.env", "/private",
	"/internal", "/logs", "/console", "/shell.php", "/xmlrpc.php", "/wp-json",
}

var sqliPayloads = []string{
	"1' OR '1'='1", "' UNION SELECT username,password FROM users--", "1 AND SLEEP(5)",
	"' OR 1=1--", "%27%20OR%20%271%27%3D%271", "1; SELECT pg_sleep(5)--",
	"' UNION ALL SELECT 1,2,3--", "1' AND 'x'='x",
}

func rootOrAdmin(i int) string {
	if i%3 == 0 {
		return "root"
	}
	if i%3 == 1 {
		return "admin"
	}
	return "deploy"
}

var legitIPs = []string{
	"41.60.12.7", "105.112.33.9", "197.210.44.8", "154.120.7.2", "102.88.10.4",
	"212.9.180.5", "162.159.36.10", "197.242.99.12", "102.140.0.4", "154.113.78.5",
	"81.199.15.2", "212.8.240.10",
}

var legitPaths = []string{
	"/", "/dashboard", "/api/v1/payments", "/api/v1/wallets", "/api/v1/auth/login",
	"/api/v1/transactions", "/api/v1/beneficiaries", "/api/v2/payouts", "/api/v2/collections",
	"/api/v1/rates", "/health", "/api/v1/cards", "/api/v1/settings", "/static/app.js", "/favicon.ico",
}

var legitUAs = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64) Firefox/126.0",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) Mobile Safari/604.1",
	"okhttp/4.12.0", "PostmanRuntime/7.37.0", "Stripe/1.0 (+https://stripe.com/docs/webhooks)",
	"Mozilla/5.0 (Linux; Android 14) Mobile Chrome/125.0",
}

func (s *Simulator) legitRequest() event.RawLog {
	method := "GET"
	if s.rnd.Float64() < 0.25 {
		method = "POST"
	}
	status := 200
	r := s.rnd.Float64()
	if r > 0.94 {
		status = 400
	} else if r > 0.9 {
		status = 404
	} else if r > 0.88 {
		status = 503
	}
	return event.RawLog{
		Source: rndPick(s.rnd, []event.Source{event.SourceGateway, event.SourceGateway, event.SourceNginx, event.SourceCloudflare}),
		Asset:  rndPick(s.rnd, s.assets),
		Fields: map[string]any{
			"ip": rndPick(s.rnd, legitIPs), "method": method, "path": rndPick(s.rnd, legitPaths),
			"status": status, "user_agent": rndPick(s.rnd, legitUAs),
		},
	}
}

func rndPick[T any](r *rand.Rand, items []T) T {
	return items[r.Intn(len(items))]
}

func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
