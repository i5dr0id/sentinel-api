package detect

import (
	"strings"
	"time"

	"github.com/i5dr0id/sentinel-api/internal/event"
)

type Outcome struct {
	Count          int
	Blocked        int
	UniquePaths    int
	DistinctAssets int
	Message        string
}

type Rule struct {
	ID          string
	Name        string
	Severity    event.Severity
	MITRE       []string
	Confidence  float64
	Description string
	Window      time.Duration

	threshold int
	keyFn     func(*event.NormalizedEvent) string
	matchFn   func(*event.NormalizedEvent) bool
	alertFn   func([]*event.NormalizedEvent) (Outcome, bool)
}

func (r *Rule) Key(ev *event.NormalizedEvent) string {
	if r.keyFn == nil {
		return ""
	}
	return r.keyFn(ev)
}

func (r *Rule) Match(ev *event.NormalizedEvent) bool {
	return r.matchFn(ev)
}

func (r *Rule) ShouldAlert(evs []*event.NormalizedEvent) (Outcome, bool) {
	if len(evs) < r.threshold {
		return Outcome{}, false
	}
	return r.alertFn(evs)
}

func Rules() []*Rule {
	out := make([]*Rule, 0, len(rules))
	for _, r := range rules {
		out = append(out, r)
	}
	return out
}

var rules = []*Rule{
	dirEnumRule,
	portScanRule,
	sqliRule,
	authBruteRule,
	wafBlockSpikeRule,
	dbAnomalyRule,
	webshellRule,
}

var dirEnumRule = &Rule{
	ID:          "dir-enum",
	Name:        "Directory Enumeration",
	Severity:    event.SeverityHigh,
	MITRE:       []string{"T1595.001", "T1083"},
	Confidence:  0.94,
	Description: "Automated content discovery against admin endpoints. Tooling signature matches DirBuster.",
	Window:      90 * time.Second,
	threshold:   12,
	matchFn: func(ev *event.NormalizedEvent) bool {
		if ev.Status != 403 && ev.Status != 404 && ev.Status != 401 {
			return false
		}
		if !strings.HasPrefix(string(ev.Source), "nginx") && ev.Source != event.SourceGateway && ev.Source != event.SourceNginx {
			return false
		}
		ua := strings.ToLower(ev.UserAgent)
		if isDirBusterUA(ua) {
			return true
		}
		return looksLikeSensitivePath(ev.Path)
	},
	keyFn: func(ev *event.NormalizedEvent) string { return ev.SrcIP },
	alertFn: func(evs []*event.NormalizedEvent) (Outcome, bool) {
		paths := map[string]struct{}{}
		blocked := 0
		for _, e := range evs {
			paths[e.Path] = struct{}{}
			if e.Status == 403 || e.Status == 401 {
				blocked++
			}
		}

		if len(paths) < 8 {
			return Outcome{}, false
		}
		return Outcome{Count: len(evs), Blocked: blocked, UniquePaths: len(paths), DistinctAssets: 1,
			Message: "Automated content discovery against admin endpoints. Tooling signature matches DirBuster."}, true
	},
}

var portScanRule = &Rule{
	ID:          "port-scan",
	Name:        "Sequential Port Scan",
	Severity:    event.SeverityHigh,
	MITRE:       []string{"T1046"},
	Confidence:  0.87,
	Description: "Reconnaissance against multiple services and hosts from a single source.",
	Window:      120 * time.Second,
	threshold:   15,
	matchFn: func(ev *event.NormalizedEvent) bool {
		return ev.Source == event.SourceGateway || ev.Source == event.SourceNginx
	},
	keyFn: func(ev *event.NormalizedEvent) string { return ev.SrcIP },
	alertFn: func(evs []*event.NormalizedEvent) (Outcome, bool) {
		assets := map[string]struct{}{}
		ports := map[string]struct{}{}
		for _, e := range evs {
			assets[e.Asset] = struct{}{}
			if e.SrcPort > 0 {
				ports[itoa(e.SrcPort)] = struct{}{}
			}
		}
		if len(assets) < 2 {
			return Outcome{}, false
		}
		return Outcome{Count: len(evs), DistinctAssets: len(assets), UniquePaths: len(ports),
			Message: "Sequential probing observed across multiple assets."}, true
	},
}

var sqliRule = &Rule{
	ID:          "sqli",
	Name:        "SQLi Pattern",
	Severity:    event.SeverityCritical,
	MITRE:       []string{"T1190"},
	Confidence:  0.91,
	Description: "SQL injection payloads matched against request path/query parameters.",
	Window:      120 * time.Second,
	threshold:   3,
	matchFn: func(ev *event.NormalizedEvent) bool {
		if ev.HasTag(event.TagSQLi) {
			return true
		}
		return sqliPattern.MatchString(ev.Path)
	},
	keyFn: func(ev *event.NormalizedEvent) string { return ev.SrcIP },
	alertFn: func(evs []*event.NormalizedEvent) (Outcome, bool) {
		return Outcome{Count: len(evs), Message: "Injection payloads observed against application endpoints."}, true
	},
}

var authBruteRule = &Rule{
	ID:          "auth-brute",
	Name:        "Credential Brute Force",
	Severity:    event.SeverityHigh,
	MITRE:       []string{"T1110"},
	Confidence:  0.9,
	Description: "Repeated authentication failures from a single source.",
	Window:      90 * time.Second,
	threshold:   5,
	matchFn: func(ev *event.NormalizedEvent) bool {
		return ev.HasTag(event.TagAuthFailure) || ev.HasTag(event.TagBruteForce)
	},
	keyFn: func(ev *event.NormalizedEvent) string { return ev.SrcIP },
	alertFn: func(evs []*event.NormalizedEvent) (Outcome, bool) {
		users := map[string]struct{}{}
		for _, e := range evs {
			if e.User != "" {
				users[e.User] = struct{}{}
			}
		}
		return Outcome{Count: len(evs), UniquePaths: len(users),
			Message: "Multiple failed authentication attempts in quick succession."}, true
	},
}

var wafBlockSpikeRule = &Rule{
	ID:          "waf-block-spike",
	Name:        "WAF Block Spike",
	Severity:    event.SeverityMedium,
	MITRE:       []string{"T1190"},
	Confidence:  0.85,
	Description: "A single source tripping WAF/rate-limit rules repeatedly.",
	Window:      60 * time.Second,
	threshold:   8,
	matchFn: func(ev *event.NormalizedEvent) bool {
		return ev.HasTag(event.TagWAFBlock)
	},
	keyFn: func(ev *event.NormalizedEvent) string { return ev.SrcIP },
	alertFn: func(evs []*event.NormalizedEvent) (Outcome, bool) {
		return Outcome{Count: len(evs), Blocked: len(evs),
			Message: "Repeated WAF/rate-limit blocks from a single source."}, true
	},
}

var dbAnomalyRule = &Rule{
	ID:          "db-anomaly",
	Name:        "Anomalous DB Query Volume",
	Severity:    event.SeverityMedium,
	MITRE:       []string{"T1190"},
	Confidence:  0.72,
	Description: "Backend reports a spike in DB-bound traffic or query latency.",
	Window:      90 * time.Second,
	threshold:   6,
	matchFn: func(ev *event.NormalizedEvent) bool {
		return ev.Source == event.SourceApp && (ev.HasTag(event.TagDbQuery) || ev.Status == 500)
	},
	keyFn: func(ev *event.NormalizedEvent) string { return ev.Asset },
	alertFn: func(evs []*event.NormalizedEvent) (Outcome, bool) {
		return Outcome{Count: len(evs),
			Message: "Unusual volume of DB-bound requests from a backend asset."}, true
	},
}

var webshellRule = &Rule{
	ID:          "webshell",
	Name:        "Webshell Delivery",
	Severity:    event.SeverityCritical,
	MITRE:       []string{"T1505.003"},
	Confidence:  0.88,
	Description: "Upload or delivery of a server-side script to a web-accessible path.",
	Window:      300 * time.Second,
	threshold:   1,
	matchFn: func(ev *event.NormalizedEvent) bool {
		if ev.HasTag(event.TagWebshell) {
			return true
		}
		if ev.Method != "POST" && ev.Method != "PUT" {
			return false
		}
		p := strings.ToLower(ev.Path)
		for _, ext := range []string{".php", ".jsp", ".aspx", ".asp", ".cgi", ".sh", ".jspx"} {
			if strings.Contains(p, ext) && !isKnownUploadPath(p) {
				return true
			}
		}
		return false
	},
	keyFn: func(ev *event.NormalizedEvent) string { return ev.SrcIP },
	alertFn: func(evs []*event.NormalizedEvent) (Outcome, bool) {
		paths := map[string]struct{}{}
		for _, e := range evs {
			paths[e.Path] = struct{}{}
		}
		return Outcome{Count: len(evs), UniquePaths: len(paths),
			Message: "Server-side script uploaded or probed on a web-accessible path."}, true
	},
}

var sqliPattern = regexpMust(`(?i)(union\s+select|(?:'|%27)\s*or\s*(?:'|%27)\s*=\s*(?:'|%27)|--\s*$|/\*|\bsleep\s*\(|information_schema|concat\s*\(|0x[0-9a-f]{6,}|'%20or%20'1'%3d'1|union\s*all\s*select)`)

func isDirBusterUA(ua string) bool {
	ua = strings.ToLower(ua)
	for _, sig := range []string{"dirbuster", "gobuster", "ffuf", "nikto", "dirb", "wfuzz", "feroxbuster", "python-requests"} {
		if strings.Contains(ua, sig) {
			return true
		}
	}
	return false
}

func looksLikeSensitivePath(p string) bool {
	pl := strings.ToLower(p)
	for _, seg := range []string{
		"administrator", "/manage", "wp-admin", "wp-login", "phpmyadmin", "backup", "config.php",
		".git", "server-status", "console", "shell", ".env", "/private", "/internal", "/admin",
		"uploads", "phpinfo", "actuator", "swagger", "metrics", "cgi-bin", "xmlrpc", ".svn",
	} {
		if strings.Contains(pl, seg) {
			return true
		}
	}
	return false
}

func isKnownUploadPath(p string) bool {
	pl := strings.ToLower(p)
	for _, seg := range []string{"/uploads/", "/images/", "/img/", "/assets/", "/media/"} {
		if strings.Contains(pl, seg) {
			return false
		}
	}
	return true
}
