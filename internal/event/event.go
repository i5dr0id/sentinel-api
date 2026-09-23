package event

import "time"

type Source string

const (
	SourceCloudflare Source = "cloudflare"
	SourceGateway    Source = "api_gateway"
	SourceNginx      Source = "nginx"
	SourceApp        Source = "app"
	SourceSSH        Source = "ssh"
	SourceAudit      Source = "audit"
)

type RawLog struct {
	Source Source         `json:"source" validate:"required"`
	Asset  string         `json:"asset"`
	Fields map[string]any `json:"fields"`
}

type Geo struct {
	CountryCode string `json:"country_code,omitempty"`
	CountryName string `json:"country_name,omitempty"`
	City        string `json:"city,omitempty"`
	ASN         string `json:"asn,omitempty"`
	Org         string `json:"org,omitempty"`
	ISP         string `json:"isp,omitempty"`
}

func (g *Geo) IsZero() bool {
	return g == nil || (g.CountryCode == "" && g.ASN == "")
}

type NormalizedEvent struct {
	ID        string            `json:"id"`
	Timestamp time.Time         `json:"timestamp"`
	Source    Source            `json:"source"`
	Asset     string            `json:"asset"`
	SrcIP     string            `json:"src_ip"`
	SrcPort   int               `json:"src_port"`
	Method    string            `json:"method"`
	Path      string            `json:"path"`
	Status    int               `json:"status"`
	Size      int               `json:"size,omitempty"`
	Proto     string            `json:"proto"`
	UserAgent string            `json:"user_agent"`
	Referer   string            `json:"referer"`
	User      string            `json:"user,omitempty"`
	Message   string            `json:"message,omitempty"`
	Tags      []string          `json:"tags,omitempty"`
	Geo       *Geo              `json:"geo,omitempty"`
	Extra     map[string]string `json:"extra,omitempty"`
}

func (e *NormalizedEvent) HasTag(tag string) bool {
	for _, t := range e.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

const (
	TagWAFBlock    = "waf_block"
	TagSoft404     = "soft_404"
	TagBruteForce  = "brute_force"
	TagSQLi        = "sqli"
	TagWebshell    = "webshell"
	TagAuthFailure = "auth_failure"
	TagDbQuery     = "db_query"
	TagScan        = "scan"
)

type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
)

func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	}
	return 0
}
