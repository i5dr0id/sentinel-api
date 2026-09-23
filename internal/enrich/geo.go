package enrich

import (
	"net"
	"strings"

	"github.com/rs/zerolog"

	"github.com/i5dr0id/sentinel-api/internal/event"
)

type Resolver interface {
	Lookup(ip string) (event.Geo, bool)
}

func Default(_ *zerolog.Logger) Resolver { return &staticResolver{table: demoASNTable} }

type staticResolver struct {
	table []asnBlock
}

type asnBlock struct {
	cidr string
	geo  event.Geo
}

func (r *staticResolver) Lookup(ip string) (event.Geo, bool) {
	ip = strings.TrimSpace(ip)
	if ip == "" || isPrivate(ip) {
		return event.Geo{}, false
	}
	for _, b := range r.table {
		_, c, err := net.ParseCIDR(b.cidr)
		if err != nil {
			continue
		}
		if c.Contains(net.ParseIP(ip)) {
			return b.geo, true
		}
	}

	return event.Geo{CountryCode: "XX", CountryName: "Unknown"}, true
}

func isPrivate(ip string) bool {
	p := net.ParseIP(ip)
	if p == nil {
		return true
	}
	return p.IsPrivate() || p.IsLoopback() || p.IsLinkLocalUnicast() || p.IsUnspecified()
}

var demoASNTable = []asnBlock{
	{cidr: "32.122.0.0/16", geo: event.Geo{CountryCode: "NL", CountryName: "Netherlands", City: "Amsterdam", ASN: "14061", Org: "DigitalOcean, LLC", ISP: "DigitalOcean"}},
	{cidr: "203.0.113.0/24", geo: event.Geo{CountryCode: "US", CountryName: "United States", City: "Test", ASN: "13335", Org: "Cloudflare, Inc.", ISP: "Cloudflare"}},
	{cidr: "198.51.100.0/24", geo: event.Geo{CountryCode: "DE", CountryName: "Germany", City: "Frankfurt", ASN: "24940", Org: "Hetzner Online GmbH", ISP: "Hetzner"}},
	{cidr: "185.220.0.0/16", geo: event.Geo{CountryCode: "SE", CountryName: "Sweden", City: "Stockholm", ASN: "1239", Org: "Rackner-AB", ISP: "Rackner"}},
	{cidr: "104.223.0.0/16", geo: event.Geo{CountryCode: "US", CountryName: "United States", City: "Fremont", ASN: "40021", Org: "QuadraNet Enterprises LLC", ISP: "QuadraNet"}},
	{cidr: "45.55.0.0/16", geo: event.Geo{CountryCode: "US", CountryName: "United States", City: "San Francisco", ASN: "14061", Org: "DigitalOcean, LLC", ISP: "DigitalOcean"}},
	{cidr: "89.187.160.0/19", geo: event.Geo{CountryCode: "RO", CountryName: "Romania", City: "Bucharest", ASN: "51167", Org: "Contabo GmbH", ISP: "Contabo"}},
	{cidr: "162.159.0.0/16", geo: event.Geo{CountryCode: "US", CountryName: "United States", City: "San Francisco", ASN: "13335", Org: "Cloudflare, Inc.", ISP: "Cloudflare"}},
	{cidr: "91.108.4.0/22", geo: event.Geo{CountryCode: "RU", CountryName: "Russian Federation", City: "Moscow", ASN: "20764", Org: "CJSC RASCOM", ISP: "RASCOM"}},
	{cidr: "41.60.0.0/16", geo: event.Geo{CountryCode: "NG", CountryName: "Nigeria", City: "Lagos", ASN: "37645", Org: "Layer3", ISP: "Layer3"}},
	{cidr: "105.112.0.0/16", geo: event.Geo{CountryCode: "NG", CountryName: "Nigeria", City: "Lagos", ASN: "29465", Org: "MTN Nigeria", ISP: "MTN"}},
	{cidr: "197.210.0.0/16", geo: event.Geo{CountryCode: "NG", CountryName: "Nigeria", City: "Abuja", ASN: "29465", Org: "MTN Nigeria", ISP: "MTN"}},
	{cidr: "154.120.0.0/16", geo: event.Geo{CountryCode: "GH", CountryName: "Ghana", City: "Accra", ASN: "30969", Org: "Ghana Internet", ISP: "GCI"}},
	{cidr: "102.88.0.0/16", geo: event.Geo{CountryCode: "ZA", CountryName: "South Africa", City: "Johannesburg", ASN: "36944", Org: "SEACOM", ISP: "SEACOM"}},
	{cidr: "212.9.0.0/16", geo: event.Geo{CountryCode: "GB", CountryName: "United Kingdom", City: "London", ASN: "20860", Org: "Iomart", ISP: "Iomart"}},
}
