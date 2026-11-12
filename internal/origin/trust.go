// Package origin supplies shared HTTP origin classification for browser policies.
package origin

import (
	"net/netip"
	"net/url"
	"strings"
)

// TrustworthyHTTP reports whether an HTTP(S) URL is potentially trustworthy.
// HTTPS and HTTP loopback/localhost origins qualify; other schemes do not.
// This classifies the URL without resolving its host or overriding TLS checks.
// https://w3c.github.io/webappsec-secure-contexts/#is-origin-trustworthy
func TrustworthyHTTP(u *url.URL) bool {
	if u == nil || u.Hostname() == "" {
		return false
	}
	if strings.EqualFold(u.Scheme, "https") {
		return true
	}
	if !strings.EqualFold(u.Scheme, "http") {
		return false
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && !ip.Is4In6() && ip.IsLoopback()
}
