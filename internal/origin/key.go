package origin

import (
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

// Key canonicalizes an HTTP origin without path, credentials or request Host
// overrides. Scheme and effective port remain part of the identity.
func Key(u *url.URL) (string, bool) {
	if u == nil {
		return "", false
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", false
	}

	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", false
	}

	if ip, err := netip.ParseAddr(host); err == nil {
		host = ip.String()
	} else {
		var err error
		host, err = idna.Lookup.ToASCII(host)
		if err != nil {
			return "", false
		}
	}

	port := u.Port()
	if port != "" {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			return "", false
		}

		port = strconv.FormatUint(n, 10)
	}

	if port == "" || scheme == "https" && port == "443" || scheme == "http" && port == "80" {
		port = ""
	}

	authority := host

	if port != "" {
		authority = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		authority = "[" + host + "]"
	}

	return scheme + "://" + authority, true
}
