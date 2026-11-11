package connrace

import (
	"errors"
	"net"
	"net/netip"

	"github.com/enetx/http"
	"golang.org/x/net/idna"
)

// Address normalizes the HTTPS authority used to share connection preparation.
func Address(req *http.Request) (string, error) {
	host := req.URL.Hostname()
	if host == "" {
		return "", errors.New("surf: missing connection race host")
	}

	if _, err := netip.ParseAddr(host); err != nil {
		var err error
		host, err = idna.Lookup.ToASCII(host)
		if err != nil {
			return "", err
		}
	}

	port := req.URL.Port()
	if port == "" {
		port = "443"
	}

	return net.JoinHostPort(host, port), nil
}
