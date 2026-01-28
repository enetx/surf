package surf

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/enetx/g"
)

// https://adguard-dns.io/kb/general/dns-providers/

// DNSOverTLS is a configuration struct for DNS over TLS settings.
type DNSOverTLS struct{ builder *Builder }

// AdGuard sets up DNS over TLS with AdGuard DNS.
func (dot *DNSOverTLS) AdGuard() *Builder {
	return dot.AddProvider("dns.adguard-dns.com", "94.140.14.14:853", "94.140.15.15:853")
}

// Google sets up DNS over TLS with Google Public DNS.
func (dot *DNSOverTLS) Google() *Builder {
	return dot.AddProvider("dns.google", "8.8.8.8:853", "8.8.4.4:853")
}

// Cloudflare sets up DNS over TLS with Cloudflare DNS.
func (dot *DNSOverTLS) Cloudflare() *Builder {
	return dot.AddProvider("1dot1dot1dot1.cloudflare-dns.com", "1.1.1.1:853", "1.0.0.1:853")
}

// Quad9 sets up DNS over TLS with Quad9 DNS.
func (dot *DNSOverTLS) Quad9() *Builder {
	return dot.AddProvider("dns.quad9.net", "9.9.9.9:853", "149.112.112.112:853")
}

// Switch sets up DNS over TLS with SWITCH DNS.
func (dot *DNSOverTLS) Switch() *Builder {
	return dot.AddProvider("dns.switch.ch", "130.59.31.248:853", "130.59.31.251:853")
}

// CIRAShield sets up DNS over TLS with CIRA Canadian Shield DNS.
func (dot *DNSOverTLS) CIRAShield() *Builder {
	return dot.AddProvider(
		"private.canadianshield.cira.ca",
		"149.112.121.10:853",
		"149.112.122.10:853",
	)
}

// Ali sets up DNS over TLS with AliDNS.
func (dot *DNSOverTLS) Ali() *Builder {
	return dot.AddProvider("dns.alidns.com", "223.5.5.5:853", "223.6.6.6:853")
}

// Quad101 sets up DNS over TLS with Quad101 DNS.
func (dot *DNSOverTLS) Quad101() *Builder {
	return dot.AddProvider("101.101.101.101", "101.101.101.101:853", "101.102.103.104:853")
}

// SB sets up DNS over TLS with Secure DNS (dot.sb).
func (dot *DNSOverTLS) SB() *Builder {
	return dot.AddProvider("dot.sb", "185.222.222.222:853", "45.11.45.11:853")
}

// Forge sets up DNS over TLS with DNS Forge.
func (dot *DNSOverTLS) Forge() *Builder {
	return dot.AddProvider("dnsforge.de", "176.9.93.198:853", "176.9.1.117:853")
}

// LibreDNS sets up DNS over TLS with LibreDNS.
func (dot *DNSOverTLS) LibreDNS() *Builder {
	return dot.AddProvider("dot.libredns.gr", "116.202.176.26:853")
}

// resolver returns a custom net.Resolver that uses a dial function to create a secure connection
// to the DNS server using DNS over TLS.
func (DNSOverTLS) resolver(serverName g.String, addresses ...g.String) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial:     dial(serverName.Std(), g.TransformSlice(addresses, g.String.Std)...),
	}
}

// AddProvider sets up DNS over TLS with a custom DNS provider.
// It configures a custom net.Resolver using the resolver method.
func (dot *DNSOverTLS) AddProvider(serverName g.String, addresses ...g.String) *Builder {
	resolver := dot.resolver(serverName, addresses...)
	return dot.builder.addCliMW(func(client *Client) error { return dnsTLSMW(client, resolver) }, 0)
}

// dial returns a dial function that establishes a secure connection to a random DNS server address
// from the given list using DNS over TLS.
func dial(serverName string, addresses ...string) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, _, _ string) (net.Conn, error) {
		var (
			dialer net.Dialer
			conn   net.Conn
			err    error
		)

		for _, address := range addresses {
			conn, err = dialer.DialContext(ctx, "tcp", address)
			if err == nil {
				break
			}
		}

		if err != nil {
			return nil, err
		}

		const keepAlivePeriod = 3 * time.Minute

		_ = conn.(*net.TCPConn).SetKeepAlive(true)
		_ = conn.(*net.TCPConn).SetKeepAlivePeriod(keepAlivePeriod)

		return tls.Client(conn, &tls.Config{
			ServerName:         serverName,
			ClientSessionCache: tls.NewLRUClientSessionCache(0),
		}), nil
	}
}
