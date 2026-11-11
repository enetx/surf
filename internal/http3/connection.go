package h3transport

import (
	"context"
	"crypto/tls"
	"net"
	"strings"

	"github.com/enetx/quic-go"
)

// dial establishes a QUIC connection, routing through SOCKS5 proxy if configured.
func (ut *Transport) dial(
	ctx context.Context,
	addr string,
	tlsCfg *tls.Config,
	cfg *quic.Config,
) (connection *quic.Conn, err error) {
	defer func() {
		if ut.racer != nil && connection != nil && err == nil {
			ut.racer.ObserveQUIC(addr, connection)
		}
	}()

	target := addr
	var route alternativeRoute

	if candidate, ok := ctx.Value(alternativeRouteKey{}).(alternativeRoute); ok &&
		strings.EqualFold(candidate.origin, addr) {
		route = candidate
		target = route.address
		defer func() {
			if ut.discovery != nil {
				ut.discovery.result(route, err)
			}
		}()
	}

	host, _, _ := net.SplitHostPort(addr)
	if tlsCfg.ServerName == "" && host != "" && net.ParseIP(host) == nil {
		tlsCfg = tlsCfg.Clone()
		tlsCfg.ServerName = host
	}

	if len(route.ech) > 0 {
		tlsCfg = tlsCfg.Clone()
		tlsCfg.EncryptedClientHelloConfigList = append([]byte(nil), route.ech...)
		tlsCfg.MinVersion = tls.VersionTLS13
	}

	dial := ut.quicDialer.Dial
	if ut.useEarlyData(ctx) {
		dial = ut.quicDialer.DialEarly
	}
	return dial(ctx, target, tlsCfg, cfg, route.hints)
}
