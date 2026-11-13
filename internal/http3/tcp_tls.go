package h3transport

import (
	"context"
	"crypto/tls"
	"net"
	"slices"

	"github.com/enetx/http"
	"github.com/enetx/surf/internal/echretry"
)

func (ut *Transport) dialTCPWithECH(base *http.Transport) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if base.TLSHandshakeTimeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, base.TLSHandshakeTimeout)
			defer cancel()
		}

		config := ut.tlsConfig.Clone()
		if base.TLSClientConfig != nil {
			config = base.TLSClientConfig.Clone()
		}

		if config.ServerName == "" {
			config.ServerName, _, _ = net.SplitHostPort(address)
		}

		if route, ok := ctx.Value(alternativeRouteKey{}).(alternativeRoute); ok && len(route.ech) > 0 {
			config.EncryptedClientHelloConfigList = slices.Clone(route.ech)
			config.MinVersion = tls.VersionTLS13
		}

		if ut.tcpVersion == 1 {
			config.NextProtos = []string{"http/1.1"}
		} else if ut.tcpVersion == 2 {
			config.NextProtos = []string{"h2"}
		} else if len(config.NextProtos) == 0 {
			config.NextProtos = []string{"h2", "http/1.1"}
		}

		dial := base.DialContext
		if dial == nil {
			dial = new(net.Dialer).DialContext
		}

		for attempt := 0; ; attempt++ {
			conn, err := dial(ctx, network, address)
			if err != nil {
				return nil, err
			}

			secure := tls.Client(conn, config)
			if err = secure.HandshakeContext(ctx); err == nil {
				return secure, nil
			}

			conn.Close()

			retry := echretry.Configs(err)
			if attempt > 0 || len(retry) == 0 || ctx.Err() != nil {
				return nil, err
			}

			config.EncryptedClientHelloConfigList = retry
		}
	}
}
