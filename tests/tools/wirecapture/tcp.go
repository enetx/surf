package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

func (s *captureServer) serveTCP(listener net.Listener) {
	for {
		raw, err := listener.Accept()
		if err != nil {
			return
		}
		go s.serveTLS(raw, s.label())
	}
}

func (s *captureServer) serveTLS(raw net.Conn, label string) {
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(90 * time.Second))
	conn := tls.Server(&capturedTCP{Conn: raw, capture: s.packets}, s.tlsConfig)
	if err := conn.Handshake(); err != nil {
		s.fail(fmt.Errorf("TLS: %w", err))
		return
	}
	switch conn.ConnectionState().NegotiatedProtocol {
	case "h2":
		s.serveH2(conn, label)
	case "", "http/1.1":
		s.serveH1(conn, label)
	default:
		s.fail(fmt.Errorf("unexpected ALPN %q", conn.ConnectionState().NegotiatedProtocol))
	}
}
