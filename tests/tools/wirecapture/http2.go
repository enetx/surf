package main

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/enetx/http/http2"
	"golang.org/x/net/http2/hpack"
)

func (s *captureServer) serveTCP(listener net.Listener) {
	for {
		raw, err := listener.Accept()
		if err != nil {
			return
		}
		label := s.label()
		go s.serveH2(raw, label)
	}
}

func (s *captureServer) serveH2(raw net.Conn, label string) {
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(90 * time.Second))
	conn := tls.Server(&capturedTCP{Conn: raw, capture: s.packets}, s.tlsConfig)
	if err := conn.Handshake(); err != nil {
		s.fail(fmt.Errorf("TLS: %w", err))
		return
	}
	if conn.ConnectionState().NegotiatedProtocol != "h2" {
		s.fail(fmt.Errorf("unexpected ALPN %q", conn.ConnectionState().NegotiatedProtocol))
		return
	}
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(conn, preface); err != nil {
		return
	}
	if string(preface) != http2.ClientPreface {
		s.fail(fmt.Errorf("invalid HTTP/2 preface"))
		return
	}
	fr := http2.NewFramer(conn, conn)
	if err := fr.WriteSettings(http2.Setting{ID: http2.SettingHeaderTableSize, Val: uint32(s.capacity)}, http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 100}, http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 20}); err != nil {
		return
	}
	decoder := hpack.NewDecoder(1<<20, nil)
	var encoded bytes.Buffer
	encoder := hpack.NewEncoder(&encoded)
	var block []byte
	var stream uint32
	for {
		frame, err := fr.ReadFrame()
		if err != nil {
			return
		}
		switch f := frame.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				if err := fr.WriteSettingsAck(); err != nil {
					return
				}
			}
			continue
		case *http2.PingFrame:
			if !f.IsAck() {
				fr.WritePing(true, f.Data)
			}
			continue
		case *http2.HeadersFrame:
			stream = f.StreamID
			block = append(block[:0], f.HeaderBlockFragment()...)
			if !f.HeadersEnded() {
				continue
			}
		case *http2.ContinuationFrame:
			block = append(block, f.HeaderBlockFragment()...)
			if !f.HeadersEnded() {
				continue
			}
		default:
			continue
		}
		fields, err := decoder.DecodeFull(block)
		if err != nil {
			s.fail(err)
			return
		}
		req := observedRequest{Label: label, Connection: raw.RemoteAddr().String(), Protocol: "h2", HeaderBlock: hex.EncodeToString(block), StreamID: uint64(stream)}
		for _, field := range fields {
			req.Fields = append(req.Fields, headerField{field.Name, field.Value})
			if field.Name == ":path" {
				req.Path = field.Value
			}
			if field.Name == ":method" {
				req.Method = field.Value
			}
		}
		s.record(req)
		if table, ok := s.nextTableSize(req.Path); ok {
			if err := fr.WriteSettings(http2.Setting{ID: http2.SettingHeaderTableSize, Val: table}); err != nil {
				return
			}
		}
		headers, body := s.response(req.Path)
		headers.Set("Content-Length", fmt.Sprint(len(body)))
		encoded.Reset()
		encoder.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
		keys := make([]string, 0, len(headers))
		for key := range headers {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			for _, value := range slices.Clone(headers[key]) {
				encoder.WriteField(hpack.HeaderField{Name: strings.ToLower(key), Value: value})
			}
		}
		if err := fr.WriteHeaders(http2.HeadersFrameParam{StreamID: stream, BlockFragment: encoded.Bytes(), EndHeaders: true}); err != nil {
			return
		}
		if err := fr.WriteData(stream, true, body); err != nil {
			return
		}
	}
}
