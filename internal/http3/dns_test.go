package h3transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/dns/dnsmessage"
)

func httpsDNSAnswer(query dnsmessage.Message, data []byte) dnsmessage.Message {
	return dnsmessage.Message{
		Header:    dnsmessage.Header{ID: query.ID, Response: true},
		Questions: query.Questions,
		Answers: []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{
					Name:  query.Questions[0].Name,
					Class: dnsmessage.ClassINET,
					Type:  dnsTypeHTTPS,
					TTL:   60,
				},
				Body: &dnsmessage.UnknownResource{Type: dnsTypeHTTPS, Data: data},
			},
		},
	}
}

func TestHTTPSDNSLocalhostDoesNotQueryExternalResolver(t *testing.T) {
	var calls atomic.Int32
	resolver := &net.Resolver{Dial: func(context.Context, string, string) (net.Conn, error) {
		calls.Add(1)
		return nil, errors.New("external DNS must not be used for localhost")
	}}
	lookup := httpsLookupForResolver(resolver)
	for _, host := range []string{"localhost", "LOCALHOST.", "service.localhost", "_8443._https.localhost"} {
		records, err := lookup(t.Context(), host)
		require.NoError(t, err, host)
		require.Empty(t, records, host)
	}
	_, err := lookup(t.Context(), "localhost.example")
	require.Error(t, err)
	require.Positive(t, calls.Load(), "ordinary names must still use the configured resolver")
}

func streamDNSResolver(t *testing.T, reply func(dnsmessage.Message) dnsmessage.Message) *net.Resolver {
	t.Helper()
	return &net.Resolver{Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			server.SetDeadline(time.Now().Add(time.Second))
			var prefix [2]byte
			if _, err := io.ReadFull(server, prefix[:]); err != nil {
				return
			}
			data := make([]byte, binary.BigEndian.Uint16(prefix[:]))
			if _, err := io.ReadFull(server, data); err != nil {
				return
			}
			var query dnsmessage.Message
			if err := query.Unpack(data); err != nil {
				t.Error(err)
				return
			}
			response := reply(query)
			data, err := response.Pack()
			if err != nil {
				t.Error(err)
				return
			}
			binary.BigEndian.PutUint16(prefix[:], uint16(len(data)))
			if _, err = server.Write(append(prefix[:], data...)); err != nil && ctx.Err() == nil {
				t.Error(err)
			}
		}()
		return client, nil
	}}
}

func TestHTTPSDNSUsesConfiguredStreamTransportAndAliasTTL(t *testing.T) {
	var calls atomic.Int32
	resolver := streamDNSResolver(t, func(query dnsmessage.Message) dnsmessage.Message {
		calls.Add(1)
		if query.Questions[0].Type != dnsTypeHTTPS {
			t.Errorf("question type %v", query.Questions[0].Type)
		}
		if strings.EqualFold(query.Questions[0].Name.String(), "origin.example.") {
			// AliasMode target alt.example, TTL 10s bounds the service TTL.
			answer := httpsDNSAnswer(query, []byte{0, 0, 3, 'a', 'l', 't', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0})
			answer.Answers[0].Header.TTL = 10
			return answer
		}
		return httpsDNSAnswer(query, []byte{0, 1, 0, 0, 1, 0, 3, 2, 'h', '3'})
	})
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	records, err := queryHTTPS(ctx, "origin.example", "127.0.0.1:53", resolver, 0)
	require.NoError(t, err)
	require.Len(t, records, 1)
	require.Equal(t, 10*time.Second, records[0].TTL)
	require.Equal(t, "alt.example.", records[0].Target)
	require.EqualValues(t, 2, calls.Load())
}

func TestHTTPSDNSUsesVerifiedTLSTransport(t *testing.T) {
	certServer := httptest.NewTLSServer(nil)
	defer certServer.Close()
	listener, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{Certificates: certServer.TLS.Certificates})
	require.NoError(t, err)
	defer listener.Close()
	var questions atomic.Int32
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(time.Second))
				var prefix [2]byte
				if _, err := io.ReadFull(conn, prefix[:]); err != nil {
					return
				}
				data := make([]byte, binary.BigEndian.Uint16(prefix[:]))
				if _, err := io.ReadFull(conn, data); err != nil {
					return
				}
				var query dnsmessage.Message
				if query.Unpack(data) != nil {
					return
				}
				questions.Add(1)
				answer := httpsDNSAnswer(query, []byte{0, 1, 0, 0, 1, 0, 3, 2, 'h', '3'})
				data, err := answer.Pack()
				if err != nil {
					return
				}
				binary.BigEndian.PutUint16(prefix[:], uint16(len(data)))
				conn.Write(append(prefix[:], data...))
			}()
		}
	}()
	roots := x509.NewCertPool()
	roots.AddCert(certServer.Certificate())
	for _, trusted := range []bool{true, false} {
		pool := roots
		if !trusted {
			pool = x509.NewCertPool()
		}
		resolver := &net.Resolver{Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			dialer := tls.Dialer{Config: &tls.Config{RootCAs: pool, ServerName: "example.com"}}
			return dialer.DialContext(ctx, "tcp", listener.Addr().String())
		}}
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		records, err := queryHTTPS(ctx, "origin.example", "unused-system-address:53", resolver, 0)
		cancel()
		if trusted {
			require.NoError(t, err)
			require.Len(t, records, 1)
		} else {
			require.Error(t, err)
			require.Empty(t, records)
		}
	}
	require.EqualValues(t, 1, questions.Load(), "an untrusted TLS resolver must not receive DNS data or trigger plaintext fallback")
}

func TestHTTPSDNSRejectsSpoofedResponseAndAliasLoop(t *testing.T) {
	for _, mode := range []string{"id", "question", "name", "loop"} {
		t.Run(mode, func(t *testing.T) {
			resolver := streamDNSResolver(t, func(query dnsmessage.Message) dnsmessage.Message {
				response := httpsDNSAnswer(query, []byte{0, 1, 0, 0, 1, 0, 3, 2, 'h', '3'})
				switch mode {
				case "id":
					response.ID++
				case "question":
					response.Questions = nil
				case "name":
					response.Answers[0].Header.Name = dnsmessage.MustNewName("attacker.example.")
				case "loop":
					response = httpsDNSAnswer(
						query,
						[]byte{0, 0, 6, 'o', 'r', 'i', 'g', 'i', 'n', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},
					)
				}
				return response
			})
			records, err := queryHTTPS(t.Context(), "origin.example", "127.0.0.1:53", resolver, 0)
			if mode == "name" {
				require.NoError(t, err)
				require.Empty(t, records)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestHTTPSDNSCancellationClosesStream(t *testing.T) {
	serverDone := make(chan struct{})
	resolver := &net.Resolver{Dial: func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() { defer close(serverDone); defer server.Close(); io.Copy(io.Discard, server) }()
		return client, nil
	}}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()
	_, err := queryHTTPS(ctx, "origin.example", "127.0.0.1:53", resolver, 0)
	require.Error(t, err)
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("DNS connection leaked after cancellation")
	}
}

func TestHTTPSDNSUDPTruncationRetriesTCP(t *testing.T) {
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer udp.Close()
	tcp, err := net.Listen("tcp", udp.LocalAddr().String())
	require.NoError(t, err)
	defer tcp.Close()
	done := make(chan error, 2)
	go func() {
		data := make([]byte, 2048)
		udp.SetReadDeadline(time.Now().Add(time.Second))
		n, address, err := udp.ReadFrom(data)
		if err != nil {
			done <- err
			return
		}
		var query dnsmessage.Message
		if err = query.Unpack(data[:n]); err != nil {
			done <- err
			return
		}
		response := dnsmessage.Message{
			Header:    dnsmessage.Header{ID: query.ID, Response: true, Truncated: true},
			Questions: query.Questions,
		}
		data, err = response.Pack()
		if err == nil {
			_, err = udp.WriteTo(data, address)
		}
		done <- err
	}()
	go func() {
		conn, err := tcp.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(time.Second))
		var prefix [2]byte
		if _, err = io.ReadFull(conn, prefix[:]); err != nil {
			done <- err
			return
		}
		data := make([]byte, binary.BigEndian.Uint16(prefix[:]))
		if _, err = io.ReadFull(conn, data); err != nil {
			done <- err
			return
		}
		var query dnsmessage.Message
		if err = query.Unpack(data); err != nil {
			done <- err
			return
		}
		response := httpsDNSAnswer(query, []byte{0, 1, 0, 0, 1, 0, 3, 2, 'h', '3'})
		data, err = response.Pack()
		if err != nil {
			done <- err
			return
		}
		binary.BigEndian.PutUint16(prefix[:], uint16(len(data)))
		_, err = conn.Write(append(prefix[:], data...))
		done <- err
	}()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	records, err := queryHTTPS(ctx, "origin.example", udp.LocalAddr().String(), nil, 0)
	require.NoError(t, err)
	require.Len(t, records, 1)
	require.NoError(t, <-done)
	require.NoError(t, <-done)
}

func FuzzHTTPSRecord(f *testing.F) {
	f.Add([]byte{0, 1, 0, 0, 1, 0, 3, 2, 'h', '3'})
	f.Add([]byte{0, 1, 0xc0, 0})
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = parseHTTPSRecord(data, time.Minute) })
}
