package main

import (
	"bufio"
	"crypto/tls"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCaptureHTTP1Fallback(t *testing.T) {
	for _, alpn := range [][]string{{"http/1.1"}, nil} {
		t.Run(strings.Join(alpn, ","), func(t *testing.T) {
			dir := t.TempDir()
			cert, _, err := certificate(dir)
			require.NoError(t, err)
			packets, err := newPacketCapture(filepath.Join(dir, "wire.pcap"))
			require.NoError(t, err)
			defer packets.Close()
			records, err := os.Create(filepath.Join(dir, "requests.jsonl"))
			require.NoError(t, err)
			defer records.Close()
			s := &captureServer{packets: packets, records: records, tlsConfig: &tls.Config{
				Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"},
			}}
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			require.NoError(t, err)
			defer listener.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				conn, err := listener.Accept()
				if err == nil {
					s.serveTLS(conn, "browser")
				}
			}()
			conn, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: alpn})
			require.NoError(t, err)
			defer conn.Close()
			require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
			first := "POST /step/0 HTTP/1.1\r\nHost: localhost\r\nX-Ordered: one\r\nx-ordered: two\r\nContent-Length: 3\r\n\r\n"
			second := "GET /complete HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
			// Body and next request share one write: no prefixed-buffer read-ahead
			// may swallow either when preserving the first raw header block.
			_, err = io.WriteString(conn, first+"abc"+second)
			require.NoError(t, err)
			reader := bufio.NewReader(conn)
			for range 2 {
				response, err := http.ReadResponse(reader, nil)
				require.NoError(t, err)
				body, err := io.ReadAll(response.Body)
				require.NoError(t, err)
				require.Equal(t, "ok", string(body))
				response.Body.Close()
			}
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("capture did not finish")
			}
			s.mu.Lock()
			defer s.mu.Unlock()
			require.Empty(t, s.errors)
			require.True(t, s.completed)
			require.Len(t, s.requests, 2)
			require.Equal(t, "h1", s.requests[0].Protocol)
			require.Equal(t, hex.EncodeToString([]byte(first)), s.requests[0].RawHeaders)
			require.Equal(t, []headerField{{"x-ordered", "one"}, {"x-ordered", "two"}, {"content-length", "3"}}, s.requests[0].Fields[4:])
			require.NotEmpty(t, s.requests[0].RecordedAt)
		})
	}
}

func TestCaptureHTTP1HeaderLimit(t *testing.T) {
	reader := bufio.NewReaderSize(strings.NewReader("GET / HTTP/1.1\r\nX: "+strings.Repeat("x", captureHeaderLimit)), captureHeaderLimit)
	_, err := peekH1Headers(reader)
	require.ErrorContains(t, err, "exceed capture limit")
}
