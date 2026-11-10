package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

const captureHeaderLimit = 64 << 10

// Peek without consuming: ReadRequest must keep the same buffer for request
// bodies and pipelined requests. A separate prefixed reader can lose read-ahead.
func peekH1Headers(reader *bufio.Reader) ([]byte, error) {
	for {
		data, _ := reader.Peek(reader.Buffered())
		if end := bytes.Index(data, []byte("\r\n\r\n")); end >= 0 {
			return bytes.Clone(data[:end+4]), nil
		}
		if reader.Buffered() >= captureHeaderLimit {
			return nil, errors.New("HTTP/1 headers exceed capture limit")
		}
		if _, err := reader.Peek(reader.Buffered() + 1); err != nil {
			return nil, err
		}
	}
}

func (s *captureServer) serveH1(conn net.Conn, label string) {
	reader := bufio.NewReaderSize(conn, captureHeaderLimit)
	for {
		raw, err := peekH1Headers(reader)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				s.fail(err)
			}
			return
		}
		request, err := http.ReadRequest(reader)
		if err != nil {
			s.fail(err)
			return
		}
		_, err = io.Copy(io.Discard, request.Body)
		request.Body.Close()
		if err != nil {
			s.fail(err)
			return
		}
		captured := observedRequest{Label: label, Connection: conn.RemoteAddr().String(), Protocol: "h1",
			Method: request.Method, Path: request.URL.RequestURI(), RawHeaders: hex.EncodeToString(raw),
			RecordedAt: time.Now().UTC().Format(time.RFC3339Nano),
			Fields:     []headerField{{":method", request.Method}, {":scheme", "https"}, {":authority", request.Host}, {":path", request.URL.RequestURI()}},
		}
		// Host is represented as authority for cross-protocol replay; raw bytes
		// retain the original spelling, order and repeated fields, including Host.
		for _, line := range strings.Split(string(raw), "\r\n")[1:] {
			name, value, ok := strings.Cut(line, ":")
			if ok && !strings.EqualFold(name, "host") {
				captured.Fields = append(captured.Fields, headerField{strings.ToLower(name), strings.TrimSpace(value)})
			}
		}
		s.record(captured)
		headers, body := s.response(captured.Path)
		response := &http.Response{StatusCode: http.StatusOK, ProtoMajor: 1, ProtoMinor: 1,
			Header: headers, Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body)), Close: request.Close,
		}
		if err := response.Write(conn); err != nil {
			s.fail(fmt.Errorf("HTTP/1 response: %w", err))
			return
		}
		if request.Close {
			return
		}
	}
}
