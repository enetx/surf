package surf_test

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/surf"
)

type http1WireRequest struct {
	headers []string
	body    string
	err     error
}

func captureHTTP1Request(ln net.Listener, done chan<- http1WireRequest) {
	var got http1WireRequest
	defer func() { done <- got }()
	conn, err := ln.Accept()
	if err != nil {
		got.err = err
		return
	}
	defer conn.Close()
	if got.err = conn.SetDeadline(time.Now().Add(5 * time.Second)); got.err != nil {
		return
	}
	reader := bufio.NewReader(conn)
	var raw strings.Builder
	for lineNumber := 0; ; lineNumber++ {
		line, err := reader.ReadString('\n')
		if err != nil {
			got.err = err
			return
		}
		raw.WriteString(line)
		if line == "\r\n" {
			break
		}
		if lineNumber > 0 {
			got.headers = append(got.headers, strings.TrimSuffix(line, "\r\n"))
		}
	}
	req, err := http.ReadRequest(bufio.NewReader(io.MultiReader(strings.NewReader(raw.String()), reader)))
	if err != nil {
		got.err = err
		return
	}
	body, err := io.ReadAll(req.Body)
	req.Body.Close()
	if err != nil {
		got.err = err
		return
	}
	got.body = string(body)
	_, got.err = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
}

func TestHTTP1OrderedHeadersOnWire(t *testing.T) {
	t.Parallel()
	client := surf.NewClient().Builder().ForceHTTP1().Timeout(5 * time.Second).Build().Unwrap()
	defer client.CloseIdleConnections()
	for _, order := range [][]string{
		{"X-Z", "Content-Length", "Host", "User-Agent", "X-A"},
		{"X-A", "User-Agent", "Host", "Content-Length", "X-Z"},
	} {
		for _, payload := range []string{"", "payload"} {
			t.Run(fmt.Sprintf("first=%s/body=%d", order[0], len(payload)), func(t *testing.T) {
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer ln.Close()
				captured := make(chan http1WireRequest, 1)
				go captureHTTP1Request(ln, captured)
				values := map[string]string{
					"X-Z": "last-alphabetically", "X-A": "first-value",
					"User-Agent": "surf-order-test",
				}
				headers := g.NewMapOrd[string, string]()
				for _, name := range order {
					headers.Insert(name, values[name])
				}
				resp := client.Post(g.String("http://"+ln.Addr().String()+"/ordered")).
					Body(payload).
					SetHeaders(headers).
					AddHeaders("X-A", "second-value").
					Do()
				if resp.IsErr() {
					t.Fatal(resp.Err())
				}
				if body := resp.Ok().Body.String(); body.IsErr() || body.Ok() != "ok" {
					t.Fatalf("response body = %v", body)
				}
				got := <-captured
				if got.err != nil {
					t.Fatal(got.err)
				}
				values["Host"] = ln.Addr().String()
				values["Content-Length"] = strconv.Itoa(len(payload))
				var want []string
				for _, name := range order {
					want = append(want, name+": "+values[name])
					if name == "X-A" {
						want = append(want, "X-A: second-value")
					}
				}
				if len(got.headers) < len(want) || !slices.Equal(got.headers[:len(want)], want) {
					t.Fatalf("wire headers = %q, want prefix %q", got.headers, want)
				}
				if !slices.IsSorted(got.headers[len(want):]) {
					t.Errorf("unlisted wire headers are unsorted: %q", got.headers[len(want):])
				}
				for _, field := range got.headers {
					if strings.Contains(strings.ToLower(field), "header-order:") {
						t.Errorf("ordering metadata reached the wire: %q", field)
					}
				}
				if got.body != payload {
					t.Errorf("body = %q, want %q", got.body, payload)
				}
			})
		}
	}
}
