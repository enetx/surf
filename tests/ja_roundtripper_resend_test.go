package surf_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/textproto"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/http/http2"
	"github.com/enetx/http/httptest"
	"github.com/enetx/http/httptrace"
	"github.com/enetx/surf"
	"golang.org/x/net/http2/hpack"
)

type resendConnKey struct{}

func TestRoundTripperResendPolicy(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name          string
		warm          bool
		method        string
		alwaysClose   bool
		informational int
		finalHeaders  bool
		reset         bool
		noGetBody     bool
		getBodyError  bool
		cancel        bool
		traceError    bool
		resend        bool
		success       bool
	}{
		{name: "fresh_get", method: http.MethodGet},
		{name: "fresh_post", method: http.MethodPost},
		{name: "reused_get", warm: true, method: http.MethodGet, resend: true, success: true},
		{name: "reused_post", warm: true, method: http.MethodPost, resend: true, success: true},
		{name: "reset_reused_post", warm: true, method: http.MethodPost, reset: true, resend: true, success: true},
		{name: "closed_twice", warm: true, method: http.MethodPost, alwaysClose: true, resend: true},
		{name: "early_hints", warm: true, method: http.MethodPost, informational: http.StatusEarlyHints},
		{name: "continue", warm: true, method: http.MethodPost, informational: http.StatusContinue},
		{name: "final_headers", warm: true, method: http.MethodPost, finalHeaders: true, success: true},
		{name: "unreplayable_body", warm: true, method: http.MethodPost, noGetBody: true},
		{name: "get_body_error", warm: true, method: http.MethodPost, getBodyError: true},
		{name: "cancelled", warm: true, method: http.MethodPost, cancel: true},
		{name: "trace_rejects_early_hints", warm: true, method: http.MethodPost, informational: http.StatusEarlyHints, traceError: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var attempts, connections, h1Requests, traceCalls, infoCalls atomic.Int32
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			payload := ""
			if tc.method == http.MethodPost {
				payload = strings.Repeat("payload=body&", 128)
			}
			bodies := make(chan string, 4)
			informationalSeen := make(chan struct{})
			finalHeadersSeen := make(chan struct{})
			var informationalOnce, finalHeadersOnce sync.Once
			ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.ProtoMajor != 2 {
					h1Requests.Add(1)
					w.WriteHeader(http.StatusOK)
					return
				}
				if r.URL.Path == "/warmup" {
					_, _ = io.WriteString(w, "warm")
					return
				}
				number := attempts.Add(1)
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Errorf("read request body: %v", err)
					return
				}
				bodies <- r.Method + "\n" + string(body)
				if number == 1 || tc.alwaysClose {
					if tc.informational != 0 {
						w.WriteHeader(tc.informational)
						// Wait until the client receives 1xx before closing TCP;
						// otherwise the server's queued frame can be discarded.
						select {
						case <-informationalSeen:
						case <-r.Context().Done():
						case <-time.After(3 * time.Second):
							t.Error("client did not receive informational response")
						}
					}
					if tc.finalHeaders {
						w.Header().Set("Content-Length", "100")
						w.WriteHeader(http.StatusOK)
						w.(http.Flusher).Flush()
						select {
						case <-finalHeadersSeen:
						case <-time.After(3 * time.Second):
							t.Error("client did not receive final headers")
						}
					}
					if tc.cancel {
						cancel()
					}
					conn := r.Context().Value(resendConnKey{}).(net.Conn)
					if tc.reset {
						for {
							wrapped, ok := conn.(interface{ NetConn() net.Conn })
							if !ok {
								break
							}
							conn = wrapped.NetConn()
						}
						tcp, ok := conn.(*net.TCPConn)
						if !ok {
							t.Errorf("expected TCP connection, got %T", conn)
						} else {
							_ = tcp.SetLinger(0)
						}
					}
					_ = conn.Close()
					return
				}
				_, _ = w.Write(body)
			}))
			ts.EnableHTTP2 = true
			ts.Config.ConnContext = func(ctx context.Context, conn net.Conn) context.Context {
				connections.Add(1)
				return context.WithValue(ctx, resendConnKey{}, conn)
			}
			ts.StartTLS()
			defer ts.Close()
			client := surf.NewClient().Builder().JA().Chrome158().Timeout(5 * time.Second).Build().Unwrap()
			defer client.CloseIdleConnections()
			if tc.warm {
				warmup := client.Get(g.String(ts.URL + "/warmup")).Do()
				if warmup.IsErr() {
					t.Fatal(warmup.Err())
				}
				if body := warmup.Ok().Body.String(); body.IsErr() {
					t.Fatal(body.Err())
				}
			}
			var request *surf.Request
			if tc.method == http.MethodPost {
				if tc.noGetBody {
					request = client.Post(g.String(ts.URL)).Body(io.NopCloser(strings.NewReader(payload)))
				} else {
					request = client.Post(g.String(ts.URL)).Body(payload)
				}
			} else {
				request = client.Get(g.String(ts.URL))
			}
			bodyErr := errors.New("GetBody failed")
			if tc.getBodyError {
				request.GetRequest().GetBody = func() (io.ReadCloser, error) { return nil, bodyErr }
			}
			userTraceErr := errors.New("user rejected informational response")
			trace := &httptrace.ClientTrace{
				GotFirstResponseByte: func() { finalHeadersOnce.Do(func() { close(finalHeadersSeen) }) },
				GotConn:              func(httptrace.GotConnInfo) { traceCalls.Add(1) },
				Got1xxResponse: func(_ int, _ textproto.MIMEHeader) error {
					infoCalls.Add(1)
					informationalOnce.Do(func() { close(informationalSeen) })
					if tc.traceError {
						return userTraceErr
					}
					return nil
				},
			}
			request.WithContext(httptrace.WithClientTrace(ctx, trace))
			response := request.Do()
			if tc.success {
				if response.IsErr() {
					t.Fatalf("expected success, got %v", response.Err())
				}
				body := response.Ok().Body.String()
				if tc.finalHeaders {
					if !body.IsErr() {
						t.Fatal("expected truncated response body")
					}
				} else if body.IsErr() || body.Ok().Std() != payload {
					t.Fatalf("retry changed body: got %v, err=%v", body, body.Err())
				}
			} else {
				if !response.IsErr() {
					response.Ok().Body.Close()
					t.Fatal("expected request error")
				}
				if tc.getBodyError && !errors.Is(response.Err(), bodyErr) {
					t.Fatalf("lost GetBody error: %v", response.Err())
				}
				if tc.cancel && !errors.Is(response.Err(), context.Canceled) {
					t.Fatalf("lost cancellation: %v", response.Err())
				}
				if tc.noGetBody && !strings.Contains(response.Err().Error(), "GetBody is nil") {
					t.Fatalf("expected unreplayable body error: %v", response.Err())
				}
				if tc.traceError && !strings.Contains(response.Err().Error(), userTraceErr.Error()) {
					t.Fatalf("lost trace callback error: %v", response.Err())
				}
			}
			want := int32(1)
			if tc.resend {
				want = 2
			}
			if n := attempts.Load(); n != want {
				t.Fatalf("expected %d request attempts, got %d", want, n)
			}
			if n := connections.Load(); n != want {
				t.Fatalf("expected %d connections, got %d", want, n)
			}
			if n := h1Requests.Load(); n != 0 {
				t.Fatalf("unexpected %d HTTP/1.1 requests", n)
			}
			if n := traceCalls.Load(); n != want {
				t.Fatalf("caller GotConn hook: expected %d calls, got %d", want, n)
			}
			if tc.informational != 0 && infoCalls.Load() != 1 {
				t.Fatalf("caller Got1xxResponse hook: got %d calls", infoCalls.Load())
			}
			for range want {
				select {
				case got := <-bodies:
					if expected := tc.method + "\n" + payload; got != expected {
						t.Fatalf("sent wrong method or body: got %q, want %q", got, expected)
					}
				default:
					t.Fatal("missing received body")
				}
			}
		})
	}
}

func TestRoundTripperDoesNotResendDialConnectionErrors(t *testing.T) {
	t.Parallel()
	for _, dialErr := range []error{io.ErrUnexpectedEOF, &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNRESET}} {
		t.Run(dialErr.Error(), func(t *testing.T) {
			var calls atomic.Int32
			client := surf.NewClient().Builder().With(func(c *surf.Client) error {
				c.GetTransport().(*http.Transport).DialContext = func(context.Context, string, string) (net.Conn, error) { calls.Add(1); return nil, dialErr }
				return nil
			}).JA().Chrome158().Build().Unwrap()
			response := client.Get("https://example.invalid/").Do()
			if !response.IsErr() || !errors.Is(response.Err(), dialErr) {
				t.Fatalf("expected original dial error, got %v", response.Err())
			}
			if n := calls.Load(); n != 1 {
				t.Fatalf("expected one dial, got %d", n)
			}
		})
	}
}

type burstConnKey struct{}
type burstConn struct {
	conn net.Conn
	id   int32
}

func TestRoundTripperResendsOtherStreamsAfterBlockResponse(t *testing.T) {
	t.Parallel()
	const requests = 4
	var connections, initialRequests, totalRequests, h1Requests atomic.Int32
	var freshRequestChosen atomic.Bool
	var freshPayload atomic.Value
	allArrived := make(chan struct{})
	blockRead := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			h1Requests.Add(1)
			w.WriteHeader(http.StatusOK)
			return
		}
		totalRequests.Add(1)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read burst body: %v", err)
			return
		}
		info := r.Context().Value(burstConnKey{}).(burstConn)
		if info.id != 1 {
			_, _ = w.Write(body)
			return
		}
		number := initialRequests.Add(1)
		if number == requests {
			close(allArrived)
		}
		select {
		case <-allArrived:
		case <-r.Context().Done():
			return
		}
		// Handler arrival order can differ from stream creation order. Give
		// the 403 to the request that actually opened the fresh connection.
		if string(body) != freshPayload.Load().(string) {
			<-r.Context().Done()
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, "blocked")
		// Wait until the 403 body reaches its caller before closing the shared
		// connection and interrupting the other three in-flight streams.
		go func() {
			select {
			case <-blockRead:
				_ = info.conn.Close()
			case <-ctx.Done():
			}
		}()
	}))
	ts.EnableHTTP2 = true
	ts.Config.ConnContext = func(ctx context.Context, conn net.Conn) context.Context {
		return context.WithValue(ctx, burstConnKey{}, burstConn{conn, connections.Add(1)})
	}
	ts.StartTLS()
	defer ts.Close()
	defer cancel()
	client := surf.NewClient().Builder().JA().Chrome158().Timeout(5 * time.Second).Build().Unwrap()
	defer client.CloseIdleConnections()
	type result struct {
		status         int
		body, expected string
		err            error
	}
	results := make(chan result, requests)
	for i := range requests {
		go func() {
			payload := strings.Repeat("body", i+1)
			trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
				if !info.Reused && freshRequestChosen.CompareAndSwap(false, true) {
					freshPayload.Store(payload)
				}
			}}
			requestCtx := httptrace.WithClientTrace(ctx, trace)
			response := client.Post(g.String(ts.URL)).Body(payload).WithContext(requestCtx).Do()
			if response.IsErr() {
				results <- result{err: response.Err()}
				return
			}
			body := response.Ok().Body.String()
			if body.IsErr() {
				results <- result{err: body.Err()}
				return
			}
			status := int(response.Ok().StatusCode)
			if status == http.StatusForbidden {
				close(blockRead)
			}
			results <- result{status: status, body: body.Ok().Std(), expected: payload}
		}()
	}
	statuses := map[int]int{}
	for range requests {
		got := <-results
		if got.err != nil {
			t.Fatal(got.err)
		}
		statuses[got.status]++
		if got.status == http.StatusOK && got.body != got.expected {
			t.Fatalf("resent body=%q, want %q", got.body, got.expected)
		}
	}
	if statuses[http.StatusForbidden] != 1 || statuses[http.StatusOK] != 3 {
		t.Fatalf("expected one 403 and three 200s, got %v", statuses)
	}
	if n := initialRequests.Load(); n != requests {
		t.Fatalf("expected %d initial streams, got %d", requests, n)
	}
	if n := totalRequests.Load(); n != 7 {
		t.Fatalf("expected 4 initial requests and 3 resends, got %d", n)
	}
	if n := connections.Load(); n < 2 {
		t.Fatalf("expected replacement HTTP/2 connection, got %d", n)
	}
	if n := h1Requests.Load(); n != 0 {
		t.Fatalf("unexpected HTTP/1.1 requests: %d", n)
	}
}

func TestRoundTripperDoesNotResendFailedDialAfterReusedGoAway(t *testing.T) {
	t.Parallel()
	var dials, h1Requests atomic.Int32
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { h1Requests.Add(1); w.WriteHeader(http.StatusOK) }))
	ts.EnableHTTP2 = true
	ts.Config.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){
		"h2": func(_ *http.Server, conn *tls.Conn, _ http.Handler) {
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			preface := make([]byte, len(http2.ClientPreface))
			if _, err := io.ReadFull(conn, preface); err != nil {
				return
			}
			fr := http2.NewFramer(conn, conn)
			if err := fr.WriteSettings(); err != nil {
				return
			}
			for {
				frame, err := fr.ReadFrame()
				if err != nil {
					return
				}
				switch f := frame.(type) {
				case *http2.SettingsFrame:
					if !f.IsAck() {
						_ = fr.WriteSettingsAck()
					}
				case *http2.HeadersFrame:
					if f.StreamID != 1 {
						// http2 internally retries a stream above the GOAWAY last-stream ID.
						_ = fr.WriteGoAway(1, http2.ErrCodeNo, nil)
						return
					}
					var block bytes.Buffer
					_ = hpack.NewEncoder(&block).WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
					_ = fr.WriteHeaders(http2.HeadersFrameParam{StreamID: f.StreamID, BlockFragment: block.Bytes(), EndHeaders: true, EndStream: true})
				}
			}
		},
	}
	ts.StartTLS()
	defer ts.Close()
	client := surf.NewClient().Builder().With(func(c *surf.Client) error {
		tr := c.GetTransport().(*http.Transport)
		dial := tr.DialContext
		tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			if dials.Add(1) > 1 {
				return nil, io.ErrUnexpectedEOF
			}
			return dial(ctx, network, address)
		}
		return nil
	}).JA().Chrome158().Timeout(5 * time.Second).Build().Unwrap()
	warmup := client.Get(g.String(ts.URL)).Do()
	if warmup.IsErr() {
		t.Fatal(warmup.Err())
	}
	warmup.Ok().Body.Close()
	response := client.Get(g.String(ts.URL)).Do()
	if !response.IsErr() || !errors.Is(response.Err(), io.ErrUnexpectedEOF) {
		t.Fatalf("lost failed-dial error: %v", response.Err())
	}
	if n := dials.Load(); n != 2 {
		t.Fatalf("expected initial dial plus one internal reconnect, got %d", n)
	}
	if n := h1Requests.Load(); n != 0 {
		t.Fatalf("unexpected HTTP/1.1 request: %d", n)
	}
}
