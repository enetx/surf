package surf_test

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/textproto"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/http/httptest"
	"github.com/enetx/http/httptrace"
	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/http3"
	"github.com/stretchr/testify/require"
)

type responseConnKey struct{}

// The same authority serves TCP and QUIC so an accidental fallback is visible
// as an actual second request. Synchronization keeps connection closure from
// discarding the response headers before the client sees them.
func TestHTTP3ResponseProgressPreventsReplay(t *testing.T) {
	for _, browser := range []string{"native", "chrome", "firefox"} {
		for _, scenario := range []string{"before-headers", "100", "103", "trace-error", "callback-error", "final-error", "success"} {
			t.Run(browser+"/"+scenario, func(t *testing.T) {
				var tcpRequests, traces, observations atomic.Int32
				seen := make(chan struct{})
				var once sync.Once
				signal := func() { once.Do(func() { close(seen) }) }
				handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.ProtoMajor != 3 {
						tcpRequests.Add(1)
						io.WriteString(w, "tcp")
						return
					}
					if scenario != "before-headers" {
						code := http.StatusEarlyHints
						if scenario == "final-error" {
							code = http.StatusOK
						}
						if scenario == "100" {
							code = http.StatusContinue
						}
						w.WriteHeader(code)
						if code == http.StatusOK {
							w.(http.Flusher).Flush()
						}
						select {
						case <-seen:
						case <-r.Context().Done():
							return
						}
					}
					if scenario == "trace-error" || scenario == "callback-error" || scenario == "final-error" {
						<-r.Context().Done()
						return
					}
					if scenario == "success" {
						io.WriteString(w, "quic")
						return
					}
					r.Context().Value(responseConnKey{}).(*quic.Conn).CloseWithError(0x102, "test closes response")
				})
				tcp := httptest.NewUnstartedServer(handler)
				udp := reserveRacingUDP(t, tcp)
				tcp.StartTLS()
				defer tcp.Close()
				server := &http3.Server{Handler: handler, TLSConfig: tcp.TLS.Clone(),
					ConnContext: func(ctx context.Context, conn *quic.Conn) context.Context {
						return context.WithValue(ctx, responseConnKey{}, conn)
					},
				}
				go server.Serve(udp)
				defer udp.Close()
				defer server.Close()
				// A recoverable transport error returned by a callback still must
				// abort rather than replay a transaction whose headers were received.
				callbackError := &quic.ApplicationError{ErrorCode: 0x102, ErrorMessage: "callback rejected response"}
				traceError := errors.New("trace rejected response")
				builder := discoveryBuilder(browser).Proxy("").ForceHTTP3().
					TLSConfig(&tls.Config{InsecureSkipVerify: true}).Timeout(10 * time.Second)
				builder.HTTP3Settings().ConnectionRacing(false).OnResponseHeaders(func(_ *http.Request, response *http.Response) error {
					observations.Add(1)
					if scenario == "callback-error" || scenario == "final-error" {
						signal()
						return callbackError
					}
					return nil
				}).Set()
				client := builder.Build().Unwrap()
				defer client.Close()
				trace := &httptrace.ClientTrace{Got1xxResponse: func(int, textproto.MIMEHeader) error {
					traces.Add(1)
					signal()
					if scenario == "trace-error" {
						return traceError
					}
					return nil
				}}
				result := client.Get(g.String(tcp.URL)).WithContext(httptrace.WithClientTrace(t.Context(), trace)).Do()
				if scenario == "before-headers" || scenario == "success" {
					require.False(t, result.IsErr(), "%v", result.Err())
					response := result.Unwrap()
					want := g.String("quic")
					if scenario == "before-headers" {
						want = "tcp"
					}
					require.Equal(t, want, response.Body.String().Unwrap())
				} else {
					require.True(t, result.IsErr())
					if scenario == "trace-error" {
						require.ErrorIs(t, result.Err(), traceError)
					}
					if scenario == "callback-error" || scenario == "final-error" {
						require.ErrorIs(t, result.Err(), callbackError)
					}
				}
				if scenario == "before-headers" {
					require.EqualValues(t, 1, tcpRequests.Load())
					require.Zero(t, observations.Load())
					require.Zero(t, traces.Load())
				} else {
					require.Zero(t, tcpRequests.Load(), "received response must prevent TCP replay")
					want := int32(1)
					if scenario == "success" {
						want = 2
					}
					require.Equal(t, want, observations.Load())
					if scenario == "callback-error" || scenario == "final-error" {
						require.Zero(t, traces.Load())
					} else {
						require.EqualValues(t, 1, traces.Load())
					}
				}
			})
		}
	}
}
