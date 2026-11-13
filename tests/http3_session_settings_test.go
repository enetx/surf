package surf_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/http/httptest"
	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/http3"
	"github.com/enetx/quic-go/qlogwriter"
	"github.com/enetx/quic-go/quicvarint"
	"github.com/enetx/surf"
	"github.com/stretchr/testify/require"
)

type settingsLegacyCache struct{ tls.ClientSessionCache }

func (c settingsLegacyCache) Put(key string, session *tls.ClientSessionState) {
	if session != nil {
		ticket, state, err := session.ResumptionState()
		if err != nil {
			return
		}
		data, err := state.Bytes()
		if err != nil {
			return
		}
		state, err = tls.ParseSessionState(data)
		if err != nil {
			return
		}
		state.Extra = slices.DeleteFunc(state.Extra, func(extra []byte) bool { return bytes.HasPrefix(extra, []byte("quic-go h3 peer settings v1\x00")) })
		session, err = tls.NewResumptionState(ticket, state)
		if err != nil {
			return
		}
	}
	c.ClientSessionCache.Put(key, session)
}

// A raw QUIC listener deliberately does not wrap tickets with HTTP/3 server
// compatibility checks. It can accept early data then send incompatible SETTINGS,
// exercising the client's independent RFC 9114 / RFC 9204 checks on actual packets.
func TestHTTP3TicketSettingsResumptionOnWire(t *testing.T) {
	for _, browser := range []string{"native", "chrome", "firefox"} {
		for _, scenario := range []string{"same", "new-table", "larger-blocked", "smaller-blocked", "changed-capacity", "smaller-capacity", "smaller-fields", "rejected", "disabled", "missing-state"} {
			t.Run(browser+"/"+scenario, func(t *testing.T) {
				bad := scenario == "smaller-blocked" || scenario == "changed-capacity" || scenario == "smaller-capacity" || scenario == "smaller-fields"
				offersEarly := scenario != "disabled" && scenario != "missing-state"
				cert := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
				tlsConfig := cert.TLS.Clone()
				cert.Close()
				tlsConfig.NextProtos = []string{"h3"}
				var handshakes atomic.Int32
				sentEarly := make(chan struct{})
				tlsConfig.GetConfigForClient = func(info *tls.ClientHelloInfo) (*tls.Config, error) {
					if handshakes.Add(1) > 1 && offersEarly {
						select {
						case <-sentEarly:
						case <-time.After(5 * time.Second):
							return nil, errors.New("client did not offer remembered 0-RTT data")
						case <-info.Context().Done():
							return nil, info.Context().Err()
						}
					}
					return nil, nil
				}
				var reject atomic.Bool
				tlsConfig.UnwrapSession = func(identity []byte, state tls.ConnectionState) (*tls.SessionState, error) {
					ss, err := tlsConfig.DecryptTicket(identity, state)
					if ss != nil && reject.Load() {
						ss.EarlyData = false
					}
					return ss, err
				}
				pc, err := net.ListenPacket("udp", "127.0.0.1:0")
				require.NoError(t, err)
				listener, err := quic.ListenEarly(pc, tlsConfig, &quic.Config{Allow0RTT: true})
				require.NoError(t, err)
				t.Cleanup(func() { listener.Close(); pc.Close() })
				var connections atomic.Int32
				closed := make(chan error, 8)
				type observation struct{ resumed, early bool }
				observed := make(chan observation, 8)
				go func() {
					for {
						conn, err := listener.Accept(t.Context())
						if err != nil {
							return
						}
						n := connections.Add(1)
						capacity, blocked, fields := uint64(4096), uint64(16), 4096
						if n == 1 && scenario == "new-table" {
							capacity, blocked = 0, 0
						}
						if n > 1 {
							switch scenario {
							case "larger-blocked":
								blocked = 32
							case "smaller-blocked":
								blocked = 1
							case "changed-capacity":
								capacity = 8192
							case "smaller-capacity":
								capacity = 1024
							case "smaller-fields":
								fields = 2048
							case "rejected", "disabled", "missing-state":
								capacity, blocked, fields = 1024, 1, 2048
							}
						}
						settings := g.NewMapOrd[uint64, uint64]()
						settings.Insert(1, capacity)
						settings.Insert(7, blocked)
						bad := n > 1 && bad
						server := &http3.Server{AdditionalSettings: settings, MaxHeaderBytes: fields,
							Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
								if bad {
									<-conn.Context().Done()
									return
								}
								observed <- observation{r.TLS.DidResume, conn.ConnectionState().Used0RTT}
								io.WriteString(w, "ok")
							})}
						go func() {
							defer conn.CloseWithError(0, "")
							// Publish SETTINGS after the handshake, so the peer can send
							// an application close instead of a Handshake-level close.
							select {
							case <-conn.HandshakeComplete():
							case <-conn.Context().Done():
								return
							}
							if bad {
								// A deliberately inconsistent peer must not decode the old
								// early QPACK instructions with its new limits first.
								stream, err := conn.OpenUniStreamSync(t.Context())
								if err != nil {
									closed <- err
									return
								}
								var payload []byte
								for _, pair := range [][2]uint64{{1, capacity}, {7, blocked}, {6, uint64(fields)}, {8, 1}} {
									payload = quicvarint.Append(quicvarint.Append(payload, pair[0]), pair[1])
								}
								data := quicvarint.Append(quicvarint.Append(nil, 0), 4)
								_, err = stream.Write(append(quicvarint.Append(data, uint64(len(payload))), payload...))
								if err != nil {
									closed <- err
									return
								}
								<-conn.Context().Done()
								closed <- context.Cause(conn.Context())
								return
							}
							server.ServeQUICConn(conn)
							closed <- context.Cause(conn.Context())
						}()
					}
				}()
				cache := &h3SessionCache{ClientSessionCache: tls.NewLRUClientSessionCache(8), stored: make(chan struct{}, 32)}
				if scenario == "missing-state" {
					cache.ClientSessionCache = settingsLegacyCache{cache.ClientSessionCache}
				}
				b := surf.NewClient().Builder().Proxy("")
				if browser == "chrome" {
					b.Impersonate().Chrome()
				} else if browser == "firefox" {
					b.Impersonate().Firefox()
				}
				var once sync.Once
				b.QUICSettings().Tracer(func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
					return &earlyTrace{streams: make(map[quic.StreamID]bool), onEarly: func() { once.Do(func() { close(sentEarly) }) }}
				}).Set()
				client := b.ForceHTTP3().HTTP3Settings().EarlyData(scenario != "disabled").Set().
					TLSConfig(&tls.Config{InsecureSkipVerify: true, ClientSessionCache: cache}).Timeout(8 * time.Second).Build().Unwrap()
				t.Cleanup(func() { client.Close() })
				origin := g.String("https://" + pc.LocalAddr().String())
				first := client.Get(origin).Do()
				require.False(t, first.IsErr(), "%v", first.Err())
				require.Equal(t, g.String("ok"), first.Unwrap().Body.String().Unwrap())
				initial := <-observed
				require.False(t, initial.resumed)
				select {
				case <-cache.stored:
				case <-time.After(5 * time.Second):
					t.Fatal("ticket never reached application cache")
				}
				client.GetClient().CloseIdleConnections()
				<-closed
				reject.Store(scenario == "rejected")
				second := client.Get(origin).Do()
				if bad {
					require.True(t, second.IsErr(), "incompatible accepted 0-RTT must close the connection")
					select {
					case reason := <-closed:
						var applicationError *quic.ApplicationError
						if !errors.As(reason, &applicationError) {
							t.Fatalf("expected peer HTTP/3 application error, got %T: %v", reason, reason)
						}
						code := http3.ErrCodeSettingsError
						if scenario == "changed-capacity" && browser != "chrome" || scenario == "smaller-capacity" && browser == "native" {
							code = http3.ErrCodeQPACKDecoderStreamError
						}
						require.EqualValues(t, code, applicationError.ErrorCode)
						t.Logf("peer decoded HTTP/3 close: %#x", applicationError.ErrorCode)
					case <-time.After(5 * time.Second):
						t.Fatal("missing SETTINGS rejection")
					}
					return
				}
				require.False(t, second.IsErr(), "%v", second.Err())
				require.Equal(t, g.String("ok"), second.Unwrap().Body.String().Unwrap())
				got := <-observed
				require.True(t, got.resumed)
				require.Equal(t, offersEarly && scenario != "rejected", got.early)
				if browser == "firefox" && scenario == "rejected" {
					require.EqualValues(t, 2, connections.Load(), "rejected 0-RTT must restart HTTP/3 on the existing QUIC connection")
				}
				t.Logf("resumed=%t early=%t connections=%d", got.resumed, got.early, connections.Load())
			})
		}
	}
}
