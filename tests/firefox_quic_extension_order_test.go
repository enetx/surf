package surf_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/enetx/http/httptest"
	"github.com/enetx/surf/internal/quictls"
	"github.com/enetx/surf/profiles/firefox/desktop"
	firefox "github.com/enetx/surf/profiles/firefox/quic"
	utls "github.com/enetx/utls"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/cryptobyte"
)

func firefoxQUICNativeExtensions(t *testing.T) []uint16 {
	t.Helper()
	var native struct {
		TLS struct {
			Extensions []uint16 `json:"extensions"`
		} `json:"tls"`
	}
	raw, err := os.ReadFile("testdata/wire/firefox_160_http3.json")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &native))
	require.NotEmpty(t, native.TLS.Extensions)
	return native.TLS.Extensions
}

// Decode the emitted ClientHello without sorting its extensions. Presence comes
// from the retained independent native capture; the fixed tail follows NSS's
// custom-writer/EmplaceExtension sequence, also seen in four fresh Firefox 160
// captures. The native fixture remains unchanged.
func firefoxQUICWireExtensionOrder(t *testing.T, raw []byte) ([]uint16, map[uint16][]byte) {
	t.Helper()
	require.GreaterOrEqual(t, len(raw), 38)
	require.Equal(t, byte(1), raw[0])
	b := cryptobyte.String(raw[38:])
	var session, ciphers, compression, extensions cryptobyte.String
	require.True(t, b.ReadUint8LengthPrefixed(&session))
	require.Empty(t, session, "QUIC's legacy session ID is empty")
	require.True(t, b.ReadUint16LengthPrefixed(&ciphers))
	require.True(t, b.ReadUint8LengthPrefixed(&compression))
	require.True(t, b.ReadUint16LengthPrefixed(&extensions))
	require.True(t, b.Empty())
	var order []uint16
	values := make(map[uint16][]byte)
	for !extensions.Empty() {
		var id uint16
		var value cryptobyte.String
		require.True(t, extensions.ReadUint16(&id))
		require.True(t, extensions.ReadUint16LengthPrefixed(&value))
		_, duplicate := values[id]
		require.False(t, duplicate, "duplicate extension %d", id)
		order = append(order, id)
		values[id] = bytes.Clone(value)
	}
	return order, values
}

func assertFirefoxQUICTail(t *testing.T, order []uint16, resumed, early bool) {
	t.Helper()
	tail := []uint16{57, 65037}
	if resumed {
		tail = append(tail, 41)
	}
	require.GreaterOrEqual(t, len(order), len(tail))
	require.Equal(t, tail, order[len(order)-len(tail):], "unmodified wire order: %v", order)
	want := slices.Clone(firefoxQUICNativeExtensions(t))
	if resumed {
		want = append(want, 41)
	}
	if early {
		want = append(want, 42)
		require.Less(t, slices.Index(order, uint16(42)), slices.Index(order, uint16(57)),
			"early_data is a permuted NSS built-in, before the custom QUIC writer")
	}
	slices.Sort(want)
	actual := slices.Clone(order)
	slices.Sort(actual)
	require.Equal(t, want, actual)
}

func TestFirefoxQUICFreshExtensionOrder(t *testing.T) {
	orders := make(map[string]bool)
	earlyPositions := make(map[int]bool)
	for range 32 {
		spec, err := firefox.NewClientHelloSpec()
		require.NoError(t, err)
		for index, extension := range spec.Extensions {
			switch extension.(type) {
			case *utls.EarlyDataExtension:
				earlyPositions[index] = true
				require.Less(t, index, len(spec.Extensions)-3, "early_data must participate in the builtin permutation")
			case utls.PreSharedKeyExtension:
				require.Equal(t, len(spec.Extensions)-1, index, "wrapped PSK must remain last")
			}
		}
		hello := func() []byte {
			client, err := quictls.Factory(firefox.NewClientHelloSpec, desktop.ClientHelloInner)(&tls.Config{
				ServerName: "fp.impersonate.pro", NextProtos: []string{"h3"},
			})
			require.NoError(t, err)
			defer client.Close()
			client.SetTransportParameters([]byte{15, 0})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			require.NoError(t, client.Start(ctx))
			var hello []byte
			for event := client.NextEvent(); event.Kind != tls.QUICNoEvent; event = client.NextEvent() {
				require.NotEqual(t, tls.QUICErrorEvent, event.Kind, "%v", event.Err)
				if event.Kind == tls.QUICWriteData && event.Level == tls.QUICEncryptionLevelInitial {
					hello = append(hello, event.Data...)
				}
			}
			return hello
		}()
		order, _ := firefoxQUICWireExtensionOrder(t, hello)
		assertFirefoxQUICTail(t, order, false, false)
		orders[fmt.Sprint(order[:len(order)-2])] = true
	}
	require.Greater(t, len(orders), 1, "builtin extension order did not vary")
	require.Greater(t, len(earlyPositions), 1, "early_data was pinned outside the builtin permutation")
}

type firefoxOrderHandshake struct {
	hello, earlyWrite, earlyRead []byte
	inner                        []uint16
	resumed, echAccepted         bool
}

// Negotiate actual QUIC TLS handshakes against Go's independent TLS server.
// Server acceptance checks the final PSK binder, including real ECH resumption.
func driveFirefoxOrderHandshake(t *testing.T, cc, sc *tls.Config, early bool) firefoxOrderHandshake {
	t.Helper()
	client, err := quictls.Factory(firefox.NewClientHelloSpec, desktop.ClientHelloInner)(cc)
	require.NoError(t, err)
	defer client.Close()
	client.SetTransportParameters([]byte{15, 0, 4, 1, 16})
	out := firefoxOrderHandshake{}
	serverConfig := sc.Clone()
	serverConfig.GetConfigForClient = func(h *tls.ClientHelloInfo) (*tls.Config, error) {
		out.inner = slices.Clone(h.Extensions)
		return nil, nil
	}
	server := tls.QUICServer(&tls.QUICConfig{TLSConfig: serverConfig, EnableSessionEvents: true})
	defer server.Close()
	server.SetTransportParameters([]byte{15, 1, 1})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, client.Start(ctx))
	require.NoError(t, server.Start(ctx))
	clientDone, serverDone := false, false
	for range 1000 {
		progress := false
		for _, fromClient := range []bool{true, false} {
			for {
				var event tls.QUICEvent
				if fromClient {
					event = client.NextEvent()
				} else {
					event = server.NextEvent()
				}
				if event.Kind == tls.QUICNoEvent {
					break
				}
				progress = true
				switch event.Kind {
				case tls.QUICWriteData:
					if fromClient {
						if event.Level == tls.QUICEncryptionLevelInitial {
							out.hello = append(out.hello, event.Data...)
						}
						require.NoError(t, server.HandleData(event.Level, event.Data))
					} else {
						require.NoError(t, client.HandleData(event.Level, event.Data))
					}
				case tls.QUICResumeSession:
					if fromClient && !early {
						event.SessionState.EarlyData = false
					}
				case tls.QUICStoreSession:
					if fromClient {
						event.SessionState.Extra = append(event.SessionState.Extra, []byte("extension-order"))
						require.NoError(t, client.StoreSession(event.SessionState))
					}
				case tls.QUICHandshakeDone:
					if fromClient {
						clientDone = true
					} else {
						serverDone = true
						require.NoError(t, server.SendSessionTicket(tls.QUICSessionTicketOptions{EarlyData: true}))
					}
				case tls.QUICSetWriteSecret:
					if fromClient && event.Level == tls.QUICEncryptionLevelEarly {
						out.earlyWrite = bytes.Clone(event.Data)
					}
				case tls.QUICSetReadSecret:
					if !fromClient && event.Level == tls.QUICEncryptionLevelEarly {
						out.earlyRead = bytes.Clone(event.Data)
					}
				case tls.QUICErrorEvent:
					t.Fatal(event.Err)
				}
			}
		}
		if !progress {
			require.True(t, clientDone && serverDone, "handshake did not complete")
			require.Equal(t, client.ConnectionState().DidResume, server.ConnectionState().DidResume)
			out.resumed = client.ConnectionState().DidResume
			out.echAccepted = client.ConnectionState().ECHAccepted
			return out
		}
	}
	t.Fatal("QUIC TLS event limit reached")
	return out
}

func TestFirefoxQUICResumedExtensionOrder(t *testing.T) {
	for _, realECH := range []bool{false, true} {
		for _, early := range []bool{false, true} {
			t.Run(fmt.Sprintf("ECH=%v/early=%v", realECH, early), func(t *testing.T) {
				certificate := httptest.NewTLSServer(nil)
				t.Cleanup(certificate.Close)
				roots := x509.NewCertPool()
				roots.AddCert(certificate.Certificate())
				cc := &tls.Config{ServerName: "example.com", RootCAs: roots, NextProtos: []string{"h3"},
					ClientSessionCache: tls.NewLRUClientSessionCache(4)}
				sc := certificate.TLS.Clone()
				sc.NextProtos = []string{"h3"}
				sc.MinVersion = tls.VersionTLS13
				sc.SetSessionTicketKeys([][32]byte{{1, 2, 3}})
				if realECH {
					list, key := testECHConfig(t)
					cc.EncryptedClientHelloConfigList = list
					sc.EncryptedClientHelloKeys = []tls.EncryptedClientHelloKey{key}
				}
				for attempt := range 3 {
					got := driveFirefoxOrderHandshake(t, cc, sc, early)
					resumed := attempt > 0
					require.Equal(t, resumed, got.resumed, "attempt %d", attempt)
					require.Equal(t, realECH, got.echAccepted)
					order, _ := firefoxQUICWireExtensionOrder(t, got.hello)
					assertFirefoxQUICTail(t, order, resumed, resumed && early)
					if resumed && early {
						require.NotEmpty(t, got.earlyWrite)
						require.Equal(t, got.earlyWrite, got.earlyRead)
					} else {
						require.Empty(t, got.earlyWrite)
						require.Empty(t, got.earlyRead)
					}
					if realECH {
						require.Equal(t, uint16(65037), got.inner[0], "NSS inner ECH marker is first")
						if resumed {
							require.Equal(t, uint16(41), got.inner[len(got.inner)-1], "inner PSK binder is last")
						}
					}
				}
			})
		}
	}
}
