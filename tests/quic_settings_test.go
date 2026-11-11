package surf_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"os"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/qlogwriter"
	"github.com/enetx/quic-go/quicvarint"
	"github.com/enetx/quic-go/tlsquic"
	"github.com/enetx/quic-go/transportparams"
	"github.com/enetx/surf"
	utls "github.com/enetx/utls"
	"github.com/stretchr/testify/require"
)

func quicWireParameters(t *testing.T, peer *h3Peer) ([]uint64, map[uint64][]byte, uint64) {
	t.Helper()
	hello, number := h3CapturedHello(t, peer)
	r := bytes.NewReader(h3HelloExtensions(t, hello)[57])
	var order []uint64
	values := make(map[uint64][]byte)
	for r.Len() > 0 {
		id, err := quicvarint.Read(r)
		require.NoError(t, err)
		length, err := quicvarint.Read(r)
		require.NoError(t, err)
		require.LessOrEqual(t, length, uint64(r.Len()))
		value := make([]byte, int(length))
		_, err = io.ReadFull(r, value)
		require.NoError(t, err)
		require.NotContains(t, values, id)
		order = append(order, id)
		values[id] = value
	}
	return order, values, number
}

func requireQUICParameter(t *testing.T, values map[uint64][]byte, id, want uint64) {
	t.Helper()
	require.Contains(t, values, id)
	value, n, err := quicvarint.Parse(values[id])
	require.NoError(t, err)
	require.Len(t, values[id], n)
	require.Equal(t, want, value, "transport parameter %d", id)
}

func TestQUICFluentSettingsOnWire(t *testing.T) {
	peer := newH3Peer(t)
	trace := new(h3Peer)
	versions := []quic.Version{quic.Version1}
	order := []uint64{15, 100, 7, 6, 5, 4, 3, 1, 8, 9, 11, 14, 32, 29}
	value := []byte("custom")
	template := h3QUICClientHello(t)
	builder := surf.NewClient().Builder()
	q := builder.QUICSettings().
		Versions(versions...).
		HandshakeIdleTimeout(2*time.Second).
		MaxIdleTimeout(21*time.Second).
		KeepAlivePeriod(0).
		InitialStreamReceiveWindow(128<<10).
		MaxStreamReceiveWindow(256<<10).
		InitialConnectionReceiveWindow(2<<20).
		MaxConnectionReceiveWindow(4<<20).
		AllowConnectionWindowIncrease(func(*quic.Conn, uint64) bool { return false }).
		MaxIncomingStreams(7).
		MaxIncomingUniStreams(11).
		RequireStreamCreditRelease(true).
		InitialPacketSize(1350).
		DisablePathMTUDiscovery(true).
		EnableDatagrams(true).
		EnableStreamResetPartialDelivery(true).
		TokenStore(quic.NewLRUTokenStore(4, 4)).
		Tracer(func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return trace }).
		ConnectionIDLength(8).
		ClientHelloSpec(&template).
		StreamReceiveWindows(256<<10, 0, 64<<10).
		OmitMaxUDPPayloadSize(true).
		MaxUDPPayloadSize(1480).
		MaxDatagramFrameSize(1200).
		MaxAckDelay(21*time.Millisecond).
		ActiveConnectionIDLimit(5).
		OmitLegacyResetStreamAt(true).
		InitialDestinationConnectionIDLength(12).
		InitialPacketNumber(17).
		DisableClientHelloScrambling(true).
		TransportParameterOrder(order...).
		TransportParameter(100, value).
		DisableTransportParameterGrease(true)
	// Setters must snapshot their slice/template arguments before Build.
	versions[0], order[0], value[0], template.CipherSuites[0] = quic.Version2, 4, 'X', 0
	client := q.Set().HTTP3Settings().StreamPriority(2, true).Set().
		ForceHTTP3().Timeout(5 * time.Second).Build().Unwrap()
	t.Cleanup(func() { client.Close() })
	// Reopening and editing the builder must not mutate an already-built transport.
	q.InitialPacketNumber(99).TransportParameter(100, []byte("changed"))
	builder.QUICSettings().MaxIdleTimeout(41 * time.Second)
	peer.request(t, client)
	gotOrder, values, number := quicWireParameters(t, peer)
	require.Equal(t, uint64(17), number)
	require.Equal(t, []uint64{15, 100, 7, 6, 5, 4, 3, 1, 8, 9, 11, 14, 32, 29}, gotOrder)
	require.Equal(t, []byte("custom"), values[100])
	for id, want := range map[uint64]uint64{
		1: 21000, 3: 1480, 4: 2 << 20, 5: 256 << 10, 6: 0, 7: 64 << 10,
		8: 7, 9: 11, 11: 21, 14: 5, 32: 1200,
	} {
		requireQUICParameter(t, values, id, want)
	}
	require.Contains(t, values, uint64(29))
	require.NotContains(t, values, uint64(0x17f7586d2cb571))
	peer.packet.mu.Lock()
	initial := bytes.Clone(peer.packet.rawInitials[0])
	peer.packet.mu.Unlock()
	require.EqualValues(t, 12, initial[5])
	require.EqualValues(t, 8, initial[6+int(initial[5])])
	require.Len(t, initial, 1350)
	trace.mu.Lock()
	priorities := slices.Clone(trace.priorities)
	trace.mu.Unlock()
	require.Len(t, priorities, 1)
	require.EqualValues(t, 2, priorities[0].Urgency)
}

func TestQUICFluentOverridesPreserveBrowserProfiles(t *testing.T) {
	for _, browser := range []string{"chrome", "firefox"} {
		t.Run(browser, func(t *testing.T) {
			peer := newH3Peer(t)
			builder := surf.NewClient().Builder()
			// A subsequent profile replaces earlier QUIC options, retaining the
			// already-registered HTTP/3 transport factory.
			builder.QUICSettings().TransportParameter(102, []byte("discarded")).Set()
			if browser == "chrome" {
				builder.Impersonate().Chrome()
			} else {
				builder.Impersonate().Firefox()
			}
			client := builder.QUICSettings().MaxIdleTimeout(43*time.Second).Set().
				QUICSettings().InitialPacketNumber(28).
				InitialStreamReceiveWindow(3<<20).
				TransportParameterOrder(15, 100).
				TransportParameter(100, []byte("override")).Set().
				ForceHTTP3().Timeout(5 * time.Second).Build().Unwrap()
			t.Cleanup(func() { client.Close() })
			capture := peer.request(t, client)
			order, values, number := quicWireParameters(t, peer)
			require.Equal(t, uint64(28), number, "fixed number must override Firefox's factory")
			require.Equal(t, []uint64{15, 100}, order[:2])
			require.Equal(t, []byte("override"), values[100])
			require.NotContains(t, values, uint64(102))
			require.Contains(t, values, uint64(17), "browser's version information must survive")
			for id, want := range map[uint64]uint64{1: 43000, 5: 3 << 20, 6: 3 << 20, 7: 3 << 20} {
				requireQUICParameter(t, values, id, want)
			}
			if browser == "chrome" {
				require.Equal(t, []byte("ORIG"), values[0x3128])
				requireQUICParameter(t, values, 3, 1472)
				requireQUICParameter(t, values, 4, 15<<20)
				requireQUICParameter(t, values, 32, 65536)
			} else {
				require.NotContains(t, values, uint64(3))
				requireQUICParameter(t, values, 4, 24<<20)
				requireQUICParameter(t, values, 32, 65535)
			}
			referenceName := "chrome_157_http3.json"
			if browser == "firefox" {
				referenceName = "firefox_160_http3.json"
			}
			// Existing independent fixtures also verify no H3 setting is lost.
			data, err := os.ReadFile("testdata/wire/" + referenceName)
			require.NoError(t, err)
			var reference browserH3Reference
			require.NoError(t, json.Unmarshal(data, &reference))
			checkBrowserH3Settings(t, capture.settings, reference.Settings)
		})
	}
}

func TestQUICFluentFactoriesAndSnapshots(t *testing.T) {
	first, second := newH3Peer(t), newH3Peer(t)
	layout := &transportparams.Layout{
		Order: []uint64{15, 100}, DisableGrease: true,
		Additional: []transportparams.Parameter{{ID: 100, Value: []byte("original")}},
	}
	var count atomic.Uint64
	var number atomic.Uint64
	client := surf.NewClient().Builder().QUICSettings().
		TransportParametersFactory(func(version quic.Version) (*transportparams.Layout, error) {
			if version != quic.Version1 {
				return nil, errors.New("unexpected QUIC version")
			}
			count.Add(1)
			return layout, nil
		}).
		TransportParameter(100, []byte("override")).
		TransportParameter(101, []byte("extra")).
		TransportParameterOrder(101, 100, 15).
		InitialPacketNumberFactory(func() (uint64, error) { return 100 + number.Add(1), nil }).
		ConnectionIDGenerator(sizedCIDGenerator{length: 6}).
		Set().ForceHTTP3().Timeout(5 * time.Second).Build().Unwrap()
	t.Cleanup(func() { client.Close() })
	for i, peer := range []*h3Peer{first, second} {
		peer.request(t, client)
		order, values, gotNumber := quicWireParameters(t, peer)
		require.Equal(t, uint64(101+i), gotNumber)
		require.Equal(t, []uint64{101, 100, 15}, order[:3])
		require.Equal(t, []byte("override"), values[100])
		require.Equal(t, []byte("extra"), values[101])
		peer.packet.mu.Lock()
		cidLength := peer.packet.initials[0].sourceCIDLength
		peer.packet.mu.Unlock()
		require.Equal(t, 6, cidLength)
	}
	require.Equal(t, uint64(2), count.Load())
	require.Equal(t, []uint64{15, 100}, layout.Order)
	require.Equal(t, []transportparams.Parameter{{ID: 100, Value: []byte("original")}}, layout.Additional)
}

func TestQUICFluentDisableBrowserDatagrams(t *testing.T) {
	peer := newH3Peer(t)
	client := surf.NewClient().Builder().Impersonate().Firefox().
		QUICSettings().EnableDatagrams(false).Set().
		ForceHTTP3().Timeout(5 * time.Second).Build().Unwrap()
	t.Cleanup(func() { client.Close() })
	capture := peer.request(t, client)
	_, values, _ := quicWireParameters(t, peer)
	require.NotContains(t, values, uint64(32))
	require.Contains(t, capture.settings, h3Setting{0x33, 0})
}

func TestQUICFluentFactoryErrors(t *testing.T) {
	for _, kind := range []string{"parameters", "packet-number", "client-hello", "tls-engine"} {
		t.Run(kind, func(t *testing.T) {
			peer := newH3Peer(t)
			q := surf.NewClient().Builder().QUICSettings()
			failure := errors.New("QUIC factory failed")
			switch kind {
			case "parameters":
				q.TransportParametersFactory(func(quic.Version) (*transportparams.Layout, error) {
					return nil, failure
				}).TransportParameterOrder(15)
			case "packet-number":
				q.InitialPacketNumberFactory(func() (uint64, error) { return 0, failure })
			case "client-hello":
				q.ClientHelloFactory(func() (utls.ClientHelloSpec, error) { return utls.ClientHelloSpec{}, failure })
			case "tls-engine":
				q.TLSClientFactory(func(*tls.Config) (tlsquic.Conn, error) { return nil, failure })
			}
			client := q.Set().ForceHTTP3().Timeout(time.Second).Build().Unwrap()
			t.Cleanup(func() { client.Close() })
			result := client.Get(g.String(peer.url)).Do()
			require.True(t, result.IsErr())
			require.Contains(t, result.Err().Error(), failure.Error())
		})
	}
}

func TestQUICFluentGreaseOverrides(t *testing.T) {
	for _, browser := range []string{"chrome", "firefox"} {
		for _, disabled := range []bool{false, true} {
			name := browser + "/enabled"
			if disabled {
				name = browser + "/disabled"
			}
			t.Run(name, func(t *testing.T) {
				peer := newH3Peer(t)
				builder := surf.NewClient().Builder()
				if browser == "chrome" {
					builder.Impersonate().Chrome()
				} else {
					builder.Impersonate().Firefox()
				}
				client := builder.QUICSettings().TransportParameterOrder(15, transportparams.Grease).
					DisableTransportParameterGrease(disabled).Set().ForceHTTP3().
					Timeout(5 * time.Second).Build().Unwrap()
				t.Cleanup(func() { client.Close() })
				peer.request(t, client)
				order, values, _ := quicWireParameters(t, peer)
				require.Equal(t, uint64(15), order[0])
				grease := 0
				for _, id := range order {
					if id >= 27 && (id-27)%31 == 0 && id != 0xff02de1a {
						grease++
					}
				}
				if disabled {
					require.Zero(t, grease)
				} else {
					require.Equal(t, 1, grease)
					require.True(t, order[1] >= 27 && (order[1]-27)%31 == 0)
				}
				require.Contains(t, values, uint64(17))
				if browser == "firefox" {
					require.Equal(t, []byte{0x43, 0xe8}, values[0xff02de1a], "GREASE overrides must preserve the enabled legacy receiver")
				}
			})
		}
	}
}

func TestQUICFluentOmitUDPPayloadSize(t *testing.T) {
	peer := newH3Peer(t)
	client := surf.NewClient().Builder().QUICSettings().
		MaxUDPPayloadSize(1480).OmitMaxUDPPayloadSize(true).Set().
		ForceHTTP3().Timeout(5 * time.Second).Build().Unwrap()
	t.Cleanup(func() { client.Close() })
	peer.request(t, client)
	_, values, _ := quicWireParameters(t, peer)
	require.NotContains(t, values, uint64(3))
}

func TestQUICFluentProfileReplacement(t *testing.T) {
	for _, browser := range []string{"chrome", "firefox"} {
		t.Run(browser, func(t *testing.T) {
			peer := newH3Peer(t)
			builder := surf.NewClient().Builder()
			if browser == "chrome" {
				builder.Impersonate().Firefox()
			} else {
				builder.Impersonate().Chrome()
			}
			q := builder.QUICSettings()
			failure := errors.New("discarded profile factory")
			q.InitialStreamReceiveWindow(1024).StreamReceiveWindows(1024, 1024, 1024).
				InitialConnectionReceiveWindow(2048).MaxUDPPayloadSize(1200).
				ConnectionIDLength(19).EnableDatagrams(false).
				ClientHelloFactory(func() (utls.ClientHelloSpec, error) { return utls.ClientHelloSpec{}, failure }).
				TLSClientFactory(func(*tls.Config) (tlsquic.Conn, error) { return nil, failure }).
				TransportParametersFactory(func(quic.Version) (*transportparams.Layout, error) { return nil, failure }).
				InitialPacketNumberFactory(func() (uint64, error) { return 0, failure }).Set()
			if browser == "chrome" {
				builder.Impersonate().Chrome()
			} else {
				builder.Impersonate().Firefox()
			}
			// A previously opened settings chain also sees the replacement profile.
			client := q.MaxIdleTimeout(45 * time.Second).Set().ForceHTTP3().
				TLSConfig(&tls.Config{InsecureSkipVerify: true, ServerName: "fp.impersonate.pro"}).
				Timeout(5 * time.Second).Build().Unwrap()
			t.Cleanup(func() { client.Close() })
			capture := peer.request(t, client)
			_, parameters, number := quicWireParameters(t, peer)
			fixture := "chrome_157_http3.json"
			if browser == "firefox" {
				fixture = "firefox_160_http3.json"
			}
			data, err := os.ReadFile("testdata/wire/" + fixture)
			require.NoError(t, err)
			var reference browserH3Reference
			require.NoError(t, json.Unmarshal(data, &reference))
			hello, _ := h3CapturedHello(t, peer)
			checkBrowserH3TLS(t, hello, reference)
			checkBrowserH3Settings(t, capture.settings, reference.Settings)
			requireQUICParameter(t, parameters, 1, 45000)
			if browser == "chrome" {
				require.EqualValues(t, 1, number)
				for id, want := range map[uint64]uint64{3: 1472, 4: 15 << 20, 5: 6 << 20, 6: 6 << 20, 7: 6 << 20, 32: 65536} {
					requireQUICParameter(t, parameters, id, want)
				}
			} else {
				require.Greater(t, number, uint64(0))
				require.NotContains(t, parameters, uint64(3))
				for id, want := range map[uint64]uint64{4: 24 << 20, 5: 12 << 20, 6: 1 << 20, 7: 1 << 20, 32: 65535} {
					requireQUICParameter(t, parameters, id, want)
				}
			}
			peer.packet.mu.Lock()
			cidLength := peer.packet.initials[0].sourceCIDLength
			peer.packet.mu.Unlock()
			require.Equal(t, reference.ClientConnectionIDLength, cidLength)
		})
	}
}
