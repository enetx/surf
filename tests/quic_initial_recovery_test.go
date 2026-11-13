package surf_test

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/http/httptest"
	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/http3"
	"github.com/enetx/quic-go/quicvarint"
	"github.com/enetx/surf"
	firefox "github.com/enetx/surf/profiles/firefox/quic"
	"github.com/stretchr/testify/require"
)

type recoveryPacketConn struct {
	net.PacketConn
	mutex    sync.Mutex
	packets  [][]byte
	drop     int
	dropOnly int
}

func (c *recoveryPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.PacketConn.ReadFrom(b)
		if err != nil {
			return n, addr, err
		}
		dropped := false
		if isH3Initial(b[:n]) {
			c.mutex.Lock()
			c.packets = append(c.packets, bytes.Clone(b[:n]))
			dropped = len(c.packets) <= c.drop || c.dropOnly > 0 && len(c.packets) == c.dropOnly
			c.mutex.Unlock()
		}
		if !dropped {
			return n, addr, nil
		}
	}
}

type initialCryptoPart struct {
	quic.CryptoRange
	data []byte
}

func recoveryCryptoParts(t *testing.T, plaintext []byte) []initialCryptoPart {
	t.Helper()
	r := bytes.NewReader(plaintext)
	read := func() uint64 { n, err := quicvarint.Read(r); require.NoError(t, err); return n }
	var parts []initialCryptoPart
	for r.Len() > 0 {
		switch typ := read(); typ {
		case 0, 1:
		case 2, 3:
			read()
			read()
			count := read()
			read()
			for range count {
				read()
				read()
			}
			if typ == 3 {
				read()
				read()
				read()
			}
		case 6:
			offset, n := read(), read()
			require.LessOrEqual(t, n, uint64(r.Len()))
			data := make([]byte, int(n))
			_, err := io.ReadFull(r, data)
			require.NoError(t, err)
			parts = append(parts, initialCryptoPart{quic.CryptoRange{Offset: int(offset), Length: int(n)}, data})
		default:
			t.Fatalf("unexpected Initial frame %#x", typ)
		}
	}
	return parts
}

func TestInitialRecoveryFluentValidationAndDisable(t *testing.T) {
	invalid := surf.NewClient().Builder().ForceHTTP3().QUICSettings().InitialCryptoProbePackets(3).Set().Build()
	require.True(t, invalid.IsErr())
	require.ErrorContains(t, invalid.Err(), "probe")
	peer := newH3Peer(t)
	q := surf.NewClient().Builder().Impersonate().Firefox().ForceHTTP3().Proxy("").QUICSettings()
	q.InitialCryptoRecoveryLayout(func(quic.InitialCryptoLayoutInfo) [][]quic.CryptoRange {
		t.Error("disabled recovery policy was invoked")
		return nil
	}).InitialCryptoProbePackets(2).InitialCryptoResendOnPeerProbe(true).
		InitialCryptoRecovery(false).InitialCryptoRecoveryLayout(nil).InitialCryptoProbePackets(0)
	client := q.Set().Timeout(5 * time.Second).Build().Unwrap()
	t.Cleanup(func() { client.Close() })
	peer.request(t, client)
}

func TestBrowserInitialRecoveryAndHRROnWire(t *testing.T) {
	for _, browser := range []string{"chrome", "firefox"} {
		for _, hrr := range []bool{false, true} {
			for _, drop := range []int{0, 1, 2, 3} {
				if drop == 3 && !hrr {
					continue
				}
				t.Run(fmt.Sprintf("%s/hrr=%t/drop=%d", browser, hrr, drop), func(t *testing.T) {
					cert := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
					serverTLS := cert.TLS.Clone()
					cert.Close()
					if hrr {
						serverTLS.CurvePreferences = []tls.CurveID{tls.CurveP384}
					}
					udp, err := net.ListenPacket("udp", "127.0.0.1:0")
					require.NoError(t, err)
					packet := &recoveryPacketConn{PacketConn: udp, drop: drop}
					if drop == 3 {
						packet.drop = 0
						packet.dropOnly = 3
					}
					server := &http3.Server{TLSConfig: serverTLS, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") })}
					go server.Serve(packet)
					t.Cleanup(func() { server.Close(); packet.Close() })
					builder := surf.NewClient().Builder().Proxy("")
					if browser == "chrome" {
						builder.Impersonate().Chrome()
					} else {
						builder.Impersonate().Firefox()
					}
					var mutex sync.Mutex
					var plans []struct {
						info  quic.InitialCryptoLayoutInfo
						first []quic.CryptoRange
					}
					if browser == "firefox" {
						// Isolate timer-driven layout recovery. Peer hints may validly
						// repeat still-unacknowledged CH1 bytes before HRR's CH2;
						// their packet races are covered by the peer recovery tests.
						builder.QUICSettings().InitialCryptoResendOnPeerProbe(false).PeerPacketRecoveryPolicy(nil).
							InitialCryptoRecoveryLayout(func(info quic.InitialCryptoLayoutInfo) [][]quic.CryptoRange {
								layout := firefox.InitialCryptoLayout(info)
								mutex.Lock()
								var first []quic.CryptoRange
								if len(layout) > 0 {
									first = slices.Clone(layout[0])
								}
								plans = append(plans, struct {
									info  quic.InitialCryptoLayoutInfo
									first []quic.CryptoRange
								}{info, first})
								mutex.Unlock()
								return layout
							}).Set()
					}
					client := builder.ForceHTTP3().TLSConfig(&tls.Config{InsecureSkipVerify: true, ServerName: "initial.recovery.test"}).Timeout(10 * time.Second).Build().Unwrap()
					t.Cleanup(func() { client.Close() })
					response := client.Get(g.String("https://" + udp.LocalAddr().String())).Do()
					require.False(t, response.IsErr(), "%v", response.Err())
					require.Equal(t, g.String("ok"), response.Unwrap().Body.String().Unwrap())
					packet.mutex.Lock()
					packets := slices.Clone(packet.packets)
					packet.mutex.Unlock()
					require.NotEmpty(t, packets)
					dcid := packets[0][6 : 6+int(packets[0][5])]
					var groups [][]initialCryptoPart
					var numbers []uint64
					assembled := make([]byte, 64<<10)
					seen := make([]bool, len(assembled))
					expected := uint64(0)
					for _, raw := range packets {
						plain, pn, err := h3InitialPlaintext(raw, dcid, expected)
						require.NoError(t, err)
						expected = pn + 1
						parts := recoveryCryptoParts(t, plain)
						if len(parts) == 0 {
							continue
						}
						groups = append(groups, parts)
						numbers = append(numbers, pn)
						for _, part := range parts {
							require.LessOrEqual(t, part.Offset+part.Length, len(assembled))
							for i, b := range part.data {
								off := part.Offset + i
								if seen[off] {
									require.Equal(t, assembled[off], b, "recovery changed TLS transcript byte %d", off)
								}
								assembled[off], seen[off] = b, true
							}
						}
					}
					firstLength := 4 + int(assembled[1])<<16 + int(assembled[2])<<8 + int(assembled[3])
					require.EqualValues(t, 1, assembled[0])
					require.True(t, slices.Contains(seen[:firstLength], true))
					for _, present := range seen[:firstLength] {
						require.True(t, present)
					}
					if drop > 0 {
						require.Greater(t, len(groups), 2, "lost Initial data must be retransmitted")
					}
					if drop == 2 {
						gap := uint64(1)
						if browser == "chrome" {
							gap = 2
						}
						require.Equal(t, numbers[1]+gap, numbers[2], "Initial PTO packet-number gap must follow the browser")
					}
					if hrr {
						require.EqualValues(t, 1, assembled[firstLength], "HRR must produce a second ClientHello")
						secondLength := 4 + int(assembled[firstLength+1])<<16 + int(assembled[firstLength+2])<<8 + int(assembled[firstLength+3])
						for _, present := range seen[firstLength : firstLength+secondLength] {
							require.True(t, present)
						}
						if browser == "firefox" {
							for _, group := range groups {
								for i, part := range group {
									if part.Offset >= firstLength {
										require.Equal(t, firstLength, part.Offset, "CH2 must keep its Initial stream offset")
										require.Zero(t, i)
										require.Len(t, group, 1)
									}
								}
							}
						}
					}
					if browser == "firefox" && drop > 0 {
						mutex.Lock()
						defer mutex.Unlock()
						require.NotEmpty(t, plans)
						var recovered []quic.CryptoRange
						index := 2
						if drop == 3 {
							index = 3
						}
						for _, part := range groups[index] {
							recovered = append(recovered, part.CryptoRange)
						}
						require.Equal(t, plans[0].first, recovered, "decrypted recovery packet must retain the exact selected range order")
						if drop == 3 {
							require.Equal(t, firstLength, plans[0].info.Remaining[0].Offset)
							require.Len(t, plans[0].first, 1)
						} else if drop == 2 {
							require.Equal(t, []quic.CryptoRange{{Length: firstLength}}, plans[0].info.Remaining)
							require.Len(t, plans[0].first, 2)
							require.Positive(t, plans[0].first[0].Offset)
						} else {
							require.GreaterOrEqual(t, len(plans[0].info.Remaining), 2)
							require.Zero(t, plans[0].first[0].Offset, "partial SNI prefix must be resent sequentially before the suffix")
						}
					}
				})
			}
		}
	}
}
