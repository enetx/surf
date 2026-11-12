package surf_test

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"slices"
	"testing"
	"time"

	"github.com/enetx/http"
	"github.com/enetx/http/http2"
	"github.com/enetx/http/httptest"
	"github.com/enetx/surf"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2/hpack"
)

// A PING after the complete initial window proves the client has processed all
// DATA before the application reads. Later PING barriers observe completed reads
// without sleeps or scheduler assumptions. Zero peer credit must not override
// Chromium's strict half-window batching while unread body bytes remain buffered.
func TestHTTP2ChromeExhaustedReceiveWindowOnWire(t *testing.T) {
	const window = 6 << 20
	certServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(certServer.Close)
	listener, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{
		Certificates: certServer.TLS.Certificates, NextProtos: []string{"h2"},
	})
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	type checkpoint struct {
		credit []uint32
		err    error
	}
	observed := make(chan checkpoint, 4)
	advance := make(chan struct{}, 3)
	go func() {
		err := func() error {
			conn, err := listener.Accept()
			if err != nil {
				return err
			}
			defer conn.Close()
			if err := conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
				return err
			}
			preface := make([]byte, len(http2.ClientPreface))
			if _, err := io.ReadFull(conn, preface); err != nil {
				return err
			}
			if string(preface) != http2.ClientPreface {
				return fmt.Errorf("unexpected preface %q", preface)
			}
			fr := http2.NewFramer(conn, conn)
			if err := fr.WriteSettings(); err != nil {
				return err
			}
			var stream, initial uint32
			for stream == 0 {
				frame, err := fr.ReadFrame()
				if err != nil {
					return err
				}
				switch frame := frame.(type) {
				case *http2.SettingsFrame:
					if !frame.IsAck() {
						frame.ForeachSetting(func(s http2.Setting) error {
							if s.ID == http2.SettingInitialWindowSize {
								initial = s.Val
							}
							return nil
						})
						if err := fr.WriteSettingsAck(); err != nil {
							return err
						}
					}
				case *http2.HeadersFrame:
					stream = frame.StreamID
				}
			}
			if initial != window {
				return fmt.Errorf("Chrome initial window = %d, want %d", initial, window)
			}
			var headers bytes.Buffer
			encoder := hpack.NewEncoder(&headers)
			for _, field := range []hpack.HeaderField{{Name: ":status", Value: "200"}, {Name: "content-length", Value: fmt.Sprint(window + 1)}} {
				if err := encoder.WriteField(field); err != nil {
					return err
				}
			}
			if err := fr.WriteHeaders(http2.HeadersFrameParam{StreamID: stream, EndHeaders: true, BlockFragment: headers.Bytes()}); err != nil {
				return err
			}
			payload := make([]byte, 16384)
			for sent := 0; sent < window; sent += len(payload) {
				if err := fr.WriteData(stream, false, payload); err != nil {
					return err
				}
			}
			var credit []uint32
			for phase := range 4 {
				if phase != 0 {
					select {
					case <-advance:
					case <-t.Context().Done():
						return t.Context().Err()
					}
				}
				ping := [8]byte{byte(phase + 1)}
				if err := fr.WritePing(false, ping); err != nil {
					return err
				}
				for {
					frame, err := fr.ReadFrame()
					if err != nil {
						return err
					}
					if f, ok := frame.(*http2.WindowUpdateFrame); ok && f.StreamID == stream {
						credit = append(credit, f.Increment)
					}
					if f, ok := frame.(*http2.PingFrame); ok && f.Flags.Has(http2.FlagPingAck) && f.Data == ping {
						break
					}
				}
				observed <- checkpoint{credit: slices.Clone(credit)}
			}
			if err := fr.WriteData(stream, true, []byte{0}); err != nil {
				return err
			}
			// Keep the response tail safe from a reset caused by unread controls.
			_, err = io.Copy(io.Discard, conn)
			return err
		}()
		if err != nil && t.Context().Err() == nil {
			observed <- checkpoint{err: err}
		}
	}()
	client := surf.NewClient().Builder().Proxy("").Impersonate().Chrome().ForceHTTP2().
		TLSConfig(&tls.Config{InsecureSkipVerify: true}).Timeout(15 * time.Second).Build().Unwrap()
	t.Cleanup(func() { client.Close() })
	response, err := client.GetClient().Get("https://" + listener.Addr().String())
	require.NoError(t, err)
	defer response.Body.Close()
	check := func(want []uint32) {
		t.Helper()
		select {
		case got := <-observed:
			require.NoError(t, got.err)
			require.Equal(t, want, got.credit)
		case <-time.After(15 * time.Second):
			t.Fatal("missing flow-control PING barrier")
		}
	}
	check(nil)
	for _, n := range []int64{32768, window/2 - 32768, 1} {
		read, err := io.CopyN(io.Discard, response.Body, n)
		require.NoError(t, err)
		require.Equal(t, n, read)
		advance <- struct{}{}
		if n == 1 {
			check([]uint32{window/2 + 1})
		} else {
			check(nil)
		}
	}
	read, err := io.Copy(io.Discard, response.Body)
	require.NoError(t, err)
	require.EqualValues(t, window/2, read)
}
