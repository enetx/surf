package surf_test

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/http/http2"
	"github.com/enetx/http/httptest"
	"github.com/enetx/surf"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2/hpack"
)

func TestHTTP2ReceiveWindowProfilesOnWire(t *testing.T) {
	for _, browser := range []string{"chrome", "firefox"} {
		t.Run(browser, func(t *testing.T) {
			// A raw TLS peer observes actual WINDOW_UPDATE frames while sending
			// more than a stream window. No public network or browser is needed.
			certServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
			t.Cleanup(certServer.Close)
			listener, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{Certificates: certServer.TLS.Certificates, NextProtos: []string{"h2"}})
			require.NoError(t, err)
			defer listener.Close()
			type observation struct {
				initial, refresh []uint32
				err              error
			}
			done := make(chan observation, 1)
			go func() {
				var got observation
				sent := false
				defer func() {
					if !sent {
						done <- got
					}
				}()
				conn, err := listener.Accept()
				if err != nil {
					got.err = err
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(8 * time.Second))
				preface := make([]byte, len(http2.ClientPreface))
				if _, got.err = io.ReadFull(conn, preface); got.err != nil {
					return
				}
				fr := http2.NewFramer(conn, conn)
				if got.err = fr.WriteSettings(); got.err != nil {
					return
				}
				var stream uint32
				window := int64(0)
				for stream == 0 || (browser == "firefox" && len(got.initial) == 0) {
					frame, err := fr.ReadFrame()
					if err != nil {
						got.err = err
						return
					}
					switch f := frame.(type) {
					case *http2.SettingsFrame:
						if !f.IsAck() {
							f.ForeachSetting(func(s http2.Setting) error {
								if s.ID == http2.SettingInitialWindowSize {
									window = int64(s.Val)
								}
								return nil
							})
							fr.WriteSettingsAck()
						}
					case *http2.HeadersFrame:
						stream = f.StreamID
					case *http2.WindowUpdateFrame:
						if f.StreamID != 0 {
							window += int64(f.Increment)
							got.initial = append(got.initial, f.Increment)
						}
					}
				}
				var block bytes.Buffer
				encoder := hpack.NewEncoder(&block)
				encoder.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
				const total = 14 << 20
				encoder.WriteField(hpack.HeaderField{Name: "content-length", Value: fmt.Sprint(total)})
				if got.err = fr.WriteHeaders(http2.HeadersFrameParam{StreamID: stream, EndHeaders: true, BlockFragment: block.Bytes()}); got.err != nil {
					return
				}
				payload := make([]byte, 16384)
				for remaining := int64(total); remaining > 0; {
					if window <= 0 {
						frame, err := fr.ReadFrame()
						if err != nil {
							got.err = err
							return
						}
						if f, ok := frame.(*http2.WindowUpdateFrame); ok && f.StreamID == stream {
							window += int64(f.Increment)
							got.refresh = append(got.refresh, f.Increment)
						}
						continue
					}
					n := min(int64(len(payload)), remaining, window)
					if got.err = fr.WriteData(stream, n == remaining, payload[:n]); got.err != nil {
						return
					}
					window -= n
					remaining -= n
				}
				done <- got
				sent = true
				// Drain control frames until the client closes. Closing a socket
				// with unread WINDOW_UPDATE bytes can reset the response tail.
				io.Copy(io.Discard, conn)
			}()
			builder := surf.NewClient().Builder()
			if browser == "chrome" {
				builder.Impersonate().Chrome()
			} else {
				builder.Impersonate().Firefox()
			}
			client := builder.TLSConfig(&tls.Config{InsecureSkipVerify: true}).Timeout(10 * time.Second).Build().Unwrap()
			defer client.Close()
			response := client.Get(g.String("https://" + listener.Addr().String())).Do().Unwrap()
			defer response.Body.Close()
			n, err := io.Copy(io.Discard, response.Body.Stream())
			require.NoError(t, err)
			require.EqualValues(t, 14<<20, n)
			got := <-done
			require.NoError(t, got.err)
			require.NotEmpty(t, got.refresh)
			if browser == "chrome" {
				require.Empty(t, got.initial)
				for _, credit := range got.refresh {
					require.Greater(t, credit, uint32(3<<20))
				}
			} else {
				require.Equal(t, []uint32{(12 << 20) - 131072}, got.initial)
				for _, credit := range got.refresh {
					require.GreaterOrEqual(t, credit, uint32(4<<20))
				}
			}
		})
	}
}
