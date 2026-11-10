package surf_test

import (
	"crypto/tls"
	"io"
	"slices"
	"strings"
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

// These representation assertions come from the pinned browser source rules,
// rather than a decoder-only snapshot of our own headers.
// https://github.com/google/quiche/blob/a1628192cf32ba40d21e0dd80f485d68c24ff87a/quiche/http2/hpack/hpack_encoder.cc
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/netwerk/protocol/http/Http2Compression.cpp
func TestBrowserHTTP2SensitiveFieldsAndCookieBoundary(t *testing.T) {
	for _, firefox := range []bool{false, true} {
		t.Run(map[bool]string{false: "chrome", true: "firefox"}[firefox], func(t *testing.T) {
			captured := make(chan []hpack.HeaderField, 1)
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("HTTP/1 fallback") }))
			server.EnableHTTP2 = true
			server.Config.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){"h2": func(_ *http.Server, conn *tls.Conn, _ http.Handler) {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				preface := make([]byte, len(http2.ClientPreface))
				if _, err := io.ReadFull(conn, preface); err != nil {
					return
				}
				fr := http2.NewFramer(conn, conn)
				fr.ReadMetaHeaders = hpack.NewDecoder(65536, nil)
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
							fr.WriteSettingsAck()
						}
					case *http2.MetaHeadersFrame:
						captured <- slices.Clone(f.Fields)
						fr.WriteHeaders(http2.HeadersFrameParam{StreamID: f.StreamID, BlockFragment: []byte{0x88}, EndHeaders: true, EndStream: true})
						return
					}
				}
			}}
			server.StartTLS()
			defer server.Close()
			im := surf.NewClient().Builder().Impersonate().Windows()
			var builder *surf.Builder
			if firefox {
				builder = im.Firefox()
			} else {
				builder = im.Chrome()
			}
			client := builder.ForceHTTP2().Timeout(5 * time.Second).Build().Unwrap()
			defer client.Close()
			// Entire cookie-pairs are exactly 19 and 20 bytes, respectively.
			small := "a=" + strings.Repeat("x", 17)
			large := "b=" + strings.Repeat("y", 18)
			response := client.Get(g.String(server.URL+"/varying-path")).SetHeaders("cookie", small+"; "+large).SetHeaders("authorization", "token").Do()
			require.False(t, response.IsErr(), "%v", response.Err())
			response.Ok().Body.Close()
			select {
			case fields := <-captured:
				var cookies []hpack.HeaderField
				auth := false
				for _, f := range fields {
					switch f.Name {
					case "cookie":
						cookies = append(cookies, f)
					case "authorization":
						auth = true
						require.Equal(t, firefox, f.Sensitive)
					}
				}
				require.True(t, auth)
				require.Equal(t, []hpack.HeaderField{{Name: "cookie", Value: small, Sensitive: firefox}, {Name: "cookie", Value: large}}, cookies)
			case <-time.After(time.Second):
				t.Fatal("missing browser fields")
			}
		})
	}
}

func TestBrowserHTTP2EncoderAcceptsPeerTableGrowth(t *testing.T) {
	for _, name := range []string{"custom", "chrome", "firefox"} {
		t.Run(name, func(t *testing.T) {
			updates := make(chan []uint64, 1)
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("HTTP/1 fallback") }))
			server.EnableHTTP2 = true
			server.Config.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){"h2": func(_ *http.Server, conn *tls.Conn, _ http.Handler) {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				preface := make([]byte, len(http2.ClientPreface))
				if _, err := io.ReadFull(conn, preface); err != nil {
					return
				}
				fr := http2.NewFramer(conn, conn)
				decoder := hpack.NewDecoder(65536, nil)
				if err := fr.WriteSettings(http2.Setting{ID: http2.SettingHeaderTableSize, Val: 65536}); err != nil {
					return
				}
				var sizes []uint64
				var pending uint32
				var requests int
				var ack bool
				for {
					frame, err := fr.ReadFrame()
					if err != nil {
						return
					}
					switch f := frame.(type) {
					case *http2.SettingsFrame:
						if f.IsAck() {
							ack = true
						} else {
							fr.WriteSettingsAck()
						}
					case *http2.HeadersFrame:
						block := f.HeaderBlockFragment()
						if !f.HeadersEnded() {
							t.Error("unexpected continuation")
							return
						}
						if _, err := decoder.DecodeFull(block); err != nil {
							t.Error(err)
							return
						}
						for len(block) > 0 && block[0]&0xe0 == 0x20 {
							value := uint64(block[0] & 31)
							block = block[1:]
							if value == 31 {
								for shift := uint(0); ; shift += 7 {
									if len(block) == 0 || shift > 63 {
										t.Error("invalid HPACK update")
										return
									}
									b := block[0]
									block = block[1:]
									value += uint64(b&127) << shift
									if b&128 == 0 {
										break
									}
								}
							}
							sizes = append(sizes, value)
						}
						pending = f.StreamID
					}
					// Ensure the SETTINGS ACK precedes the first response, so the
					// second request deterministically sees the new encoder capacity.
					if ack && pending != 0 {
						if err := fr.WriteHeaders(http2.HeadersFrameParam{StreamID: pending, BlockFragment: []byte{0x88}, EndHeaders: true, EndStream: true}); err != nil {
							return
						}
						pending = 0
						requests++
						if requests == 2 {
							updates <- sizes
							return
						}
					}
				}
			}}
			server.StartTLS()
			defer server.Close()
			builder := surf.NewClient().Builder()
			switch name {
			case "chrome":
				builder = builder.Impersonate().Chrome()
			case "firefox":
				builder = builder.Impersonate().Firefox()
			default:
				builder = builder.HTTP2Settings().MaxEncoderHeaderTableSize(65536).Set()
			}
			client := builder.ForceHTTP2().Timeout(5 * time.Second).Build().Unwrap()
			defer client.Close()
			for range 2 {
				response := client.Get(g.String(server.URL + "/table")).Do()
				require.False(t, response.IsErr(), "%v", response.Err())
				response.Ok().Body.Close()
			}
			select {
			case sizes := <-updates:
				require.Contains(t, sizes, uint64(65536), "encoder must honor peer growth beyond 4096")
			case <-time.After(time.Second):
				t.Fatal("missing table updates")
			}
		})
	}
}
