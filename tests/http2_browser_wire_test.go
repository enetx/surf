package surf_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/http/http2"
	"github.com/enetx/http/httptest"
	"github.com/enetx/surf"
	"golang.org/x/net/http2/hpack"
)

// Pin the HTTP/2 settings, navigation headers and their wire order from the
// current Chrome and Firefox platform fixtures.
// HPACK indexing policy and resource-dependent stream priorities are transport
// features outside this profile check.
func TestBrowserHTTP2Wire(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"chrome-158-windows", "chrome-158-android", "chrome-158-macos", "chrome-157-macos", "chrome-158-ios", "chrome-157-ios", "firefox-160-windows"} {
		t.Run(name, func(t *testing.T) {
			type capture struct {
				settings []http2.Setting
				window   uint32
				headers  []hpack.HeaderField
				priority http2.PriorityParam
				streamID uint32
				flags    http2.Flags
				length   uint32
				block    []byte
			}
			captured := make(chan capture, 1)
			ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				t.Error("Browser request fell back to HTTP/1.1")
				w.WriteHeader(http.StatusBadRequest)
			}))
			ts.EnableHTTP2 = true
			ts.Config.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){
				"h2": func(_ *http.Server, conn *tls.Conn, _ http.Handler) {
					defer conn.Close()
					_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
					preface := make([]byte, len(http2.ClientPreface))
					if _, err := io.ReadFull(conn, preface); err != nil || string(preface) != http2.ClientPreface {
						return
					}
					fr := http2.NewFramer(conn, conn)
					decoder := hpack.NewDecoder(65536, nil)
					if err := fr.WriteSettings(); err != nil {
						return
					}
					var got capture
					for {
						f, err := fr.ReadFrame()
						if err != nil {
							return
						}
						switch f := f.(type) {
						case *http2.SettingsFrame:
							if !f.IsAck() {
								_ = f.ForeachSetting(func(s http2.Setting) error { got.settings = append(got.settings, s); return nil })
								_ = fr.WriteSettingsAck()
							}
						case *http2.WindowUpdateFrame:
							if f.StreamID == 0 {
								got.window = f.Increment
							}
						case *http2.HeadersFrame:
							if !f.HeadersEnded() {
								return
							}
							got.block = slices.Clone(f.HeaderBlockFragment())
							fields, err := decoder.DecodeFull(got.block)
							if err != nil {
								return
							}
							got.headers = fields
							got.priority = f.Priority
							got.streamID = f.StreamID
							got.flags = f.Flags
							got.length = f.Header().Length
							captured <- got
							var response bytes.Buffer
							_ = hpack.NewEncoder(&response).WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
							_ = fr.WriteHeaders(http2.HeadersFrameParam{StreamID: f.StreamID, BlockFragment: response.Bytes(), EndHeaders: true, EndStream: true})
							return
						}
					}
				},
			}
			ts.StartTLS()
			defer ts.Close()

			im := surf.NewClient().Builder().Impersonate().Windows()
			switch name {
			case "chrome-158-android":
				im.Android()
			case "chrome-158-macos", "chrome-157-macos":
				im.MacOS()
			case "chrome-158-ios", "chrome-157-ios":
				im.IOS()
			}
			var builder *surf.Builder
			if strings.HasPrefix(name, "firefox-") {
				builder = im.Firefox()
			} else {
				builder = im.Chrome()
			}
			builder.Proxy("")
			if name == "chrome-157-macos" {
				// Preserve the original independent 157 HPACK byte oracle.
				// Current 158 semantic cases exercise the new default headers.
				builder.UserAgent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36").
					SetHeaders("sec-ch-ua", `"Not-A.Brand";v="99", "Google Chrome";v="157", "Chromium";v="157"`)
			}
			if name == "chrome-157-ios" {
				// Retain the original captured iPhone HEADERS-length oracle.
				builder.UserAgent("Mozilla/5.0 (iPhone; CPU iPhone OS 27_0_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/157.0.8103.37 Mobile/15E148 Safari/604.1")
			}
			url := g.String(ts.URL + "/a")
			if name == "chrome-157-ios" || name == "chrome-158-ios" {
				// Reproduce the supplied iPhone navigation, including the encoded
				// header length, while keeping the connection entirely local.
				builder.SetHeaders("accept-language", "ru").With(func(c *surf.Client) error {
					transport := c.GetTransport().(*http.Transport)
					dial := transport.DialContext
					transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
						return dial(ctx, network, ts.Listener.Addr().String())
					}
					return nil
				})
				url = "https://tls.peet.ws/api/all"
			}
			if name == "firefox-160-windows" || name == "chrome-157-macos" || name == "chrome-158-macos" {
				// Replay the new independent tls.peet.ws navigation entirely
				// against the local peer, retaining its authority and path.
				builder.With(func(c *surf.Client) error {
					transport := c.GetTransport().(*http.Transport)
					dial := transport.DialContext
					transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
						return dial(ctx, network, ts.Listener.Addr().String())
					}
					return nil
				})
				url = "https://tls.peet.ws/api/all"
			}
			client := builder.Timeout(5 * time.Second).Build().Unwrap()
			defer client.CloseIdleConnections()
			resp := client.Get(url).Do()
			if resp.IsErr() {
				t.Fatal(resp.Err())
			}
			if resp.Ok().StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200", resp.Ok().StatusCode)
			}
			var got capture
			select {
			case got = <-captured:
			case <-time.After(time.Second):
				t.Fatal("no HTTP/2 capture")
			}
			fixture, err := os.ReadFile("testdata/wire/" + name + ".golden")
			if err != nil {
				t.Fatal(err)
			}
			_, want, found := strings.Cut(string(fixture), "## http/2 navigation\n")
			if !found {
				t.Fatal("missing HTTP/2 reference")
			}
			var normalized strings.Builder
			normalized.WriteString("SETTINGS")
			for _, setting := range got.settings {
				fmt.Fprintf(&normalized, " %d=%d", setting.ID, setting.Val)
			}
			fmt.Fprintf(&normalized, "\nWINDOW_UPDATE stream=0 increment=%d\n", got.window)
			fmt.Fprintf(&normalized, "HEADERS stream=%d flags=0x%x", got.streamID, got.flags)
			if name == "chrome-157-ios" || name == "chrome-157-macos" || name == "chrome-158-macos" {
				fmt.Fprintf(&normalized, " length=%d", got.length)
			}
			if got.flags.Has(http2.FlagHeadersPriority) {
				fmt.Fprintf(&normalized, " exclusive=%t dep=%d weight=%d", got.priority.Exclusive, got.priority.StreamDep, int(got.priority.Weight)+1)
			}
			normalized.WriteByte('\n')
			if name == "chrome-157-macos" || name == "chrome-158-macos" {
				fmt.Fprintf(&normalized, "HPACK %x\n", got.block)
			}
			for _, field := range got.headers {
				value := field.Value
				if field.Name == ":authority" {
					value = strings.ReplaceAll(value, strings.TrimPrefix(ts.URL, "https://"), "127.0.0.1:PORT")
				}
				fmt.Fprintf(&normalized, "%s: %s\n", field.Name, value)
			}
			if normalized.String() != want {
				t.Errorf("HTTP/2 navigation differs from platform golden\n got:\n%s\nwant:\n%s", normalized.String(), want)
			}
		})
	}
}
