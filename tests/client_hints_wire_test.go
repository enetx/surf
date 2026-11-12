package surf_test

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	stdhttp "net/http"
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
	"github.com/enetx/surf/header"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2/hpack"
)

type clientHintsFixture struct {
	Cases []struct {
		Name     string
		AcceptCH string `json:"accept_ch"`
		Requests []struct {
			Method, Path string
			Headers      [][2]string
		}
	}
}

func hintsFixture(t *testing.T) clientHintsFixture {
	t.Helper()
	data, err := os.ReadFile("testdata/wire/client_hints/chromium-158.json")
	require.NoError(t, err)
	var fixture clientHintsFixture
	require.NoError(t, json.Unmarshal(data, &fixture))
	return fixture
}
func hintProjection(names []string) []string {
	return slices.DeleteFunc(slices.Clone(names), func(name string) bool {
		return !strings.HasPrefix(strings.ToLower(name), "sec-ch-ua") && !slices.Contains([]string{header.USER_AGENT, header.CONTENT_TYPE, header.UPGRADE_INSECURE_REQUESTS, header.ACCEPT}, strings.ToLower(name))
	})
}
func hintH1Peer(t *testing.T, accept string) (string, <-chan []string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	captured := make(chan []string, 16)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(10 * time.Second))
				reader := bufio.NewReader(conn)
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					var raw strings.Builder
					raw.WriteString(line)
					var names []string
					for {
						line, err = reader.ReadString('\n')
						if err != nil {
							return
						}
						raw.WriteString(line)
						if line == "\r\n" {
							break
						}
						name, _, _ := strings.Cut(line, ":")
						names = append(names, name)
					}
					req, err := http.ReadRequest(bufio.NewReader(io.MultiReader(strings.NewReader(raw.String()), reader)))
					if err != nil {
						return
					}
					io.Copy(io.Discard, req.Body)
					req.Body.Close()
					captured <- names
					fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nAccept-CH: %s\r\nCritical-CH: %s\r\n\r\nok", accept, accept)
				}
			}()
		}
	}()
	return "http://" + ln.Addr().String(), captured
}
func hintH2Peer(t *testing.T, accept string) (string, <-chan []string) {
	t.Helper()
	captured := make(chan []string, 16)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("unexpected H1 fallback") }))
	server.EnableHTTP2 = true
	server.Config.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){"h2": func(_ *http.Server, conn *tls.Conn, _ http.Handler) {
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		preface := make([]byte, len(http2.ClientPreface))
		if _, err := io.ReadFull(conn, preface); err != nil {
			return
		}
		fr := http2.NewFramer(conn, conn)
		fr.ReadMetaHeaders = hpack.NewDecoder(65536, nil)
		fr.WriteSettings()
		var block bytes.Buffer
		encoder := hpack.NewEncoder(&block)
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
				var names []string
				for _, field := range f.Fields {
					names = append(names, field.Name)
				}
				captured <- names
				block.Reset()
				for _, field := range []hpack.HeaderField{{Name: ":status", Value: "200"}, {Name: "accept-ch", Value: accept}, {Name: "critical-ch", Value: accept}} {
					encoder.WriteField(field)
				}
				fr.WriteHeaders(http2.HeadersFrameParam{StreamID: f.StreamID, BlockFragment: block.Bytes(), EndHeaders: true, EndStream: true})
			}
		}
	}}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server.URL, captured
}
func TestClientHintsBrowserHeaderOrderOnWire(t *testing.T) {
	for _, fixture := range hintsFixture(t).Cases {
		for _, major := range []int{1, 2, 3} {
			t.Run(fmt.Sprintf("%s/http%d", fixture.Name, major), func(t *testing.T) {
				var origin string
				var captured <-chan []string
				var peer *h3Peer
				switch major {
				case 1:
					origin, captured = hintH1Peer(t, fixture.AcceptCH)
				case 2:
					origin, captured = hintH2Peer(t, fixture.AcceptCH)
				case 3:
					peer = startH3PeerWithHeaders(t, nil, nil, stdhttp.Header{"Accept-Ch": {fixture.AcceptCH}, "Critical-Ch": {fixture.AcceptCH}})
					origin = peer.url
				}
				b := surf.NewClient().Builder().Proxy("").Impersonate().Chrome().Timeout(5 * time.Second)
				switch major {
				case 1:
					b.ForceHTTP1()
				case 2:
					b.ForceHTTP2()
				case 3:
					b.ForceHTTP3()
				}
				b.With(func(r *surf.Request) error {
					if r.GetRequest().URL.Path == "/fetch" {
						r.SetHeaders(header.SEC_FETCH_MODE, "cors")
						r.SetHeaders(header.SEC_FETCH_DEST, "empty")
					}
					return nil
				}, 1)
				c := b.Build().Unwrap()
				defer c.Close()
				for _, stage := range []string{"initial", "post", "fetch", "warm"} {
					var request *surf.Request
					if stage == "post" {
						request = c.Post(g.String(origin+"/post")).Body("hello").SetHeaders(header.CONTENT_TYPE, "text/plain;charset=UTF-8")
					} else if stage == "fetch" {
						request = c.Get(g.String(origin + "/fetch"))
					} else {
						request = c.Get(g.String(origin + "/"))
					}
					result := request.Do()
					require.False(t, result.IsErr(), "%v", result.Err())
					result.Ok().Body.String().Unwrap()
				}
				// Independent browser data supplies cold navigation, critical restart,
				// fetch POST and warm navigation orders. H2/H3 casing is always lowercase.
				var expected [][]string
				for _, request := range fixture.Requests {
					var names []string
					for _, field := range request.Headers {
						names = append(names, field[0])
					}
					expected = append(expected, hintProjection(names))
				}
				count := 5
				if fixture.Name == "empty" {
					count = 4
				}
				require.Len(t, expected, count)
				for i, want := range expected {
					var names []string
					if major == 3 {
						select {
						case got := <-peer.requests:
							for _, field := range got.headers {
								names = append(names, field.Name)
							}
						case err := <-peer.errors:
							t.Fatal(err)
						case <-time.After(time.Second):
							t.Fatal("no H3 request")
						}
					} else {
						select {
						case names = <-captured:
						case <-time.After(time.Second):
							t.Fatal("no wire request")
						}
					}
					got := hintProjection(names)
					if major != 1 {
						for j := range want {
							want[j] = strings.ToLower(want[j])
						}
					}
					require.Equal(t, want, got, "stage %d", i)
				}
			})
		}
	}
}
