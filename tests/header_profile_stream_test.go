package surf_test

import (
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/surf"
	"github.com/enetx/surf/header"
	"github.com/stretchr/testify/require"
)

func TestHeaderProfileStreamingFramingOnWire(t *testing.T) {
	for _, browser := range []string{"chrome", "firefox"} {
		for _, major := range []int{1, 2, 3} {
			t.Run(fmt.Sprintf("%s/http%d", browser, major), func(t *testing.T) {
				origin, captured := newProfileWirePeer(t, major, nil)
				im := surf.NewClient().Builder().Proxy("").Impersonate()
				var b *surf.Builder
				if browser == "chrome" {
					b = im.Chrome()
				} else {
					b = im.Firefox()
				}
				switch major {
				case 1:
					b.ForceHTTP1()
				case 2:
					b.ForceHTTP2()
				case 3:
					b.ForceHTTP3()
				}
				var before http.Header
				client := b.With(func(r *surf.Request) error { before = r.GetRequest().Header.Clone(); return nil }, 1000).Timeout(10 * time.Second).Build().Unwrap()
				defer client.Close()
				for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions} {
					for _, mode := range []string{"known", "unknown", "factory"} {
						t.Run(method+"/"+mode, func(t *testing.T) {
							payload := "stream-body"
							request := client.Get(g.String(origin + "/stream"))
							request.GetRequest().Method = method
							switch mode {
							case "known":
								request.StreamingBody(strings.NewReader(payload), int64(len(payload)))
							case "unknown":
								request.StreamingBody(strings.NewReader(payload))
							case "factory":
								request.StreamingBodyFactory(func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(payload)), nil }, int64(len(payload)))
							}
							order := g.NewMapOrd[string, string]()
							for _, name := range []string{"x-first", header.HOST, "transfer-encoding", header.CONTENT_LENGTH, header.CONTENT_TYPE, header.USER_AGENT, "x-last"} {
								value := ""
								switch name {
								case "x-first":
									value = "first"
								case "x-last":
									value = "last"
								case header.CONTENT_TYPE:
									value = "application/octet-stream"
								case header.USER_AGENT:
									value = "stream-test"
								}
								order.Insert(name, value)
							}
							result := request.SetHeaders(order).Do()
							require.False(t, result.IsErr(), "%v", result.Err())
							result.Unwrap().Body.String().Unwrap()
							var got profileWireCapture
							select {
							case got = <-captured:
							case <-time.After(5 * time.Second):
								t.Fatal("no streamed request")
							}
							var regular [][2]string
							for _, f := range got.fields {
								if !strings.HasPrefix(f[0], ":") {
									regular = append(regular, [2]string{strings.ToLower(f[0]), f[1]})
								}
							}
							want := [][2]string{{"x-first", "first"}}
							if major == 1 {
								want = append(want, [2]string{header.HOST, strings.TrimPrefix(strings.TrimPrefix(origin, "https://"), "http://")})
							}
							if mode == "unknown" {
								if major == 1 {
									want = append(want, [2]string{"transfer-encoding", "chunked"})
								}
							} else {
								want = append(want, [2]string{header.CONTENT_LENGTH, strconv.Itoa(len(payload))})
							}
							want = append(want, [2]string{header.CONTENT_TYPE, "application/octet-stream"}, [2]string{header.USER_AGENT, "stream-test"}, [2]string{"x-last", "last"})
							require.GreaterOrEqual(t, len(regular), len(want))
							require.Equal(t, want, regular[:len(want)], "caller prefix includes implicit framing fields")
							tail := regular[len(want):]
							require.True(t, slices.IsSortedFunc(tail, func(a, b [2]string) int { return strings.Compare(a[0], b[0]) }))
							require.Equal(t, payload, got.body)
							require.Equal(t, before, request.GetRequest().Header, "serialization keeps logical headers immutable")
							for _, f := range got.fields {
								require.NotContains(t, strings.ToLower(f[0]), "header-order:")
							}
						})
					}
				}
			})
		}
	}
}
