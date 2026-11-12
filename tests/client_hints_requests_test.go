package surf_test

import (
	"fmt"
	"io"
	stdhttp "net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/http/httptest"
	"github.com/enetx/surf"
	"github.com/enetx/surf/header"
	"github.com/stretchr/testify/require"
)

func TestClientHintsCriticalPOSTReplayAcrossProtocols(t *testing.T) {
	for _, major := range []int{1, 2, 3} {
		for _, mode := range []string{"buffered", "factory", "stream"} {
			t.Run(fmt.Sprintf("http%d/%s", major, mode), func(t *testing.T) {
				var requests atomic.Int32
				var checked atomic.Int32
				check := func(body io.Reader, fields map[string][]string) {
					data, err := io.ReadAll(body)
					if err != nil || string(data) != "payload" {
						t.Errorf("body=%q, err=%v", data, err)
					}
					if requests.Add(1) == 2 {
						h := http.Header(fields)
						if h.Get(header.SEC_CH_UA_ARCH) != `"x86"` || !strings.Contains(h.Get(header.COOKIE), "token=new") {
							t.Errorf("restart headers: %v", h)
						}
						checked.Add(1)
					}
				}
				responseHeaders := map[string]string{header.ACCEPT_CH: header.SEC_CH_UA_ARCH, header.CRITICAL_CH: header.SEC_CH_UA_ARCH, header.SET_COOKIE: "token=new; Path=/"}
				handler := func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
					check(r.Body, r.Header)
					for k, v := range responseHeaders {
						w.Header().Set(k, v)
					}
					fmt.Fprint(w, "ok")
				}
				var origin string
				if major == 3 {
					server, udp, target, err := createHTTP3TestServer(handler)
					require.NoError(t, err)
					go server.Serve(udp)
					defer server.Close()
					defer udp.Close()
					origin = target
				} else {
					server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						check(r.Body, r.Header)
						for k, v := range responseHeaders {
							w.Header().Set(k, v)
						}
						fmt.Fprint(w, "ok")
					}))
					server.EnableHTTP2 = major == 2
					server.StartTLS()
					defer server.Close()
					origin = server.URL
				}
				b := surf.NewClient().Builder().Proxy("").Impersonate().Chrome().Session().Timeout(5 * time.Second)
				switch major {
				case 1:
					b.ForceHTTP1()
				case 2:
					b.ForceHTTP2()
				case 3:
					b.ForceHTTP3()
				}
				b.With(func(r *surf.Request) error {
					r.SetHeaders(header.SEC_FETCH_MODE, "navigate")
					r.SetHeaders(header.SEC_FETCH_DEST, "document")
					return nil
				}, 1)
				c := b.Build().Unwrap()
				defer c.Close()
				request := c.Post(g.String(origin))
				switch mode {
				case "buffered":
					request.Body("payload")
				case "factory":
					request.StreamingBodyFactory(func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("payload")), nil }, 7)
				case "stream":
					request.StreamingBody(strings.NewReader("payload"), 7)
				}
				result := request.Do()
				require.False(t, result.IsErr(), "%v", result.Err())
				require.Equal(t, g.String("ok"), result.Ok().Body.String().Unwrap())
				want := int32(2)
				if mode == "stream" {
					want = 1
				}
				require.Equal(t, want, requests.Load())
				require.Equal(t, want-1, checked.Load())
			})
		}
	}
}
