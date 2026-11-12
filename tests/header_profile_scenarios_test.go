package surf_test

import (
	"context"
	"fmt"
	"io"
	"math"
	"net"
	stdhttp "net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/surf"
	"github.com/enetx/surf/header"
	"github.com/stretchr/testify/require"
)

func TestHeaderProfileRedirectOriginScopeOnWire(t *testing.T) {
	for _, browser := range []string{"chrome", "firefox"} {
		for _, standard := range []bool{false, true} {
			for _, fetch := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/std=%v/fetch=%v", browser, standard, fetch), func(t *testing.T) {
					trusted, captured := newProfileWirePeer(t, 1, nil)
					u, err := url.Parse(trusted)
					require.NoError(t, err)
					address := u.Host
					u.Host = net.JoinHostPort("insecure.example", u.Port())
					insecure := u.String()
					im := surf.NewClient().Builder().Proxy("").Impersonate()
					var b *surf.Builder
					if browser == "chrome" {
						b = im.Chrome()
					} else {
						b = im.Firefox()
					}
					b.ForceHTTP1().With(func(c *surf.Client) error {
						c.GetTransport().(*http.Transport).DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
							return (&net.Dialer{}).DialContext(ctx, network, address)
						}
						return nil
					}, 1)
					b.With(func(c *surf.Client) error {
						base := c.GetClient().Transport
						c.GetClient().Transport = hintRoundTrip(func(req *http.Request) (*http.Response, error) {
							resp, err := base.RoundTrip(req)
							if err != nil {
								return resp, err
							}
							target := ""
							switch req.URL.Path {
							case "/start":
								target = insecure + "/middle"
								resp.Header.Set(header.ACCEPT_CH, header.SEC_CH_UA_ARCH)
							case "/middle":
								target = trusted + "/end"
							}
							if target != "" {
								resp.StatusCode = http.StatusFound
								resp.Status = "302 Found"
								resp.Header.Set("Location", target)
							}
							return resp, nil
						})
						return nil
					}, math.MaxInt)
					// Select the initial operation only: following hops must carry
					// its kind even when metadata is absent in the middle request.
					if fetch {
						b.With(func(r *surf.Request) error {
							if r.GetRequest().URL.Path == "/start" {
								r.Fetch()
							}
							return nil
						})
					}
					c := b.Timeout(10 * time.Second).Build().Unwrap()
					defer c.Close()
					if standard {
						resp, err := c.Std().Get(trusted + "/start")
						require.NoError(t, err)
						require.NoError(t, resp.Body.Close())
					} else {
						ownershipDo(t, c.Get(g.String(trusted+"/start")))
					}
					for i := range 3 {
						var request profileWireCapture
						select {
						case request = <-captured:
						case <-time.After(5 * time.Second):
							t.Fatal("missing origin transition request")
						}
						fields := make(stdhttp.Header)
						for _, field := range request.fields {
							fields.Add(field[0], field[1])
							if i == 1 {
								require.False(t, strings.HasPrefix(strings.ToLower(field[0]), "sec-fetch-"))
								require.False(t, strings.HasPrefix(strings.ToLower(field[0]), "sec-ch-"))
							}
						}
						require.Equal(t, !fetch, strings.Contains(fields.Get(header.ACCEPT), "text/html"), "request kind survives hop %d", i)
						if i == 1 {
							require.Equal(t, "gzip, deflate", fields.Get(header.ACCEPT_ENCODING))
						} else {
							require.Equal(t, "gzip, deflate, br, zstd", fields.Get(header.ACCEPT_ENCODING))
							mode := "navigate"
							if fetch {
								mode = "cors"
							}
							require.Equal(t, mode, fields.Get(header.SEC_FETCH_MODE))
						}
						if browser == "chrome" && i == 2 && !fetch {
							require.Equal(t, `"x86"`, fields.Get(header.SEC_CH_UA_ARCH), "return to a trustworthy origin uses its retained opt-in")
						} else {
							require.Empty(t, fields.Get(header.SEC_CH_UA_ARCH))
						}
					}
				})
			}
		}
	}
}

func TestHeaderProfileRequestScenarioSelectors(t *testing.T) {
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
				c := b.Timeout(10 * time.Second).Build().Unwrap()
				defer c.Close()
				for _, method := range []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"} {
					t.Run(method, func(t *testing.T) {
						r := c.Get(g.String(origin))
						r.GetRequest().Method = method
						// Reuse a logical request to ensure a selector replaces
						// generated defaults from its preceding scenario.
						for _, navigation := range []bool{false, true, false} {
							if navigation {
								r.Navigation()
							} else {
								r.Fetch()
							}
							result := r.Do()
							require.False(t, result.IsErr(), "%v", result.Err())
							response := result.Unwrap().GetResponse()
							_, err := io.Copy(io.Discard, response.Body)
							require.NoError(t, err)
							require.NoError(t, response.Body.Close())
							var observed profileWireCapture
							select {
							case observed = <-captured:
							case <-time.After(5 * time.Second):
								t.Fatal("missing scenario request")
							}
							fields := make(http.Header)
							for _, field := range observed.fields {
								fields.Add(field[0], field[1])
							}
							mode, dest, priority := "cors", "empty", "u=1, i"
							if browser == "firefox" {
								priority = "u=4"
							}
							if navigation {
								mode, dest, priority = "navigate", "document", "u=0, i"
							}
							if browser == "chrome" && major == 1 {
								priority = ""
							}
							require.Equal(t, method, observed.method)
							require.Equal(t, mode, fields.Get(header.SEC_FETCH_MODE))
							require.Equal(t, dest, fields.Get(header.SEC_FETCH_DEST))
							require.Equal(t, priority, fields.Get(header.PRIORITY))
							require.Equal(t, navigation, strings.Contains(fields.Get(header.ACCEPT), "text/html"))
							if !navigation {
								require.Equal(t, "*/*", fields.Get(header.ACCEPT))
								require.Empty(t, fields.Get(header.UPGRADE_INSECURE_REQUESTS))
							}
						}
					})
				}
			})
		}
	}
}
