package surf_test

import (
	"fmt"
	"io"
	stdhttp "net/http"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/http/http2"
	"github.com/enetx/surf"
	"github.com/enetx/surf/profiles"
	"github.com/stretchr/testify/require"
)

func profilePriorityBuilder(browser string) *surf.Builder {
	im := surf.NewClient().Builder().Proxy("").Timeout(10 * time.Second).Impersonate().Windows()
	if browser == "chrome" {
		return im.Chrome().ForceHTTP2()
	}
	return im.Firefox().ForceHTTP2()
}

// Weights are independently decoded from native HEADERS payloads: Chrome
// navigation/fetch 256/220 and Firefox 42/22. PriorityParam stores weight minus
// one. Literal Priority fields do not select the browser's internal priority.
func TestHeaderProfileHTTP2PriorityOnWire(t *testing.T) {
	for _, browser := range []string{"chrome", "firefox"} {
		for _, standard := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/std=%v", browser, standard), func(t *testing.T) {
				origin, captured := newProfileWirePeer(t, 2, nil)
				c := profilePriorityBuilder(browser).Build().Unwrap()
				defer c.Close()
				for _, method := range []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"} {
					for _, tc := range []struct {
						name       string
						kind       profiles.RequestKind
						mode       []string
						suppress   bool
						priority   string
						navigation bool
					}{
						{name: "automatic", navigation: method == "GET" || method == "HEAD"},
						{name: "fetch without metadata", kind: profiles.FetchRequest, suppress: true},
						{name: "navigation without metadata", kind: profiles.NavigationRequest, suppress: true, navigation: true},
						{name: "explicit cors", kind: profiles.NavigationRequest, mode: []string{"cors"}},
						{name: "explicit navigate", kind: profiles.FetchRequest, mode: []string{"navigate"}, navigation: true},
						{name: "literal priority independent", kind: profiles.FetchRequest, suppress: true, priority: "u=0, i"},
					} {
						t.Run(method+"/"+tc.name, func(t *testing.T) {
							fields := make(http.Header)
							if tc.suppress || tc.mode != nil {
								fields["Sec-Fetch-Mode"] = tc.mode
							}
							if tc.priority != "" {
								fields.Set("Priority", tc.priority)
							}
							if standard {
								r, err := stdhttp.NewRequest(method, origin, nil)
								require.NoError(t, err)
								r.Header = stdhttp.Header(fields)
								if tc.kind != profiles.AutomaticRequest {
									r = r.WithContext(profiles.WithRequestKind(r.Context(), tc.kind))
								}
								response, err := c.Std().Do(r)
								require.NoError(t, err)
								_, err = io.Copy(io.Discard, response.Body)
								require.NoError(t, err)
								require.NoError(t, response.Body.Close())
							} else {
								r := c.Get(g.String(origin))
								r.GetRequest().Method = method
								r.GetRequest().Header = fields
								if tc.kind == profiles.FetchRequest {
									r.Fetch()
								} else if tc.kind == profiles.NavigationRequest {
									r.Navigation()
								}
								result := r.Do()
								require.False(t, result.IsErr(), "%v", result.Err())
								response := result.Unwrap().GetResponse()
								_, err := io.Copy(io.Discard, response.Body)
								require.NoError(t, err)
								require.NoError(t, response.Body.Close())
							}
							select {
							case got := <-captured:
								weight := uint8(219)
								if tc.navigation {
									weight = 255
								}
								if browser == "firefox" {
									weight = 21
									if tc.navigation {
										weight = 41
									}
								}
								require.True(t, got.hasPriority)
								require.Equal(t, http2.PriorityParam{Weight: weight, Exclusive: browser == "chrome"}, got.priority)
							case <-time.After(5 * time.Second):
								t.Fatal("missing HEADERS priority")
							}
						})
					}
				}
			})
		}
	}
}

func TestHeaderProfileHTTP2PriorityUserOverrideOnWire(t *testing.T) {
	for _, browser := range []string{"chrome", "firefox"} {
		for _, policy := range []string{"fixed", "fixed equal navigation default", "callback", "nil callback"} {
			t.Run(browser+"/"+policy, func(t *testing.T) {
				origin, captured := newProfileWirePeer(t, 2, nil)
				b := profilePriorityBuilder(browser)
				settings := b.HTTP2Settings()
				want := http2.PriorityParam{Weight: 77, Exclusive: true}
				switch policy {
				case "fixed":
					settings.PriorityParam(want)
				case "fixed equal navigation default", "nil callback":
					want = http2.PriorityParam{Weight: 255, Exclusive: true}
					if browser == "firefox" {
						want = http2.PriorityParam{Weight: 41}
					}
					if policy == "nil callback" {
						settings.HeaderPriority(nil)
					} else {
						settings.PriorityParam(want)
					}
				case "callback":
					settings.PriorityParam(http2.PriorityParam{Weight: 3}).HeaderPriority(func(info http2.PriorityRequest) http2.PriorityParam {
						require.Equal(t, "GET", info.Method)
						return want
					})
				}
				c := settings.Set().Build().Unwrap()
				defer c.Close()
				ownershipDo(t, c.Get(g.String(origin)).Fetch())
				select {
				case got := <-captured:
					require.True(t, got.hasPriority)
					require.Equal(t, want, got.priority)
				case <-time.After(5 * time.Second):
					t.Fatal("missing overridden HEADERS priority")
				}
			})
		}
	}
}
