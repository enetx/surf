package surf_test

import (
	"fmt"
	"io"
	stdhttp "net/http"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/surf"
	"github.com/enetx/surf/header"
	"github.com/enetx/surf/profiles"
	"github.com/stretchr/testify/require"
)

// Browser navigation context exists independently of emitted Fetch Metadata.
// Suppressing either field must not silently turn a document into a subresource
// for Accept-CH/Critical-CH processing. A true Fetch must still ignore that policy.
func TestClientHintsNavigationWithoutMetadataOnWire(t *testing.T) {
	for _, major := range []int{1, 2, 3} {
		for _, standard := range []bool{false, true} {
			for _, suppressed := range [][]string{{header.SEC_FETCH_MODE}, {header.SEC_FETCH_DEST}, {header.SEC_FETCH_MODE, header.SEC_FETCH_DEST}} {
				for _, fetch := range []bool{false, true} {
					t.Run(fmt.Sprintf("http%d/std=%v/suppressed=%v/fetch=%v", major, standard, suppressed, fetch), func(t *testing.T) {
						origin, captures := newProfileWirePeer(t, major, http.Header{
							header.ACCEPT_CH: {header.SEC_CH_UA_ARCH}, header.CRITICAL_CH: {header.SEC_CH_UA_ARCH},
						})
						b := surf.NewClient().Builder().Proxy("").Timeout(10 * time.Second).Impersonate().Chrome()
						switch major {
						case 1:
							b.ForceHTTP1()
						case 2:
							b.ForceHTTP2()
						case 3:
							b.ForceHTTP3()
						}
						c := b.Build().Unwrap()
						defer c.Close()
						kind := profiles.NavigationRequest
						if fetch {
							kind = profiles.FetchRequest
						}
						if standard {
							r, err := stdhttp.NewRequest(http.MethodGet, origin, nil)
							require.NoError(t, err)
							r = r.WithContext(profiles.WithRequestKind(r.Context(), kind))
							for _, name := range suppressed {
								r.Header[name] = nil
							}
							response, err := c.Std().Do(r)
							require.NoError(t, err)
							_, err = io.Copy(io.Discard, response.Body)
							require.NoError(t, err)
							require.NoError(t, response.Body.Close())
						} else {
							r := c.Get(g.String(origin)).Navigation()
							if fetch {
								r.Fetch()
							}
							for _, name := range suppressed {
								r.GetRequest().Header[name] = nil
							}
							ownershipDo(t, r)
						}
						attempts := 2
						if fetch {
							attempts = 1
							require.Empty(t, c.ClientHintNames(g.String(origin)))
						} else {
							require.Equal(t, []string{header.SEC_CH_UA_ARCH}, c.ClientHintNames(g.String(origin)))
						}
						for i := range attempts {
							select {
							case request := <-captures:
								fields := make(http.Header)
								for _, field := range request.fields {
									fields.Add(field[0], field[1])
								}
								for _, name := range suppressed {
									require.Empty(t, fields.Values(name), "suppressed field remains absent after restart")
								}
								if i == 0 {
									require.Empty(t, fields.Get(header.SEC_CH_UA_ARCH))
								} else {
									require.Equal(t, `"x86"`, fields.Get(header.SEC_CH_UA_ARCH))
								}
							case <-time.After(5 * time.Second):
								t.Fatal("missing navigation/restart wire request")
							}
						}
						select {
						case extra := <-captures:
							t.Fatalf("unexpected third restart: %+v", extra.fields)
						default:
						}
					})
				}
			}
		}
	}
}

func TestClientHintsStandaloneNavigationClassification(t *testing.T) {
	for _, tc := range []struct {
		name       string
		kind       profiles.RequestKind
		headers    http.Header
		navigation bool
	}{
		{name: "bare GET remains unspecified"},
		{name: "known navigation", kind: profiles.NavigationRequest, navigation: true},
		{name: "known fetch", kind: profiles.FetchRequest},
		{name: "explicit navigation mode wins", kind: profiles.FetchRequest, headers: http.Header{header.SEC_FETCH_MODE: {"navigate"}}, navigation: true},
		{name: "automatic remains unspecified", kind: profiles.AutomaticRequest},
		{name: "explicit cors wins", kind: profiles.NavigationRequest, headers: http.Header{header.SEC_FETCH_MODE: {"cors"}}},
		{name: "explicit image wins", kind: profiles.NavigationRequest, headers: http.Header{header.SEC_FETCH_DEST: {"image"}}},
		{name: "legacy document pair", headers: http.Header{header.SEC_FETCH_MODE: {"navigate"}, header.SEC_FETCH_DEST: {"document"}}, navigation: true},
		{name: "incomplete legacy pair", headers: http.Header{header.SEC_FETCH_MODE: {"navigate"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			c := hintClient(t, nil, func(req *http.Request) (*http.Response, error) {
				calls++
				return hintResponse(req, http.Header{header.ACCEPT_CH: {header.SEC_CH_UA_ARCH}, header.CRITICAL_CH: {header.SEC_CH_UA_ARCH}}), nil
			})
			r := c.Get("https://a.example/")
			if tc.headers != nil {
				r.GetRequest().Header = tc.headers.Clone()
			}
			if tc.name != "bare GET remains unspecified" {
				r.WithContext(profiles.WithRequestKind(r.GetRequest().Context(), tc.kind))
			}
			ownershipDo(t, r)
			want := 1
			if tc.navigation {
				want = 2
				require.Equal(t, []string{header.SEC_CH_UA_ARCH}, c.ClientHintNames("https://a.example/"))
			} else {
				require.Empty(t, c.ClientHintNames("https://a.example/"))
			}
			require.Equal(t, want, calls)
		})
	}
}
