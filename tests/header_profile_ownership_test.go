package surf_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	stdhttp "net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/surf"
	"github.com/enetx/surf/header"
	"github.com/enetx/surf/profiles"
	"github.com/enetx/surf/profiles/chrome"
	chromedesktop "github.com/enetx/surf/profiles/chrome/desktop"
	"github.com/stretchr/testify/require"
)

func TestHeaderProfileOwnershipCustomVariantCallbacks(t *testing.T) {
	for _, modern := range []bool{false, true} {
		for _, explicit := range []bool{false, true} {
			name := "legacy"
			if modern {
				name = "factory"
			}
			if explicit {
				name += "/explicit"
			}
			t.Run(name, func(t *testing.T) {
				origin, captures := newProfileWirePeer(t, 1, nil)
				fields := func() g.MapOrd[g.String, g.String] {
					h := g.NewMapOrd[g.String, g.String]()
					h.Insert("x-first", "one")
					h.Insert("x-second", "two")
					h.Insert("x-third", "three")
					return h
				}
				// Variant is a public customization point. Build snapshots its
				// selection, so restore the exported preset before issuing a request.
				client := func() *surf.Client {
					original := chrome.Desktop
					defer func() { chrome.Desktop = original }()
					variant := original
					variant.BuildRequestHeaders = nil
					variant.BuildHeaders = func(profiles.OSKey) *g.MapOrd[g.String, g.String] { h := fields(); return &h }
					variant.Headers = nil
					variant.HeaderCase = func(profiles.HeaderContext) []string { return []string{"x-fIrSt"} }
					variant.ClientHints = nil
					variant.ProtocolHeaders = func(h http.Header, _ int) { h[http.HeaderOrderKey] = []string{"x-third", "x-first", "x-second"} }
					variant.RequestHeaders = func(r *http.Request, _ int) {
						r.Header[http.HeaderOrderKey] = []string{"x-second", "x-third", "x-first"}
					}
					variant.ClientHintsOrder = func(r *http.Request, _ bool) {
						r.Header[http.HeaderOrderKey] = []string{"x-third", "x-second", "x-first"}
					}
					if modern {
						variant.BuildRequestHeaders = func(profiles.HeaderContext) g.MapOrd[g.String, g.String] { return fields() }
						variant.BuildHeaders = func(profiles.OSKey) *g.MapOrd[g.String, g.String] { panic("factory invoked legacy defaults") }
						variant.ProtocolHeaders = func(http.Header, int) { panic("factory invoked legacy protocol callback") }
						variant.RequestHeaders = func(*http.Request, int) { panic("factory invoked legacy request callback") }
						variant.ClientHintsOrder = func(*http.Request, bool) { panic("factory invoked legacy hint callback") }
					}
					chrome.Desktop = variant
					return surf.NewClient().Builder().Proxy("").Impersonate().Chrome().ForceHTTP1().Timeout(10 * time.Second).Build().Unwrap()
				}()
				defer client.Close()
				request := client.Get(g.String(origin))
				if explicit {
					request.GetRequest().Header[http.HeaderOrderKey] = []string{"x-second", "x-first", "x-third"}
				}
				ownershipDo(t, request)
				var names []string
				for _, field := range (<-captures).fields {
					if strings.HasPrefix(strings.ToLower(field[0]), "x-") {
						names = append(names, strings.ToLower(field[0]))
					}
					if strings.EqualFold(field[0], "x-first") {
						require.Equal(t, "x-fIrSt", field[0], "public casing hook also works with the legacy factory contract")
					}
				}
				want := []string{"x-third", "x-second", "x-first"}
				if modern {
					want = []string{"x-first", "x-second", "x-third"}
				}
				if explicit {
					want = []string{"x-second", "x-first", "x-third"}
				}
				require.Equal(t, want, names)
			})
		}
	}
}

type ownershipRoundTrip func(*http.Request) (*http.Response, error)

func (f ownershipRoundTrip) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func ownershipResponse(req *http.Request, status int, headers http.Header) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     headers,
		Body:       io.NopCloser(strings.NewReader("ok")),
		Request:    req,
	}
}

func ownershipClient(t *testing.T, configure func(*surf.Builder), trip ownershipRoundTrip) (*surf.Client, *surf.Builder) {
	t.Helper()
	b := surf.NewClient().Builder().Proxy("").Impersonate().Windows().Chrome()
	if configure != nil {
		configure(b)
	}
	b.With(func(c *surf.Client) error {
		c.GetClient().Transport = trip
		return nil
	}, math.MaxInt)
	c := b.Build().Unwrap()
	t.Cleanup(func() { require.NoError(t, c.Close()) })
	return c, b
}

func ownershipDo(t *testing.T, req *surf.Request) {
	t.Helper()
	result := req.Do()
	require.False(t, result.IsErr(), "%v", result.Err())
	response := result.Unwrap()
	require.Equal(t, g.String("ok"), response.Body.String().Unwrap())
	require.NoError(t, response.Body.Close())
}

func ownershipValues(h http.Header, name string) ([]string, bool) {
	var values []string
	present := false
	for key, fields := range h {
		if strings.EqualFold(key, name) {
			if !present {
				values = slices.Clone(fields)
			} else {
				values = append(values, fields...)
			}
			present = true
		}
	}
	return values, present
}

func TestHeaderProfileOwnershipExplicitValues(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value []string
	}{
		{name: "mixed case", value: []string{"application/x-explicit"}},
		{name: "empty value", value: []string{""}},
		{name: "nil values"},
		{name: "empty values", value: []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var received http.Header
			c, _ := ownershipClient(t, nil, func(req *http.Request) (*http.Response, error) {
				received = req.Header.Clone()
				return ownershipResponse(req, 200, nil), nil
			})
			req := c.Get("https://example.com/")
			for _, name := range []string{"aCcEpT", "uSeR-aGeNt", "sEc-Ch-Ua"} {
				req.GetRequest().Header[name] = slices.Clone(tc.value)
			}
			ownershipDo(t, req)
			for _, name := range []string{header.ACCEPT, header.USER_AGENT, header.SEC_CH_UA} {
				values, present := ownershipValues(received, name)
				require.True(t, present)
				require.Equal(t, []string(tc.value), values)
				var occurrences int
				for key := range received {
					if strings.EqualFold(key, name) {
						occurrences++
					}
				}
				require.Equal(t, 1, occurrences, "profile must not add a canonical alias for %s", name)
			}
			for _, key := range []string{http.HeaderOrderKey, http.PHeaderOrderKey, http.HeaderCaseKey} {
				_, present := received[key]
				require.False(t, present, "logical profile defaults must not create %s", key)
			}
		})
	}
}

func TestHeaderProfileOwnershipPresetIdenticalExplicitOrder(t *testing.T) {
	var requests []*http.Request
	c, _ := ownershipClient(t, nil, func(req *http.Request) (*http.Response, error) {
		requests = append(requests, req.Clone(req.Context()))
		return ownershipResponse(req, 200, http.Header{
			"Accept-Ch":   {header.SEC_CH_UA_ARCH},
			"Critical-Ch": {header.SEC_CH_UA_ARCH},
		}), nil
	})
	req := c.Get("https://example.com/")
	preset := chromedesktop.BuildRequestHeaders(profiles.HeaderContext{Request: req.GetRequest(), OS: profiles.Windows, Protocol: 2})
	var want []string
	for _, name := range preset.Keys() {
		if !strings.HasPrefix(name.Std(), ":") {
			want = append(want, strings.ToLower(name.Std()))
		}
	}
	req.SetHeaders(preset)
	preset.Insert("X-After-SetHeaders", "mutation")
	ownershipDo(t, req)
	require.Len(t, requests, 2)
	for _, request := range requests {
		require.Equal(t, want, request.Header[http.HeaderOrderKey], "explicit order identical to a preset still belongs to the application")
		require.Empty(t, request.Header.Get("X-After-SetHeaders"))
	}
	require.Empty(t, requests[0].Header.Get(header.SEC_CH_UA_ARCH))
	require.Equal(t, `"x86"`, requests[1].Header.Get(header.SEC_CH_UA_ARCH))
}

func TestHeaderProfileOwnershipOrderedSetters(t *testing.T) {
	for _, add := range []bool{false, true} {
		name := "SetHeaders"
		if add {
			name = "AddHeaders"
		}
		t.Run(name, func(t *testing.T) {
			for _, gStrings := range []bool{false, true} {
				name := "string"
				if gStrings {
					name = "g.String"
				}
				t.Run(name, func(t *testing.T) {
					var received http.Header
					c, _ := ownershipClient(t, nil, func(req *http.Request) (*http.Response, error) {
						received = req.Header.Clone()
						return ownershipResponse(req, 200, nil), nil
					})
					req := c.Get("https://example.com/").SetHeaders("X-Multi", "first")
					fields := g.NewMapOrd[string, string]()
					fields.Insert("X-Last", "last")
					fields.Insert("aCcEpT", "application/x-explicit")
					fields.Insert(":path", "")
					fields.Insert("X-Multi", "second")
					fields.Insert("X-Slot", "")
					fields.Insert(":method", "")
					var input any = fields
					if gStrings {
						converted := g.NewMapOrd[g.String, g.String]()
						fields.Iter().ForEach(func(name, value string) { converted.Insert(g.String(name), g.String(value)) })
						input = converted
					}
					if add {
						req.AddHeaders(input)
					} else {
						req.SetHeaders(input)
					}
					ownershipDo(t, req)
					require.Equal(t, []string{"x-last", "accept", "x-multi", "x-slot"}, received[http.HeaderOrderKey])
					require.Equal(t, []string{":path", ":method"}, received[http.PHeaderOrderKey])
					require.Equal(t, "application/x-explicit", received.Get(header.ACCEPT))
					want := []string{"second"}
					if add {
						want = []string{"first", "second"}
					}
					require.Equal(t, want, received.Values("X-Multi"))
					_, sent := received["X-Slot"]
					require.False(t, sent, "empty MapOrd values reserve a position without adding a field")
					switch original := input.(type) {
					case g.MapOrd[string, string]:
						require.EqualValues(t, 6, original.Len())
					case g.MapOrd[g.String, g.String]:
						require.EqualValues(t, 6, original.Len())
					}
				})
			}
		})
	}
}

func TestHeaderProfileOwnershipIndependentMetadata(t *testing.T) {
	for _, key := range []string{http.HeaderOrderKey, http.PHeaderOrderKey, http.HeaderCaseKey} {
		t.Run(key, func(t *testing.T) {
			for _, tc := range []struct {
				name   string
				values []string
			}{
				{name: "nil"},
				{name: "empty", values: []string{}},
				{name: "custom", values: []string{"x-explicit", ":path", "sEc-Ch-Ua"}},
			} {
				t.Run(tc.name, func(t *testing.T) {
					var received http.Header
					c, _ := ownershipClient(t, nil, func(req *http.Request) (*http.Response, error) {
						received = req.Header.Clone()
						return ownershipResponse(req, 200, nil), nil
					})
					req := c.Get("https://example.com/")
					req.GetRequest().Header[key] = slices.Clone(tc.values)
					ownershipDo(t, req)
					values, present := received[key]
					require.True(t, present)
					require.Equal(t, tc.values, values)
					for _, other := range []string{http.HeaderOrderKey, http.PHeaderOrderKey, http.HeaderCaseKey} {
						if other != key {
							_, present := received[other]
							require.False(t, present, "ownership of %s must not synthesize %s on logical requests", key, other)
						}
					}
				})
			}
		})
	}
}

func TestHeaderProfileOwnershipSameValueInMiddleware(t *testing.T) {
	var initialAccept string
	var received http.Header
	c, _ := ownershipClient(t, func(b *surf.Builder) {
		b.With(func(req *surf.Request) error {
			initialAccept = req.GetRequest().Header.Get(header.ACCEPT)
			req.SetHeaders("aCcEpT", initialAccept)
			req.SetHeaders(header.SEC_FETCH_MODE, "cors")
			return nil
		})
	}, func(req *http.Request) (*http.Response, error) {
		received = req.Header.Clone()
		return ownershipResponse(req, 200, nil), nil
	})
	ownershipDo(t, c.Get("https://example.com/"))
	require.Contains(t, initialAccept, "text/html", "profile defaults must remain visible to request middleware")
	require.Equal(t, initialAccept, received.Get(header.ACCEPT), "an explicit setter retains ownership even when its value equals the old default")
	require.Equal(t, "cors", received.Get(header.SEC_FETCH_MODE))
	require.Equal(t, "empty", received.Get(header.SEC_FETCH_DEST))
	require.Empty(t, received.Get(header.UPGRADE_INSECURE_REQUESTS))
	require.Empty(t, received.Get(header.SEC_FETCH_USER))
}

func TestHeaderProfileOwnershipRepeatedRequestTypeChanges(t *testing.T) {
	var received []http.Header
	c, _ := ownershipClient(t, nil, func(req *http.Request) (*http.Response, error) {
		received = append(received, req.Header.Clone())
		return ownershipResponse(req, 200, nil), nil
	})
	req := c.Get("https://example.com/")
	ownershipDo(t, req)
	req.GetRequest().Method = http.MethodPost
	ownershipDo(t, req)
	req.GetRequest().Method = http.MethodGet
	req.SetHeaders(header.SEC_FETCH_MODE, "cors")
	ownershipDo(t, req)
	req.SetHeaders(header.SEC_FETCH_MODE, "navigate")
	ownershipDo(t, req)
	require.Len(t, received, 4)
	for _, index := range []int{0, 3} {
		require.Equal(t, "navigate", received[index].Get(header.SEC_FETCH_MODE))
		require.Equal(t, "document", received[index].Get(header.SEC_FETCH_DEST))
		require.Equal(t, "1", received[index].Get(header.UPGRADE_INSECURE_REQUESTS))
		require.Contains(t, received[index].Get(header.ACCEPT), "text/html")
	}
	for _, index := range []int{1, 2} {
		require.Equal(t, "cors", received[index].Get(header.SEC_FETCH_MODE))
		require.Equal(t, "empty", received[index].Get(header.SEC_FETCH_DEST))
		require.Empty(t, received[index].Get(header.UPGRADE_INSECURE_REQUESTS))
		require.Empty(t, received[index].Get(header.SEC_FETCH_USER))
		require.Equal(t, "*/*", received[index].Get(header.ACCEPT))
	}
}

func TestHeaderProfileOwnershipBuilderProfileSnapshot(t *testing.T) {
	var received []http.Header
	c, b := ownershipClient(t, nil, func(req *http.Request) (*http.Response, error) {
		received = append(received, req.Header.Clone())
		return ownershipResponse(req, 200, nil), nil
	})
	reused := c.Get("https://example.com/")
	ownershipDo(t, reused)
	b.Impersonate().MacOS().Chrome()
	ownershipDo(t, c.Get("https://example.com/"))
	require.Equal(t, received[0], received[1], "unbuilt profile changes must not affect the current client")
	require.Same(t, c, b.Build().Unwrap())
	ownershipDo(t, reused)
	require.Contains(t, received[2].Get(header.USER_AGENT), "Macintosh")
	require.Equal(t, `"macOS"`, received[2].Get(header.SEC_CH_UA_PLATFORM))
	b.Impersonate().Firefox()
	ownershipDo(t, c.Get("https://example.com/"))
	require.Equal(t, received[2], received[3], "profile replacement becomes active only at Build")
	b.Build().Unwrap()
	ownershipDo(t, reused)
	require.Contains(t, received[4].Get(header.USER_AGENT), "Firefox/160")
	require.Empty(t, received[4].Get(header.SEC_CH_UA))
	require.Empty(t, received[4].Get(header.SEC_CH_UA_PLATFORM))
	require.Empty(t, received[4].Get(header.SEC_CH_UA_ARCH))
}

func TestHeaderProfileOwnershipBuilderHintsSnapshot(t *testing.T) {
	var received http.Header
	c, b := ownershipClient(t, nil, func(req *http.Request) (*http.Response, error) {
		received = req.Header.Clone()
		return ownershipResponse(req, 200, http.Header{"Accept-Ch": {header.SEC_CH_UA_ARCH}}), nil
	})
	ownershipDo(t, c.Get("https://example.com/"))
	ownershipDo(t, c.Get("https://example.com/"))
	require.Equal(t, `"x86"`, received.Get(header.SEC_CH_UA_ARCH))
	b.ClientHints().Architecture("arm").Set()
	ownershipDo(t, c.Get("https://example.com/"))
	require.Equal(t, `"x86"`, received.Get(header.SEC_CH_UA_ARCH), "unbuilt hint overrides must not mutate the active transport snapshot")
	require.Same(t, c, b.Build().Unwrap())
	ownershipDo(t, c.Get("https://example.com/"))
	ownershipDo(t, c.Get("https://example.com/"))
	require.Equal(t, `"arm"`, received.Get(header.SEC_CH_UA_ARCH))
}

func TestHeaderProfileOwnershipRedirects(t *testing.T) {
	for _, stdAdapter := range []bool{false, true} {
		adapter := "surf"
		if stdAdapter {
			adapter = "std"
		}
		t.Run(adapter, func(t *testing.T) {
			for _, crossOrigin := range []bool{false, true} {
				origin := "same origin"
				if crossOrigin {
					origin = "cross origin"
				}
				t.Run(origin, func(t *testing.T) {
					for _, method := range []string{http.MethodGet, http.MethodPost} {
						t.Run(method, func(t *testing.T) {
							var requests []*http.Request
							var bodies []string
							c, _ := ownershipClient(t, func(b *surf.Builder) { b.Session() }, func(req *http.Request) (*http.Response, error) {
								requests = append(requests, req.Clone(req.Context()))
								var data []byte
								if req.Body != nil {
									var err error
									data, err = io.ReadAll(req.Body)
									require.NoError(t, err)
								}
								bodies = append(bodies, string(data))
								if len(requests) == 1 {
									target := "https://a.example/next"
									if crossOrigin {
										target = "https://b.example/next"
									}
									return ownershipResponse(req, 302, http.Header{"Location": {target}, "Set-Cookie": {"token=new; Path=/"}}), nil
								}
								return ownershipResponse(req, 200, nil), nil
							})
							fields := http.Header{
								"Accept":             {"application/x-owner"},
								"Authorization":      {"Bearer owner"},
								"Cookie":             {"explicit=1"},
								http.HeaderOrderKey:  {"cookie", "accept", "authorization"},
								http.PHeaderOrderKey: {":path", ":method", ":scheme", ":authority"},
								http.HeaderCaseKey:   {"aCcEpT"},
							}
							if stdAdapter {
								var body io.Reader
								if method == http.MethodPost {
									body = strings.NewReader("payload")
								}
								req, err := stdhttp.NewRequest(method, "https://a.example/start", body)
								require.NoError(t, err)
								req.Header = stdhttp.Header(fields.Clone())
								resp, err := c.Std().Do(req)
								require.NoError(t, err)
								require.NoError(t, resp.Body.Close())
							} else {
								req := c.Get("https://a.example/start")
								req.GetRequest().Method = method
								req.GetRequest().Header = fields.Clone()
								if method == http.MethodPost {
									req.Body("payload")
								}
								ownershipDo(t, req)
							}
							require.Len(t, requests, 2)
							require.Equal(t, http.MethodGet, requests[1].Method)
							require.Empty(t, bodies[1], "POST-to-GET redirect must drop the request body")
							for _, req := range requests {
								require.Equal(t, "application/x-owner", req.Header.Get(header.ACCEPT))
								for _, key := range []string{http.HeaderOrderKey, http.PHeaderOrderKey, http.HeaderCaseKey} {
									require.Equal(t, fields[key], req.Header[key])
								}
							}
							if crossOrigin {
								require.Empty(t, requests[1].Header.Get(header.AUTHORIZATION))
								require.Empty(t, requests[1].Header.Get(header.COOKIE))
							} else {
								require.Equal(t, "Bearer owner", requests[1].Header.Get(header.AUTHORIZATION))
								require.Contains(t, requests[1].Header.Get(header.COOKIE), "explicit=1")
								require.Contains(t, requests[1].Header.Get(header.COOKIE), "token=new")
							}
							if method == http.MethodPost {
								// Redirect changes method/body, not the Fetch request mode.
								// https://fetch.spec.whatwg.org/#http-redirect-fetch
								for _, req := range requests {
									require.Equal(t, "cors", req.Header.Get(header.SEC_FETCH_MODE))
									require.Equal(t, "empty", req.Header.Get(header.SEC_FETCH_DEST))
									require.Empty(t, req.Header.Get(header.UPGRADE_INSECURE_REQUESTS))
								}
							}
						})
					}
				})
			}
		})
	}
}

func TestHeaderProfileOwnershipStdContext(t *testing.T) {
	type ownershipContextKey struct{}
	ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), ownershipContextKey{}, "original"), 10*time.Second)
	defer cancel()
	var requests []*http.Request
	c, _ := ownershipClient(t, nil, func(req *http.Request) (*http.Response, error) {
		requests = append(requests, req.Clone(req.Context()))
		if len(requests) == 1 {
			return ownershipResponse(req, 302, http.Header{"Location": {"/next"}}), nil
		}
		return ownershipResponse(req, 200, nil), nil
	})
	req, err := stdhttp.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/start", nil)
	require.NoError(t, err)
	req.Header.Set("Accept", "application/x-explicit")
	response, err := c.Std().Do(req)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	require.Len(t, requests, 2)
	wantDeadline, _ := ctx.Deadline()
	for _, request := range requests {
		require.Equal(t, "original", request.Context().Value(ownershipContextKey{}))
		deadline, ok := request.Context().Deadline()
		require.True(t, ok)
		require.Equal(t, wantDeadline, deadline)
		require.Equal(t, "application/x-explicit", request.Header.Get(header.ACCEPT))
	}
	cancel()
	for _, request := range requests {
		require.ErrorIs(t, request.Context().Err(), context.Canceled)
	}
	require.Equal(t, "original", response.Request.Context().Value(ownershipContextKey{}))
	require.ErrorIs(t, response.Request.Context().Err(), context.Canceled)
}

func TestHeaderProfileOwnershipRedirectChainDropsEntityFields(t *testing.T) {
	for _, browser := range []string{"chrome", "firefox"} {
		for _, standard := range []bool{false, true} {
			for _, major := range []int{1, 2, 3} {
				for _, statuses := range [][]int{{302, 302}, {307, 303, 302}} {
					name := browser + "/surf/"
					if standard {
						name = browser + "/std/"
					}
					for _, status := range statuses {
						name += http.StatusText(status) + "/"
					}
					name += fmt.Sprintf("http%d", major)
					t.Run(name, func(t *testing.T) {
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
						hop := 0
						b.With(func(c *surf.Client) error {
							base := c.GetClient().Transport
							c.GetClient().Transport = ownershipRoundTrip(func(req *http.Request) (*http.Response, error) {
								resp, err := base.RoundTrip(req)
								if err == nil && hop < len(statuses) {
									resp.StatusCode = statuses[hop]
									resp.Status = http.StatusText(resp.StatusCode)
									resp.Header.Set("Location", req.URL.String()+"next")
								}
								hop++
								return resp, err
							})
							return nil
						}, math.MaxInt)
						c := b.Build().Unwrap()
						defer c.Close()
						fields := http.Header{
							"Sec-Fetch-Mode":   {"navigate"},
							"Origin":           {"https://a.example"},
							"Content-Type":     {"application/x-original"},
							"Content-Language": {"en"},
							"Content-Location": {"/entity"},
						}
						if standard {
							req, err := stdhttp.NewRequest(http.MethodPost, origin+"/start", strings.NewReader("payload"))
							require.NoError(t, err)
							req.Header = stdhttp.Header(fields)
							resp, err := c.Std().Do(req)
							require.NoError(t, err)
							require.NoError(t, resp.Body.Close())
						} else {
							req := c.Post(g.String(origin + "/start")).Body("payload")
							req.GetRequest().Header = fields
							ownershipDo(t, req)
						}
						require.Equal(t, len(statuses)+1, hop)
						for i := range hop {
							var req profileWireCapture
							select {
							case req = <-captured:
							case <-time.After(5 * time.Second):
								t.Fatal("redirect request missing from wire")
							}
							fields := make(http.Header)
							for _, field := range req.fields {
								fields.Add(field[0], field[1])
							}
							require.Equal(t, "navigate", fields.Get(header.SEC_FETCH_MODE), "hop %d", i)
							if major == 2 {
								weight := uint8(255)
								if browser == "firefox" {
									weight = 41
								}
								require.True(t, req.hasPriority)
								require.Equal(t, weight, req.priority.Weight, "navigation priority survives hop %d", i)
							}
							if req.method == http.MethodPost {
								require.Equal(t, "payload", req.body)
								require.Equal(t, "https://a.example", fields.Get(header.ORIGIN))
								require.Equal(t, "application/x-original", fields.Get(header.CONTENT_TYPE))
								continue
							}
							require.Equal(t, http.MethodGet, req.method)
							require.Empty(t, req.body)
							for _, field := range []string{header.ORIGIN, header.CONTENT_TYPE, header.CONTENT_LENGTH, "content-language", "content-location"} {
								require.Empty(t, fields.Get(field), "old %s returned on redirect hop %d", field, i)
							}
						}
					})
				}
			}
		}
	}
}

func TestHeaderProfileOwnershipStdCancellation(t *testing.T) {
	entered := make(chan context.Context, 1)
	c, _ := ownershipClient(t, nil, func(req *http.Request) (*http.Response, error) {
		entered <- req.Context()
		<-req.Context().Done()
		return nil, req.Context().Err()
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := stdhttp.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/", nil)
	require.NoError(t, err)
	result := make(chan error, 1)
	go func() {
		response, err := c.Std().Do(req)
		if response != nil {
			response.Body.Close()
		}
		result <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("request did not reach the transport")
	}
	cancel()
	select {
	case err := <-result:
		require.True(t, errors.Is(err, context.Canceled), "%v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("standard adapter lost request cancellation")
	}
}
