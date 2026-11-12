package surf_test

import (
	"io"
	"math"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/surf"
	"github.com/enetx/surf/header"
	chromecommon "github.com/enetx/surf/profiles/chrome/common"
	"github.com/stretchr/testify/require"
)

const allUAHints = "sec-ch-ua-full-version, sec-ch-ua-arch, sec-ch-ua-platform-version, sec-ch-ua-model, sec-ch-ua-bitness, sec-ch-ua-wow64, sec-ch-ua-full-version-list, sec-ch-ua-form-factors"

func TestClientHintsConfiguredLowEntropyAndExplicitOwnership(t *testing.T) {
	t.Parallel()
	for _, explicit := range []bool{false, true} {
		name := "configured"
		if explicit {
			name = "explicit preset-identical middleware values"
		}
		t.Run(name, func(t *testing.T) {
			var received http.Header
			c := hintClient(t, func(b *surf.Builder) {
				b.Impersonate().Windows().Chrome()
				b.ClientHints().Value(header.SEC_CH_UA, `"Configured";v="158"`).
					Value(header.SEC_CH_UA_MOBILE, "?1").Value(header.SEC_CH_UA_PLATFORM, `"OtherOS"`).Set()
				if explicit {
					b.With(func(r *surf.Request) error {
						r.SetHeaders(g.Map[string, string]{
							header.SEC_CH_UA:        chromecommon.SecCHUA,
							header.SEC_CH_UA_MOBILE: "?0", header.SEC_CH_UA_PLATFORM: `"Windows"`,
						})
						return nil
					})
				}
			}, func(r *http.Request) (*http.Response, error) {
				received = r.Header.Clone()
				return hintResponse(r, nil), nil
			})
			ownershipDo(t, c.Get("https://example.com/"))
			want := []string{`"Configured";v="158"`, "?1", `"OtherOS"`}
			if explicit {
				want = []string{chromecommon.SecCHUA, "?0", `"Windows"`}
			}
			for i, field := range []string{header.SEC_CH_UA, header.SEC_CH_UA_MOBILE, header.SEC_CH_UA_PLATFORM} {
				require.Equal(t, want[i], received.Get(field), field)
			}
		})
	}
}

func TestClientHintsBuilderProfileDefaultsAndCallOrder(t *testing.T) {
	t.Parallel()
	for _, os := range []string{"windows", "mac", "linux", "android"} {
		for _, before := range []bool{false, true} {
			t.Run(os+"/before="+map[bool]string{false: "false", true: "true"}[before], func(t *testing.T) {
				var last http.Header
				overrides := func(b *surf.Builder) {
					b.ClientHints().Architecture("arm").PlatformVersion("99.0.1").FullVersion("158.1.2.3").WoW64(true).FormFactors("Desktop", "Tablet").Model(`a"b\c`).Set()
				}
				c := hintClient(t, func(b *surf.Builder) {
					if before {
						overrides(b)
					}
					im := b.Impersonate()
					switch os {
					case "mac":
						im.MacOS()
					case "linux":
						im.Linux()
					case "android":
						im.Android()
					}
					im.Chrome()
					if !before {
						overrides(b)
					}
				}, func(r *http.Request) (*http.Response, error) {
					last = r.Header.Clone()
					return hintResponse(r, http.Header{"Accept-Ch": {allUAHints}}), nil
				})
				hintRequest(t, c, "https://example.com/", nil)
				hintRequest(t, c, "https://example.com/", nil)
				require.Equal(t, `"arm"`, last.Get(header.SEC_CH_UA_ARCH))
				require.Equal(t, `"99.0.1"`, last.Get(header.SEC_CH_UA_PLATFORM_VERSION))
				require.Equal(t, `"158.1.2.3"`, last.Get(header.SEC_CH_UA_FULL_VERSION))
				require.Equal(t, `"Chromium";v="158.1.2.3", "Not.A/Brand";v="24.0.0.0", "Google Chrome";v="158.1.2.3"`, last.Get(header.SEC_CH_UA_FULL_VERSION_LIST))
				require.Equal(t, `"a\"b\\c"`, last.Get(header.SEC_CH_UA_MODEL))
				require.Equal(t, "?1", last.Get(header.SEC_CH_UA_WOW64))
				require.Equal(t, `"Desktop", "Tablet"`, last.Get(header.SEC_CH_UA_FORM_FACTORS))
			})
		}
	}
}
func TestClientHintsAutomaticBrowserSelection(t *testing.T) {
	t.Parallel()
	for _, browser := range []string{"chrome", "android", "firefox", "ios", "replaced", "native"} {
		t.Run(browser, func(t *testing.T) {
			b := surf.NewClient().Builder().Proxy("")
			switch browser {
			case "chrome":
				b.Impersonate().Chrome()
			case "android":
				b.Impersonate().Android().Chrome()
			case "firefox":
				b.Impersonate().Firefox()
			case "ios":
				b.Impersonate().IOS().Chrome()
			case "replaced":
				b.Impersonate().Chrome().Impersonate().Firefox()
			}
			var last http.Header
			b.With(func(c *surf.Client) error {
				c.GetClient().Transport = hintRoundTrip(func(r *http.Request) (*http.Response, error) {
					last = r.Header.Clone()
					return hintResponse(r, http.Header{"Accept-Ch": {allUAHints}}), nil
				})
				return nil
			}, math.MaxInt)
			c := b.Build().Unwrap()
			defer c.Close()
			hintRequest(t, c, "https://example.com/", nil)
			hintRequest(t, c, "https://example.com/", nil)
			if browser == "chrome" || browser == "android" {
				require.Len(t, c.ClientHintNames("https://example.com/"), 8)
				if browser == "android" {
					require.Equal(t, `""`, last.Get(header.SEC_CH_UA_ARCH))
					require.Equal(t, `""`, last.Get(header.SEC_CH_UA_BITNESS))
					require.Equal(t, `"Mobile"`, last.Get(header.SEC_CH_UA_FORM_FACTORS))
				} else {
					require.Equal(t, `"x86"`, last.Get(header.SEC_CH_UA_ARCH))
					require.Equal(t, `"19.0.0"`, last.Get(header.SEC_CH_UA_PLATFORM_VERSION))
				}
			} else {
				require.Empty(t, c.ClientHintNames("https://example.com/"))
				require.Empty(t, last.Get(header.SEC_CH_UA_ARCH))
				c.ClearClientHints()
			}
		})
	}
}
func TestClientHintsBuilderValidation(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		configure func(*surf.ClientHints)
	}{
		{"capacity zero", func(h *surf.ClientHints) { h.Capacity(0) }}, {"capacity large", func(h *surf.ClientHints) { h.Capacity(1<<20 + 1) }},
		{"lifetime", func(h *surf.ClientHints) { h.Lifetime(-time.Second) }}, {"unknown", func(h *surf.ClientHints) { h.Value("x-unknown", "value") }},
		{"injection", func(h *surf.ClientHints) { h.Value(header.SEC_CH_UA_ARCH, "a\r\nb") }},
		{"control", func(h *surf.ClientHints) { h.Value(header.SEC_CH_UA_ARCH, "a\x7fb") }},
		{"non ascii", func(h *surf.ClientHints) { h.Architecture("☃") }},
		{"form factors", func(h *surf.ClientHints) { h.FormFactors("Desktop\n") }},
		{"bad brand", func(h *surf.ClientHints) { h.FullVersionList(surf.ClientHintBrand{Brand: "a\n", Version: "1"}) }},
		{"bad version", func(h *surf.ClientHints) { h.FullVersionList(surf.ClientHintBrand{Brand: "a", Version: "\r"}) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := surf.NewClient().Builder()
			h := b.ClientHints()
			tc.configure(h)
			require.True(t, h.Set().Build().IsErr())
		})
	}
}
func TestClientHintsCustomValuesSnapshotsAndDisable(t *testing.T) {
	t.Parallel()
	brands := []surf.ClientHintBrand{{Brand: "Test", Version: "1.2.3"}, {Brand: `A"B`, Version: "24.0.0.0"}}
	factors := []string{"Desktop"}
	var last http.Header
	c := hintClient(t, func(b *surf.Builder) {
		b.ClientHints().FullVersionList(brands...).FormFactors(factors...).Clock(nil).WoW64(false).Value("Sec-CH-DPR", "2").Set()
		brands[0].Brand = "changed"
		factors[0] = "changed"
	}, func(r *http.Request) (*http.Response, error) {
		last = r.Header.Clone()
		return hintResponse(r, http.Header{"Accept-Ch": {allUAHints + ",sec-ch-dpr"}}), nil
	})
	hintRequest(t, c, "https://example.com/", nil)
	hintRequest(t, c, "https://example.com/", nil)
	require.Equal(t, `"Test";v="1.2.3", "A\"B";v="24.0.0.0"`, last.Get(header.SEC_CH_UA_FULL_VERSION_LIST))
	require.Equal(t, `"Desktop"`, last.Get(header.SEC_CH_UA_FORM_FACTORS))
	require.Equal(t, "2", last.Get("sec-ch-dpr"))
	require.Equal(t, "?0", last.Get(header.SEC_CH_UA_WOW64))
	var calls int
	disabled := hintClient(t, func(b *surf.Builder) { b.ClientHints().Enabled(false).Set() }, func(r *http.Request) (*http.Response, error) {
		calls++
		require.Empty(t, r.Header.Get(header.SEC_CH_UA_ARCH))
		return hintResponse(r, http.Header{"Accept-Ch": {allUAHints}, "Critical-Ch": {header.SEC_CH_UA_ARCH}}), nil
	})
	hintRequest(t, disabled, "https://example.com/", nil)
	require.Equal(t, 1, calls)
	require.Empty(t, disabled.ClientHintNames("https://example.com/"))
}
func TestClientHintsNavigationRedirectScope(t *testing.T) {
	t.Parallel()
	var requests []*http.Request
	count := 0
	c := hintClient(t, nil, func(r *http.Request) (*http.Response, error) {
		requests = append(requests, r.Clone(r.Context()))
		count++
		fields := http.Header{"Accept-Ch": {header.SEC_CH_UA_ARCH}, "Critical-Ch": {header.SEC_CH_UA_ARCH}}
		response := hintResponse(r, fields)
		switch count {
		case 1: // Critical restart before processing this redirect.
			response.StatusCode = 302
			fields.Set("Location", "https://b.example/")
		case 2:
			response.StatusCode = 302
			fields.Set("Location", "https://b.example/")
		case 3: // The second origin has its own restart allowance.
		case 4:
			fields.Set("Accept-Ch", header.SEC_CH_UA_BITNESS)
			response.StatusCode = 302
			fields.Set("Location", "https://a.example/end")
		case 5:
			fields.Set("Accept-Ch", header.SEC_CH_UA_BITNESS)
			fields.Set("Critical-Ch", header.SEC_CH_UA_BITNESS)
		default:
			fields.Set("Accept-Ch", header.SEC_CH_UA_ARCH)
			fields.Set("Critical-Ch", header.SEC_CH_UA_ARCH)
		}
		return response, nil
	})
	hintRequest(t, c, "https://a.example/", nil)
	require.Len(t, requests, 5, "returning to an origin in one navigation must not restart it twice")
	require.Empty(t, requests[2].Header.Get(header.SEC_CH_UA_ARCH), "do not forward generated hints across origins")
	require.Equal(t, `"x86"`, requests[3].Header.Get(header.SEC_CH_UA_ARCH))
	c.ClearClientHints()
	hintRequest(t, c, "https://a.example/new", nil)
	require.Len(t, requests, 7, "a new navigation has a new restart allowance")
}
func TestClientHintsStdAdapterRedirectState(t *testing.T) {
	t.Parallel()
	count := 0
	c := hintClient(t, func(b *surf.Builder) { b.Impersonate().Chrome() }, func(r *http.Request) (*http.Response, error) {
		count++
		fields := http.Header{"Accept-Ch": {header.SEC_CH_UA_ARCH}, "Critical-Ch": {header.SEC_CH_UA_ARCH}}
		resp := hintResponse(r, fields)
		if count == 2 {
			resp.StatusCode = 302
			fields.Set("Location", "/second")
			fields.Set("Accept-Ch", header.SEC_CH_UA_BITNESS)
		}
		if count >= 3 {
			fields.Set("Accept-Ch", header.SEC_CH_UA_BITNESS)
			fields.Set("Critical-Ch", header.SEC_CH_UA_BITNESS)
		}
		return resp, nil
	})
	resp, err := c.Std().Get("https://example.com/")
	require.NoError(t, err)
	defer resp.Body.Close()
	_, err = io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, 3, count, "standard redirects must retain the per-navigation restart limit")
	require.True(t, strings.HasSuffix(resp.Request.URL.Path, "second"))
}

func TestClientHintsPreservesExplicitOrderedHeaders(t *testing.T) {
	t.Parallel()
	var orders [][]string
	c := hintClient(t, func(b *surf.Builder) {
		b.Impersonate().Chrome()
		ordered := g.NewMapOrd[string, string]()
		ordered.Insert("x-last", "first")
		ordered.Insert(header.SEC_CH_UA_ARCH, `"arm"`)
		ordered.Insert("x-first", "last")
		b.SetHeaders(ordered)
		b.With(func(r *surf.Request) error {
			r.GetRequest().Header[http.HeaderCaseKey] = []string{"x-last"}
			orders = append(orders, slices.Clone(r.GetRequest().Header[http.HeaderOrderKey]))
			return nil
		}, 1)
	}, func(r *http.Request) (*http.Response, error) {
		require.Equal(t, orders[len(orders)-1], r.Header[http.HeaderOrderKey])
		require.Equal(t, []string{"x-last"}, r.Header[http.HeaderCaseKey])
		require.Equal(t, `"arm"`, r.Header.Get(header.SEC_CH_UA_ARCH))
		return hintResponse(r, http.Header{"Accept-Ch": {header.SEC_CH_UA_BITNESS}, "Critical-Ch": {header.SEC_CH_UA_BITNESS}}), nil
	})
	result := c.Get("https://example.com/").Do()
	require.False(t, result.IsErr(), "%v", result.Err())
	result.Ok().Body.Close()
}

func TestClientHintsSerializedListOverrideAndEmptyList(t *testing.T) {
	t.Parallel()
	for _, empty := range []bool{false, true} {
		t.Run(map[bool]string{true: "empty", false: "serialized"}[empty], func(t *testing.T) {
			var value string
			c := hintClient(t, func(b *surf.Builder) {
				b.Impersonate().Chrome()
				h := b.ClientHints()
				if empty {
					h.FullVersionList()
				} else {
					h.FullVersionList(surf.ClientHintBrand{Brand: "Old", Version: "1"}).Value(header.SEC_CH_UA_FULL_VERSION_LIST, `"New";v="2"`)
				}
				h.Set()
			}, func(r *http.Request) (*http.Response, error) {
				value = r.Header.Get(header.SEC_CH_UA_FULL_VERSION_LIST)
				return hintResponse(r, http.Header{"Accept-Ch": {header.SEC_CH_UA_FULL_VERSION_LIST}}), nil
			})
			hintRequest(t, c, "https://example.com/", nil)
			hintRequest(t, c, "https://example.com/", nil)
			if empty {
				require.Empty(t, value)
			} else {
				require.Equal(t, `"New";v="2"`, value)
			}
		})
	}
}
