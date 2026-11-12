package surf_test

import (
	"context"
	"io"
	stdhttp "net/http"
	"testing"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/surf"
	"github.com/enetx/surf/header"
	"github.com/stretchr/testify/require"
)

type hintOwnershipContext struct {
	context.Context
	values []string
}

func TestClientHintsOwnershipSettersWithNonComparableContext(t *testing.T) {
	type contextKey struct{}
	client := surf.NewClient()
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	ctx := hintOwnershipContext{
		Context: context.WithValue(context.Background(), contextKey{}, "application-value"),
		values:  []string{"makes the context value non-comparable"},
	}
	request := client.Get("https://example.com/").WithContext(ctx)
	require.NotPanics(t, func() {
		request.SetHeaders("X-Ownership", "first").AddHeaders("X-Ownership", "second")
	}, "public header setters must accept any valid context.Context implementation")
	require.Equal(t, []string{"first", "second"}, request.GetRequest().Header.Values("X-Ownership"))
	require.Equal(t, "application-value", request.GetRequest().Context().Value(contextKey{}))
}

func TestClientHintsExplicitOwnershipAcrossStdRedirect(t *testing.T) {
	for _, profile := range []string{"standalone", "chrome"} {
		t.Run(profile, func(t *testing.T) {
			for _, setter := range []string{"automatic", "SetHeaders", "MapOrd", "AddHeaders"} {
				t.Run(setter, func(t *testing.T) {
					const firstOrigin = "https://a.example"
					const nextOrigin = "https://b.example"
					const value = `"x86"`
					var requests []*http.Request
					c := hintClient(t, func(b *surf.Builder) {
						if profile == "chrome" {
							b.Impersonate().Chrome()
						}
						b.With(func(req *surf.Request) error {
							if req.GetRequest().URL.Host != "b.example" {
								return nil
							}
							// The value deliberately equals the automatically
							// generated hint on the preceding origin. A setter
							// transfers ownership even without a value change.
							switch setter {
							case "SetHeaders":
								req.SetHeaders(header.SEC_CH_UA_ARCH, value)
							case "MapOrd":
								fields := g.NewMapOrd[string, string]()
								fields.Insert(header.SEC_CH_UA_ARCH, value)
								req.SetHeaders(fields)
							case "AddHeaders":
								req.AddHeaders(header.SEC_CH_UA_ARCH, value)
							}
							return nil
						})
					}, func(req *http.Request) (*http.Response, error) {
						requests = append(requests, req.Clone(req.Context()))
						response := hintResponse(req, make(http.Header))
						if req.URL.Path == "/prime" {
							response.Header.Set(header.ACCEPT_CH, header.SEC_CH_UA_ARCH)
						} else if req.URL.Host == "a.example" {
							response.StatusCode = http.StatusFound
							response.Header.Set("Location", nextOrigin+"/end")
						}
						return response, nil
					})
					standard := c.Std()
					for _, target := range []string{firstOrigin + "/prime", firstOrigin + "/start"} {
						req, err := stdhttp.NewRequest(http.MethodGet, target, nil)
						require.NoError(t, err)
						// Standalone Client Hints has no browser profile to
						// supply the document-navigation classification.
						req.Header.Set(header.SEC_FETCH_MODE, "navigate")
						req.Header.Set(header.SEC_FETCH_DEST, "document")
						response, err := standard.Do(req)
						require.NoError(t, err)
						_, err = io.Copy(io.Discard, response.Body)
						require.NoError(t, err)
						require.NoError(t, response.Body.Close())
					}
					require.Len(t, requests, 3)
					require.Empty(t, requests[0].Header.Get(header.SEC_CH_UA_ARCH))
					require.Equal(t, "a.example", requests[1].URL.Host)
					require.Equal(t, []string{value}, requests[1].Header.Values(header.SEC_CH_UA_ARCH), "first origin opted in and generated the hint automatically")
					require.Equal(t, "b.example", requests[2].URL.Host)
					if setter == "automatic" {
						_, present := requests[2].Header[http.CanonicalHeaderKey(header.SEC_CH_UA_ARCH)]
						require.False(t, present, "automatic hints must not leak to an origin without an opt-in")
					} else {
						require.Equal(t, []string{value}, requests[2].Header.Values(header.SEC_CH_UA_ARCH), "explicit ownership must survive generated-field cleanup")
					}
					if setter == "MapOrd" {
						require.Equal(t, []string{header.SEC_CH_UA_ARCH}, requests[2].Header[http.HeaderOrderKey])
					}
					require.Equal(t, []string{header.SEC_CH_UA_ARCH}, c.ClientHintNames(firstOrigin))
					require.Empty(t, c.ClientHintNames(nextOrigin), "a user field does not create an Accept-CH cache entry")
				})
			}
		})
	}
}
