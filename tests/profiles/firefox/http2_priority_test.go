package firefox_test

import (
	"context"
	"net/url"
	"testing"

	"github.com/enetx/http"
	"github.com/enetx/http/http2"
	"github.com/enetx/surf/profiles"
	"github.com/enetx/surf/profiles/firefox/common"
	"github.com/stretchr/testify/require"
)

func TestHTTP2HeaderPriorityRequestScenarios(t *testing.T) {
	t.Parallel()
	for _, method := range []string{"", http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut,
		http.MethodPatch, http.MethodDelete, http.MethodOptions, http.MethodTrace, http.MethodConnect} {
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			automatic := uint8(21)
			if method == "" || method == http.MethodGet || method == http.MethodHead {
				automatic = 41
			}
			for _, tc := range []struct {
				name   string
				kind   profiles.RequestKind
				mode   []string
				weight uint8
			}{
				{"automatic", profiles.AutomaticRequest, nil, automatic},
				{"explicit navigation", profiles.NavigationRequest, nil, 41},
				{"explicit fetch", profiles.FetchRequest, nil, 21},
				{"navigate mode overrides fetch", profiles.FetchRequest, []string{"NAVIGATE"}, 41},
				{"cors mode overrides navigation", profiles.NavigationRequest, []string{"cors"}, 21},
				{"same-origin mode is fetch", profiles.NavigationRequest, []string{"same-origin"}, 21},
				{"empty mode retains navigation kind", profiles.NavigationRequest, []string{""}, 41},
				{"suppressed mode retains fetch kind", profiles.FetchRequest, nil, 21},
			} {
				t.Run(tc.name, func(t *testing.T) {
					ctx := profiles.WithRequestKind(context.Background(), tc.kind)
					fields := map[string][]string{"sEc-FeTcH-mOdE": tc.mode}
					got := common.HeaderPriority(http2.PriorityRequest{Context: ctx, Method: method, Header: fields})
					require.Equal(t, http2.PriorityParam{Weight: tc.weight}, got)
				})
			}
		})
	}
}

func TestHTTP2HeaderPriorityLiteralUrgencyIsIndependent(t *testing.T) {
	t.Parallel()
	for _, kind := range []profiles.RequestKind{profiles.NavigationRequest, profiles.FetchRequest} {
		want := uint8(21)
		if kind == profiles.NavigationRequest {
			want = 41
		}
		for _, literal := range []string{"", "u=0, i", "u=1", "u=4", "u=7", "invalid"} {
			info := http2.PriorityRequest{
				Context: profiles.WithRequestKind(context.Background(), kind),
				Method:  http.MethodGet,
				Header:  map[string][]string{"Priority": {literal}},
			}
			require.Equal(t, http2.PriorityParam{Weight: want}, common.HeaderPriority(info), "%v, %q", kind, literal)
		}
	}
}

func TestHTTP2HeaderPriorityDoesNotMutateRequestView(t *testing.T) {
	t.Parallel()
	address, err := url.Parse("https://tls.peet.ws/api/all?fetch=1")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(profiles.WithRequestKind(context.Background(), profiles.FetchRequest))
	cancel()
	fields := http.Header{
		"Sec-Fetch-Mode": nil,
		"Priority":       {"u=0, i"},
		"Header-Order:":  {"priority", "sec-fetch-mode"},
		"X-Test":         {"one", "two"},
	}
	beforeHeaders, beforeURL := fields.Clone(), *address
	info := http2.PriorityRequest{Context: ctx, Method: http.MethodGet, URL: address, Header: fields}
	for range 10 {
		require.Equal(t, http2.PriorityParam{Weight: 21}, common.HeaderPriority(info))
	}
	require.Equal(t, beforeHeaders, fields)
	require.Equal(t, beforeURL, *address)
	require.Equal(t, ctx, info.Context)
	require.Equal(t, http.MethodGet, info.Method)
	require.Equal(t, context.Canceled, ctx.Err())

	// Standalone callers can omit a context and URL. The method and any
	// explicit Fetch Metadata retain the same documented selection rules.
	require.Equal(t, http2.PriorityParam{Weight: 41}, common.HeaderPriority(http2.PriorityRequest{}))
	require.Equal(t, http2.PriorityParam{Weight: 21}, common.HeaderPriority(http2.PriorityRequest{Method: http.MethodPost}))
	require.Equal(t, http2.PriorityParam{Weight: 21}, common.HeaderPriority(http2.PriorityRequest{
		Method: http.MethodGet, Header: map[string][]string{"Sec-Fetch-Mode": {"cors"}},
	}))
}
