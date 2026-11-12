package chrome_test

import (
	"context"
	"net/url"
	"reflect"
	"testing"

	"github.com/enetx/http"
	"github.com/enetx/http/http2"
	"github.com/enetx/surf/profiles"
	"github.com/enetx/surf/profiles/chrome/common"
)

func TestChromeHTTP2PriorityUsesRequestScenario(t *testing.T) {
	for _, tc := range []struct {
		name, method string
		kind         profiles.RequestKind
		headers      http.Header
		weight       uint8
	}{
		{name: "default GET navigation", method: "GET", weight: 255},
		{name: "default HEAD navigation", method: "HEAD", weight: 255},
		{name: "unspecified method navigation", weight: 255},
		{name: "ordinary POST fetch", method: "POST", weight: 219},
		{name: "ordinary PATCH fetch", method: "PATCH", weight: 219},
		{name: "GET Fetch context without metadata", method: "GET", kind: profiles.FetchRequest, weight: 219},
		{name: "HEAD Fetch context without metadata", method: "HEAD", kind: profiles.FetchRequest, weight: 219},
		{name: "POST navigation context without metadata", method: "POST", kind: profiles.NavigationRequest, weight: 255},
		{name: "nil metadata retains Fetch context", method: "GET", kind: profiles.FetchRequest,
			headers: http.Header{"Sec-Fetch-Mode": nil}, weight: 219},
		{name: "empty metadata retains navigation context", method: "POST", kind: profiles.NavigationRequest,
			headers: http.Header{"Sec-Fetch-Mode": {""}}, weight: 255},
		{name: "explicit Fetch Metadata wins", method: "GET", kind: profiles.NavigationRequest,
			headers: http.Header{"Sec-Fetch-Mode": {"cors"}}, weight: 219},
		{name: "case insensitive navigation metadata wins", method: "POST", kind: profiles.FetchRequest,
			headers: http.Header{"sEc-FeTcH-mOdE": {"NaViGaTe"}}, weight: 255},
		{name: "custom Priority does not turn navigation into fetch", method: "GET",
			headers: http.Header{"Priority": {"u=7"}}, weight: 255},
		{name: "custom Priority does not turn Fetch into navigation", method: "GET", kind: profiles.FetchRequest,
			headers: http.Header{"Priority": {"u=0, i"}}, weight: 219},
		{name: "explicit order metadata does not change scenario", method: "GET", kind: profiles.FetchRequest,
			headers: http.Header{http.HeaderOrderKey: nil, http.PHeaderOrderKey: {}, http.HeaderCaseKey: {"Sec-Fetch-Mode"}}, weight: 219},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := profiles.WithRequestKind(context.Background(), tc.kind)
			target, err := url.Parse("https://example.com/path")
			if err != nil {
				t.Fatal(err)
			}
			headers := tc.headers.Clone()
			before := headers.Clone()
			info := http2.PriorityRequest{Context: ctx, Method: tc.method, URL: target, Header: headers}
			want := http2.PriorityParam{Exclusive: true, Weight: tc.weight}
			if got := common.HeaderPriority(info); got != want {
				t.Fatalf("HEADERS priority = %+v, want %+v", got, want)
			}
			if !reflect.DeepEqual(headers, before) || target.String() != "https://example.com/path" {
				t.Fatal("priority policy mutated request fields")
			}
		})
	}
}

func TestChromeHTTP2PriorityAcceptsMissingContext(t *testing.T) {
	for _, method := range []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT"} {
		want := uint8(219)
		if method == "GET" || method == "HEAD" {
			want = 255
		}
		if got := common.HeaderPriority(http2.PriorityRequest{Method: method}); got != (http2.PriorityParam{Exclusive: true, Weight: want}) {
			t.Errorf("%s priority = %+v, want encoded weight %d and exclusive", method, got, want)
		}
	}
}
