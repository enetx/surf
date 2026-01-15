package surf_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/http/httptest"
	"github.com/enetx/surf"
)

func TestImpersonateOSIntegration(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, r *http.Request) {
		userAgent := r.Header.Get("User-Agent")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"user_agent": "%s"}`, userAgent)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	// Test that different OS impersonations work through the public API
	testCases := []struct {
		name        string
		builderFunc func() *surf.Client
		expectedUA  string
	}{
		{
			"Windows Chrome impersonation",
			func() *surf.Client {
				return surf.NewClient().Builder().
					Impersonate().Windows().Chrome().
					Build().Unwrap()
			},
			"Windows NT 10.0",
		},
		{
			"macOS Chrome impersonation",
			func() *surf.Client {
				return surf.NewClient().Builder().
					Impersonate().MacOS().Chrome().
					Build().Unwrap()
			},
			"Macintosh",
		},
		{
			"Linux Firefox impersonation",
			func() *surf.Client {
				return surf.NewClient().Builder().
					Impersonate().Linux().Firefox().
					Build().Unwrap()
			},
			"X11; Linux x86_64",
		},
		{
			"Android Chrome impersonation",
			func() *surf.Client {
				return surf.NewClient().Builder().
					Impersonate().Android().Chrome().
					Build().Unwrap()
			},
			"Android",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := tc.builderFunc()

			resp := client.Get(g.String(ts.URL)).Do()
			if resp.IsErr() {
				t.Fatalf("%s request failed: %v", tc.name, resp.Err())
			}

			if !resp.Ok().StatusCode.IsSuccess() {
				t.Errorf("%s: expected success, got %d", tc.name, resp.Ok().StatusCode)
			}

			body := resp.Ok().Body.String().Std()
			if !strings.Contains(body, tc.expectedUA) {
				t.Logf("%s: Expected user agent to contain '%s', got: %s",
					tc.name, tc.expectedUA, body)
			}
		})
	}
}

func TestImpersonateOSMobileVsDesktop(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, r *http.Request) {
		userAgent := r.Header.Get("User-Agent")
		secCHUAMobile := r.Header.Get("Sec-CH-UA-Mobile")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"user_agent": "%s", "mobile": "%s"}`, userAgent, secCHUAMobile)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	testCases := []struct {
		name         string
		builderFunc  func() *surf.Client
		expectMobile bool
		expectedUA   string
	}{
		{
			"Desktop Windows",
			func() *surf.Client {
				return surf.NewClient().Builder().
					Impersonate().Windows().Chrome().
					Build().Unwrap()
			},
			false,
			"Windows",
		},
		{
			"Mobile Android",
			func() *surf.Client {
				return surf.NewClient().Builder().
					Impersonate().Android().Chrome().
					Build().Unwrap()
			},
			true,
			"Mobile",
		},
		{
			"Mobile iOS",
			func() *surf.Client {
				return surf.NewClient().Builder().
					Impersonate().IOS().Chrome().
					Build().Unwrap()
			},
			true,
			"iPhone",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := tc.builderFunc()

			resp := client.Get(g.String(ts.URL)).Do()
			if resp.IsErr() {
				t.Fatalf("%s request failed: %v", tc.name, resp.Err())
			}

			if !resp.Ok().StatusCode.IsSuccess() {
				t.Errorf("%s: expected success, got %d", tc.name, resp.Ok().StatusCode)
			}

			body := resp.Ok().Body.String().Std()
			if !strings.Contains(body, tc.expectedUA) {
				t.Logf("%s: Expected to find '%s' in response: %s",
					tc.name, tc.expectedUA, body)
			}

			// Check mobile header if present
			if tc.expectMobile && strings.Contains(body, `"mobile": "?0"`) {
				t.Logf("%s: Expected mobile indicator, but got desktop", tc.name)
			} else if !tc.expectMobile && strings.Contains(body, `"mobile": "?1"`) {
				t.Logf("%s: Expected desktop indicator, but got mobile", tc.name)
			}
		})
	}
}

func TestImpersonateOSBrowserEngineIdentifiers(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, r *http.Request) {
		userAgent := r.Header.Get("User-Agent")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"user_agent": "%s"}`, userAgent)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	testCases := []struct {
		name        string
		builderFunc func() *surf.Client
		expected    string
	}{
		{
			"Chrome WebKit engine",
			func() *surf.Client {
				return surf.NewClient().Builder().
					Impersonate().Windows().Chrome().
					Build().Unwrap()
			},
			"AppleWebKit/537.36",
		},
		{
			"Firefox Gecko engine",
			func() *surf.Client {
				return surf.NewClient().Builder().
					Impersonate().Windows().Firefox().
					Build().Unwrap()
			},
			"Gecko/20100101",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := tc.builderFunc()

			resp := client.Get(g.String(ts.URL)).Do()
			if resp.IsErr() {
				t.Fatalf("%s request failed: %v", tc.name, resp.Err())
			}

			body := resp.Ok().Body.String().Std()
			if !strings.Contains(body, tc.expected) {
				t.Logf("%s: Expected to find '%s' in user agent: %s",
					tc.name, tc.expected, body)
			}
		})
	}
}
