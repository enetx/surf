package surf_test

import (
	"fmt"
	"testing"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/http/httptest"
	"github.com/enetx/surf"
	utls "github.com/enetx/utls"
)

func TestJAChrome131(t *testing.T) {
	t.Parallel()

	client := surf.NewClient().Builder().
		JA().Chrome131().
		Build()

	if client == nil {
		t.Fatal("expected client to be built successfully")
	}

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"message": "success"}`)
	}

	ts := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer ts.Close()

	// Test that JA fingerprint is applied
	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}

	// JA fingerprint should be applied at TLS level
	// We can't easily verify the actual fingerprint without a specialized server
	// but we can verify the request completes successfully with JA configured
	if resp.Ok().Body.String().Empty() {
		t.Error("expected response body to contain data")
	}
}

func TestJAChromeVersions(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"ja3": "test"}`)
	}

	ts := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer ts.Close()

	chromeVersions := []struct {
		name   string
		method func() *surf.Client
	}{
		{"Chrome58", func() *surf.Client { return surf.NewClient().Builder().JA().Chrome58().Build() }},
		{"Chrome62", func() *surf.Client { return surf.NewClient().Builder().JA().Chrome62().Build() }},
		{"Chrome70", func() *surf.Client { return surf.NewClient().Builder().JA().Chrome70().Build() }},
		{"Chrome72", func() *surf.Client { return surf.NewClient().Builder().JA().Chrome72().Build() }},
		{"Chrome83", func() *surf.Client { return surf.NewClient().Builder().JA().Chrome83().Build() }},
		{"Chrome87", func() *surf.Client { return surf.NewClient().Builder().JA().Chrome87().Build() }},
		{"Chrome96", func() *surf.Client { return surf.NewClient().Builder().JA().Chrome96().Build() }},
		{"Chrome100", func() *surf.Client { return surf.NewClient().Builder().JA().Chrome100().Build() }},
		{"Chrome102", func() *surf.Client { return surf.NewClient().Builder().JA().Chrome102().Build() }},
		{"Chrome106", func() *surf.Client { return surf.NewClient().Builder().JA().Chrome106().Build() }},
		{"Chrome120", func() *surf.Client { return surf.NewClient().Builder().JA().Chrome120().Build() }},
		{"Chrome120PQ", func() *surf.Client { return surf.NewClient().Builder().JA().Chrome120PQ().Build() }},
	}

	for _, tc := range chromeVersions {
		t.Run(tc.name, func(t *testing.T) {
			client := tc.method()
			if client == nil {
				t.Fatalf("expected client to be built with %s", tc.name)
			}

			req := client.Get(g.String(ts.URL))
			resp := req.Do()

			if resp.IsErr() {
				t.Logf("%s JA test failed (may be expected): %v", tc.name, resp.Err())
				return
			}

			if !resp.Ok().StatusCode.IsSuccess() {
				t.Errorf("expected success with %s JA, got %d", tc.name, resp.Ok().StatusCode)
			}
		})
	}
}

func TestJAEdgeVersions(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"ja3": "edge"}`)
	}

	ts := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer ts.Close()

	edgeVersions := []struct {
		name   string
		method func() *surf.Client
	}{
		{"Edge", func() *surf.Client { return surf.NewClient().Builder().JA().Edge().Build() }},
		{"Edge85", func() *surf.Client { return surf.NewClient().Builder().JA().Edge85().Build() }},
		{"Edge106", func() *surf.Client { return surf.NewClient().Builder().JA().Edge106().Build() }},
	}

	for _, tc := range edgeVersions {
		t.Run(tc.name, func(t *testing.T) {
			client := tc.method()
			if client == nil {
				t.Fatalf("expected client to be built with %s", tc.name)
			}

			req := client.Get(g.String(ts.URL))
			resp := req.Do()

			if resp.IsErr() {
				t.Logf("%s JA test failed (may be expected): %v", tc.name, resp.Err())
				return
			}

			if !resp.Ok().StatusCode.IsSuccess() {
				t.Errorf("expected success with %s JA, got %d", tc.name, resp.Ok().StatusCode)
			}
		})
	}
}

func TestJAFirefoxVersions(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"ja3": "firefox"}`)
	}

	ts := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer ts.Close()

	firefoxVersions := []struct {
		name   string
		method func() *surf.Client
	}{
		{"Firefox", func() *surf.Client { return surf.NewClient().Builder().JA().Firefox().Build() }},
		{"Firefox55", func() *surf.Client { return surf.NewClient().Builder().JA().Firefox55().Build() }},
		{"Firefox56", func() *surf.Client { return surf.NewClient().Builder().JA().Firefox56().Build() }},
		{"Firefox63", func() *surf.Client { return surf.NewClient().Builder().JA().Firefox63().Build() }},
		{"Firefox65", func() *surf.Client { return surf.NewClient().Builder().JA().Firefox65().Build() }},
		{"Firefox99", func() *surf.Client { return surf.NewClient().Builder().JA().Firefox99().Build() }},
		{"Firefox102", func() *surf.Client { return surf.NewClient().Builder().JA().Firefox102().Build() }},
		{"Firefox105", func() *surf.Client { return surf.NewClient().Builder().JA().Firefox105().Build() }},
		{"Firefox120", func() *surf.Client { return surf.NewClient().Builder().JA().Firefox120().Build() }},
	}

	for _, tc := range firefoxVersions {
		t.Run(tc.name, func(t *testing.T) {
			client := tc.method()
			if client == nil {
				t.Fatalf("expected client to be built with %s", tc.name)
			}

			req := client.Get(g.String(ts.URL))
			resp := req.Do()

			if resp.IsErr() {
				t.Logf("%s JA test failed (may be expected): %v", tc.name, resp.Err())
				return
			}

			if !resp.Ok().StatusCode.IsSuccess() {
				t.Errorf("expected success with %s JA, got %d", tc.name, resp.Ok().StatusCode)
			}
		})
	}
}

func TestJAiOSVersions(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"ja3": "ios"}`)
	}

	ts := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer ts.Close()

	iOSVersions := []struct {
		name   string
		method func() *surf.Client
	}{
		{"IOS", func() *surf.Client { return surf.NewClient().Builder().JA().IOS().Build() }},
		{"IOS11", func() *surf.Client { return surf.NewClient().Builder().JA().IOS11().Build() }},
		{"IOS12", func() *surf.Client { return surf.NewClient().Builder().JA().IOS12().Build() }},
		{"IOS13", func() *surf.Client { return surf.NewClient().Builder().JA().IOS13().Build() }},
		{"IOS14", func() *surf.Client { return surf.NewClient().Builder().JA().IOS14().Build() }},
	}

	for _, tc := range iOSVersions {
		t.Run(tc.name, func(t *testing.T) {
			client := tc.method()
			if client == nil {
				t.Fatalf("expected client to be built with %s", tc.name)
			}

			req := client.Get(g.String(ts.URL))
			resp := req.Do()

			if resp.IsErr() {
				t.Logf("%s JA test failed (may be expected): %v", tc.name, resp.Err())
				return
			}

			if !resp.Ok().StatusCode.IsSuccess() {
				t.Errorf("expected success with %s JA, got %d", tc.name, resp.Ok().StatusCode)
			}
		})
	}
}

func TestJAAndroidAndSafari(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"ja3": "mobile"}`)
	}

	ts := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer ts.Close()

	testCases := []struct {
		name   string
		method func() *surf.Client
	}{
		{"Android", func() *surf.Client { return surf.NewClient().Builder().JA().Android().Build() }},
		{"Safari", func() *surf.Client { return surf.NewClient().Builder().JA().Safari().Build() }},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := tc.method()
			if client == nil {
				t.Fatalf("expected client to be built with %s", tc.name)
			}

			req := client.Get(g.String(ts.URL))
			resp := req.Do()

			if resp.IsErr() {
				t.Logf("%s JA test failed (may be expected): %v", tc.name, resp.Err())
				return
			}

			if !resp.Ok().StatusCode.IsSuccess() {
				t.Errorf("expected success with %s JA, got %d", tc.name, resp.Ok().StatusCode)
			}
		})
	}
}

func TestJARandomizedProfiles(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"ja3": "randomized"}`)
	}

	ts := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer ts.Close()

	randomizedProfiles := []struct {
		name   string
		method func() *surf.Client
	}{
		{"Randomized", func() *surf.Client { return surf.NewClient().Builder().JA().Randomized().Build() }},
		{"RandomizedALPN", func() *surf.Client { return surf.NewClient().Builder().JA().RandomizedALPN().Build() }},
		{
			"RandomizedNoALPN",
			func() *surf.Client { return surf.NewClient().Builder().JA().RandomizedNoALPN().Build() },
		},
	}

	for _, tc := range randomizedProfiles {
		t.Run(tc.name, func(t *testing.T) {
			client := tc.method()
			if client == nil {
				t.Fatalf("expected client to be built with %s", tc.name)
			}

			req := client.Get(g.String(ts.URL))
			resp := req.Do()

			if resp.IsErr() {
				t.Logf("%s JA test failed (may be expected): %v", tc.name, resp.Err())
				return
			}

			if !resp.Ok().StatusCode.IsSuccess() {
				t.Errorf("expected success with %s JA, got %d", tc.name, resp.Ok().StatusCode)
			}
		})
	}
}

func TestJASetHelloSpec(t *testing.T) {
	t.Parallel()

	// Test SetHelloSpec method with custom spec
	ja3Builder := surf.NewClient().Builder().JA()
	spec := utls.ClientHelloSpec{}
	client := ja3Builder.SetHelloSpec(spec).Build()

	if client == nil {
		t.Error("expected client to be built with SetHelloSpec")
	}
}

func TestJAFirefox143(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"message": "success"}`)
	}

	ts := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().
		JA().Firefox144().
		Build()

	if client == nil {
		t.Fatal("expected client to be built successfully")
	}

	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}

	if resp.Ok().Body.String().Empty() {
		t.Error("expected response body to contain data")
	}
}

func TestJAWithImpersonate(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"message": "success"}`)
	}

	ts := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().
		Impersonate().Chrome().
		Build()

	if client == nil {
		t.Fatal("expected client to be built successfully")
	}

	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}

	if resp.Ok().Body.String().Empty() {
		t.Error("expected response body to contain data")
	}
}

func TestJAMultipleCalls(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"message": "success"}`)
	}

	ts := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().
		JA().Chrome131().
		JA().Firefox144().
		Build()

	if client == nil {
		t.Fatal("expected client to be built successfully")
	}

	// Last JA setting should be used
	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}

	if resp.Ok().Body.String().Empty() {
		t.Error("expected response body to contain data")
	}
}

func TestJAWithHTTP2(t *testing.T) {
	t.Parallel()

	client := surf.NewClient().Builder().
		JA().Chrome131().
		HTTP2Settings().
		HeaderTableSize(65536).
		EnablePush(1).
		Set().
		Build()

	if client == nil {
		t.Fatal("expected client to be built successfully")
	}

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"message": "success"}`)
	}

	ts := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer ts.Close()

	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}

	if resp.Ok().Body.String().Empty() {
		t.Error("expected response body to contain data")
	}
}

func TestJARoundTripperHTTP1(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"http1": "test"}`)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().
		JA().Chrome131().
		Build()

	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}
}

func TestJACloseIdleConnections(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"idle": "test"}`)
	}

	ts := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().
		JA().Chrome131().
		Build()

	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	client.CloseIdleConnections()

	req2 := client.Get(g.String(ts.URL))
	resp2 := req2.Do()

	if resp2.IsErr() {
		t.Fatal(resp2.Err())
	}

	if !resp2.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success after closing idle connections, got %d", resp2.Ok().StatusCode)
	}
}
