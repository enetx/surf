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

func TestJAChrome144(t *testing.T) {
	t.Parallel()

	client := surf.NewClient().Builder().
		JA().Chrome144().
		Build().Unwrap()

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
	if resp.Ok().Body.String().IsEmpty() {
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
		{"Chrome58", func() *surf.Client { return surf.NewClient().Builder().JA().Chrome58().Build().Unwrap() }},
		{"Chrome62", func() *surf.Client { return surf.NewClient().Builder().JA().Chrome62().Build().Unwrap() }},
		{"Chrome70", func() *surf.Client { return surf.NewClient().Builder().JA().Chrome70().Build().Unwrap() }},
		{"Chrome72", func() *surf.Client { return surf.NewClient().Builder().JA().Chrome72().Build().Unwrap() }},
		{"Chrome83", func() *surf.Client { return surf.NewClient().Builder().JA().Chrome83().Build().Unwrap() }},
		{"Chrome87", func() *surf.Client { return surf.NewClient().Builder().JA().Chrome87().Build().Unwrap() }},
		{"Chrome96", func() *surf.Client { return surf.NewClient().Builder().JA().Chrome96().Build().Unwrap() }},
		{"Chrome100", func() *surf.Client { return surf.NewClient().Builder().JA().Chrome100().Build().Unwrap() }},
		{"Chrome102", func() *surf.Client { return surf.NewClient().Builder().JA().Chrome102().Build().Unwrap() }},
		{"Chrome106", func() *surf.Client { return surf.NewClient().Builder().JA().Chrome106().Build().Unwrap() }},
		{"Chrome120", func() *surf.Client { return surf.NewClient().Builder().JA().Chrome120().Build().Unwrap() }},
		{"Chrome120PQ", func() *surf.Client { return surf.NewClient().Builder().JA().Chrome120PQ().Build().Unwrap() }},
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
		{"Edge", func() *surf.Client { return surf.NewClient().Builder().JA().Edge().Build().Unwrap() }},
		{"Edge85", func() *surf.Client { return surf.NewClient().Builder().JA().Edge85().Build().Unwrap() }},
		{"Edge106", func() *surf.Client { return surf.NewClient().Builder().JA().Edge106().Build().Unwrap() }},
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
		{"Firefox", func() *surf.Client { return surf.NewClient().Builder().JA().Firefox().Build().Unwrap() }},
		{"Firefox55", func() *surf.Client { return surf.NewClient().Builder().JA().Firefox55().Build().Unwrap() }},
		{"Firefox56", func() *surf.Client { return surf.NewClient().Builder().JA().Firefox56().Build().Unwrap() }},
		{"Firefox63", func() *surf.Client { return surf.NewClient().Builder().JA().Firefox63().Build().Unwrap() }},
		{"Firefox65", func() *surf.Client { return surf.NewClient().Builder().JA().Firefox65().Build().Unwrap() }},
		{"Firefox99", func() *surf.Client { return surf.NewClient().Builder().JA().Firefox99().Build().Unwrap() }},
		{"Firefox102", func() *surf.Client { return surf.NewClient().Builder().JA().Firefox102().Build().Unwrap() }},
		{"Firefox105", func() *surf.Client { return surf.NewClient().Builder().JA().Firefox105().Build().Unwrap() }},
		{"Firefox120", func() *surf.Client { return surf.NewClient().Builder().JA().Firefox120().Build().Unwrap() }},
		{"Firefox141", func() *surf.Client { return surf.NewClient().Builder().JA().Firefox141().Build().Unwrap() }},
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
		{"IOS", func() *surf.Client { return surf.NewClient().Builder().JA().IOS().Build().Unwrap() }},
		{"IOS11", func() *surf.Client { return surf.NewClient().Builder().JA().IOS11().Build().Unwrap() }},
		{"IOS12", func() *surf.Client { return surf.NewClient().Builder().JA().IOS12().Build().Unwrap() }},
		{"IOS13", func() *surf.Client { return surf.NewClient().Builder().JA().IOS13().Build().Unwrap() }},
		{"IOS14", func() *surf.Client { return surf.NewClient().Builder().JA().IOS14().Build().Unwrap() }},
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
		{"Android", func() *surf.Client { return surf.NewClient().Builder().JA().Android().Build().Unwrap() }},
		{"Safari", func() *surf.Client { return surf.NewClient().Builder().JA().Safari().Build().Unwrap() }},
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
		{"Randomized", func() *surf.Client { return surf.NewClient().Builder().JA().Randomized().Build().Unwrap() }},
		{
			"RandomizedALPN",
			func() *surf.Client { return surf.NewClient().Builder().JA().RandomizedALPN().Build().Unwrap() },
		},
		{
			"RandomizedNoALPN",
			func() *surf.Client { return surf.NewClient().Builder().JA().RandomizedNoALPN().Build().Unwrap() },
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
	client := ja3Builder.SetHelloSpec(spec).Build().Unwrap()

	if client == nil {
		t.Error("expected client to be built with SetHelloSpec")
	}
}

func TestJAFirefox147(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"message": "success"}`)
	}

	ts := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().
		JA().Firefox147().
		Build().Unwrap()

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

	if resp.Ok().Body.String().IsEmpty() {
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
		Build().Unwrap()

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

	if resp.Ok().Body.String().IsEmpty() {
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
		JA().Chrome144().
		JA().Firefox147().
		Build().Unwrap()

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

	if resp.Ok().Body.String().IsEmpty() {
		t.Error("expected response body to contain data")
	}
}

func TestJAWithHTTP2(t *testing.T) {
	t.Parallel()

	client := surf.NewClient().Builder().
		JA().Chrome144().
		HTTP2Settings().
		HeaderTableSize(65536).
		EnablePush(1).
		Set().
		Build().Unwrap()

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

	if resp.Ok().Body.String().IsEmpty() {
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
		JA().Chrome144().
		Build().Unwrap()

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
		JA().Chrome144().
		Build().Unwrap()

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
