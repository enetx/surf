package surf_test

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	ehttp "github.com/enetx/http"
	"github.com/enetx/http/httptest"
	"github.com/enetx/surf"
)

func TestClientStd(t *testing.T) {
	t.Parallel()

	handler := func(w ehttp.ResponseWriter, _ *ehttp.Request) {
		w.Header().Set("X-Test", "value")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "std adapter test")
	}

	ts := httptest.NewServer(ehttp.HandlerFunc(handler))
	defer ts.Close()

	surfClient := surf.NewClient().Builder().Session().Build().Unwrap()
	stdClient := surfClient.Std()

	if stdClient == nil {
		t.Fatal("Std() returned nil")
	}

	resp, err := stdClient.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestTransportAdapter(t *testing.T) {
	t.Parallel()

	var requestMWCalled bool

	handler := func(w ehttp.ResponseWriter, r *ehttp.Request) {
		if r.Header.Get("X-Request-MW") != "called" {
			t.Error("request middleware not applied")
		}
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(ehttp.HandlerFunc(handler))
	defer ts.Close()

	surfClient := surf.NewClient().Builder().
		With(func(req *surf.Request) error {
			requestMWCalled = true
			req.SetHeaders("X-Request-MW", "called")
			return nil
		}).
		Build().Unwrap()

	stdClient := surfClient.Std()
	req, err := http.NewRequest("GET", ts.URL, nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := stdClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if !requestMWCalled {
		t.Error("request middleware not called")
	}
}

func TestCookieJarAdapter(t *testing.T) {
	t.Parallel()

	handler := func(w ehttp.ResponseWriter, _ *ehttp.Request) {
		ehttp.SetCookie(w, &ehttp.Cookie{Name: "test", Value: "value"})
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(ehttp.HandlerFunc(handler))
	defer ts.Close()

	surfClient := surf.NewClient().Builder().Session().Build().Unwrap()
	stdClient := surfClient.Std()

	u, _ := url.Parse(ts.URL)

	resp, err := stdClient.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	cookies := stdClient.Jar.Cookies(u)
	if len(cookies) == 0 {
		t.Error("expected cookies to be set")
	}
}

func TestAdapterWithComplexResponse(t *testing.T) {
	t.Parallel()

	handler := func(w ehttp.ResponseWriter, _ *ehttp.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Custom", "test-value")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"message":"success","data":123}`)
	}

	ts := httptest.NewServer(ehttp.HandlerFunc(handler))
	defer ts.Close()

	surfClient := surf.NewClient().Builder().Session().Build().Unwrap()
	stdClient := surfClient.Std()

	resp, err := stdClient.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Errorf("expected status 201, got %d", resp.StatusCode)
	}

	if resp.Header.Get("Content-Type") != "application/json" {
		t.Error("expected Content-Type to be application/json")
	}

	if resp.Header.Get("X-Custom") != "test-value" {
		t.Error("expected custom header to be preserved")
	}
}

func TestAdapterWithPostData(t *testing.T) {
	t.Parallel()

	var receivedData string

	handler := func(w ehttp.ResponseWriter, r *ehttp.Request) {
		body := make([]byte, r.ContentLength)
		r.Body.Read(body)
		receivedData = string(body)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "received")
	}

	ts := httptest.NewServer(ehttp.HandlerFunc(handler))
	defer ts.Close()

	surfClient := surf.NewClient().Builder().Session().Build().Unwrap()
	stdClient := surfClient.Std()

	req, err := http.NewRequest("POST", ts.URL, strings.NewReader(`{"key":"value"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := stdClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	if receivedData != `{"key":"value"}` {
		t.Errorf("expected received data to be JSON, got %s", receivedData)
	}
}

func TestAdapterNilCheck(t *testing.T) {
	t.Parallel()

	client := surf.NewClient()
	stdClient := client.Std()

	if stdClient == nil {
		t.Fatal("Std() adapter should not return nil")
	}

	if stdClient.Transport == nil {
		t.Error("Std() adapter should have transport set")
	}
}

func TestAdapterCloseIdleConnections(t *testing.T) {
	t.Parallel()

	handler := func(w ehttp.ResponseWriter, _ *ehttp.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "test")
	}

	ts := httptest.NewServer(ehttp.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	stdClient := client.Std()

	// Make a request
	resp, err := stdClient.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	// Close idle connections - should not panic
	stdClient.CloseIdleConnections()

	// Should still be able to make requests after closing idle connections
	resp2, err := stdClient.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
}

func TestAdapterRoundTripDirect(t *testing.T) {
	t.Parallel()

	handler := func(w ehttp.ResponseWriter, r *ehttp.Request) {
		if r.Header.Get("X-Custom") != "test" {
			t.Error("missing custom header")
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "roundtrip test")
	}

	ts := httptest.NewServer(ehttp.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	stdClient := client.Std()

	// Create request
	req, err := http.NewRequest("GET", ts.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Custom", "test")

	// Call RoundTrip directly on transport
	resp, err := stdClient.Transport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestAdapterRedirectHandling(t *testing.T) {
	t.Parallel()

	redirectCount := 0
	handler := func(w ehttp.ResponseWriter, r *ehttp.Request) {
		if redirectCount < 2 {
			redirectCount++
			ehttp.Redirect(w, r, fmt.Sprintf("/redirect%d", redirectCount), http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "final")
	}

	ts := httptest.NewServer(ehttp.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().MaxRedirects(3).Build().Unwrap()
	stdClient := client.Std()

	resp, err := stdClient.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected final status 200, got %d", resp.StatusCode)
	}
}

func TestAdapterSetCookiesEdgeCases(t *testing.T) {
	t.Parallel()

	handler := func(w ehttp.ResponseWriter, r *ehttp.Request) {
		cookies := r.Cookies()
		for _, cookie := range cookies {
			if cookie.Name == "test-cookie" && cookie.Value == "test-value" {
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, "cookie received")
				return
			}
		}
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "no cookie")
	}

	ts := httptest.NewServer(ehttp.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().Session().Build().Unwrap()
	stdClient := client.Std()

	// Test SetCookies functionality through the adapter
	u, _ := url.Parse(ts.URL)

	// Set cookies manually on the jar
	testCookies := []*http.Cookie{
		{Name: "test-cookie", Value: "test-value", Path: "/"},
		{Name: "another-cookie", Value: "another-value", Path: "/"},
	}

	stdClient.Jar.SetCookies(u, testCookies)

	// Make request and verify cookies are sent
	resp, err := stdClient.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200 (cookie received), got %d", resp.StatusCode)
	}

	// Verify cookies are in jar
	retrievedCookies := stdClient.Jar.Cookies(u)
	if len(retrievedCookies) < 2 {
		t.Errorf("expected at least 2 cookies, got %d", len(retrievedCookies))
	}
}

func TestAdapterErrorHandling(t *testing.T) {
	t.Parallel()

	client := surf.NewClient()
	stdClient := client.Std()

	// Test with invalid URL
	_, err := stdClient.Get("invalid://url with spaces")
	if err == nil {
		t.Error("expected error for invalid URL")
	}

	// Test RoundTrip with nil request - this will panic as expected by Go's http.RoundTripper interface
	// We'll test that the panic is recovered
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Error("expected panic for nil request")
			}
		}()
		stdClient.Transport.RoundTrip(nil)
	}()
}

func TestAdapterTimeoutHandling(t *testing.T) {
	t.Parallel()

	// Slow handler that takes longer than timeout
	handler := func(w ehttp.ResponseWriter, _ *ehttp.Request) {
		time.Sleep(200 * time.Millisecond) // Short enough for test but longer than client timeout
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "slow response")
	}

	ts := httptest.NewServer(ehttp.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().
		Timeout(50 * time.Millisecond). // Very short timeout
		Build().Unwrap()
	stdClient := client.Std()

	_, err := stdClient.Get(ts.URL)
	if err == nil {
		t.Error("expected timeout error")
	}
}
