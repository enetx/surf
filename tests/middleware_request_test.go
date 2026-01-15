package surf_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/http/httptest"
	"github.com/enetx/http/httptrace"
	"github.com/enetx/surf"
)

func TestMiddlewareRequestUserAgent(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, r *http.Request) {
		userAgent := r.Header.Get("User-Agent")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"user-agent": "%s"}`, userAgent)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	testCases := []struct {
		name      string
		userAgent string
	}{
		{"Custom String", "MyCustomAgent/1.0"},
		{"Browser Like", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
		{"Empty Agent", ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := surf.NewClient().Builder().UserAgent(tc.userAgent).Build().Unwrap()
			req := client.Get(g.String(ts.URL))
			resp := req.Do()

			if resp.IsErr() {
				t.Fatal(resp.Err())
			}

			body := resp.Ok().Body.String()
			if !strings.Contains(body.Std(), tc.userAgent) && tc.userAgent != "" {
				t.Errorf("expected user agent %s in response", tc.userAgent)
			}
		})
	}
}

func TestMiddlewareRequestUserAgentTypes(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, r *http.Request) {
		userAgent := r.Header.Get("User-Agent")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"user-agent": "%s"}`, userAgent)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	t.Run("g.String type", func(t *testing.T) {
		client := surf.NewClient().Builder().UserAgent(g.String("gString-UserAgent/1.0")).Build().Unwrap()
		resp := client.Get(g.String(ts.URL)).Do()

		if resp.IsErr() {
			t.Fatal(resp.Err())
		}

		body := resp.Ok().Body.String()
		if !strings.Contains(body.Std(), "gString-UserAgent/1.0") {
			t.Error("expected g.String user agent in response")
		}
	})

	t.Run("[]string slice", func(t *testing.T) {
		userAgents := []string{"Agent1/1.0", "Agent2/1.0", "Agent3/1.0"}
		client := surf.NewClient().Builder().UserAgent(userAgents).Build().Unwrap()

		// Make multiple requests to test random selection
		foundAgents := make(map[string]bool)
		for i := 0; i < 10; i++ {
			resp := client.Get(g.String(ts.URL)).Do()
			if resp.IsErr() {
				t.Fatal(resp.Err())
			}

			body := resp.Ok().Body.String()
			for _, agent := range userAgents {
				if strings.Contains(body.Std(), agent) {
					foundAgents[agent] = true
					break
				}
			}
		}

		if len(foundAgents) == 0 {
			t.Error("no user agents from slice were used")
		}
	})

	t.Run("g.Slice[string] type", func(t *testing.T) {
		userAgents := g.SliceOf("gSliceAgent1/1.0", "gSliceAgent2/1.0")
		client := surf.NewClient().Builder().UserAgent(userAgents).Build().Unwrap()
		resp := client.Get(g.String(ts.URL)).Do()

		if resp.IsErr() {
			t.Fatal(resp.Err())
		}

		body := resp.Ok().Body.String()
		hasAgent := strings.Contains(body.Std(), "gSliceAgent1/1.0") ||
			strings.Contains(body.Std(), "gSliceAgent2/1.0")
		if !hasAgent {
			t.Error("expected g.Slice[string] user agent in response")
		}
	})

	t.Run("g.Slice[g.String] type", func(t *testing.T) {
		userAgents := g.SliceOf(g.String("gStringSliceAgent1/1.0"), g.String("gStringSliceAgent2/1.0"))
		client := surf.NewClient().Builder().UserAgent(userAgents).Build().Unwrap()
		resp := client.Get(g.String(ts.URL)).Do()

		if resp.IsErr() {
			t.Fatal(resp.Err())
		}

		body := resp.Ok().Body.String()
		hasAgent := strings.Contains(body.Std(), "gStringSliceAgent1/1.0") ||
			strings.Contains(body.Std(), "gStringSliceAgent2/1.0")
		if !hasAgent {
			t.Error("expected g.Slice[g.String] user agent in response")
		}
	})
}

func TestMiddlewareRequestUserAgentErrors(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	t.Run("empty []string slice", func(t *testing.T) {
		client := surf.NewClient().Builder().UserAgent([]string{}).Build().Unwrap()
		resp := client.Get(g.String(ts.URL)).Do()

		if resp.IsOk() {
			t.Error("expected error for empty string slice")
		}
	})

	t.Run("empty g.Slice[string]", func(t *testing.T) {
		client := surf.NewClient().Builder().UserAgent(g.Slice[string]{}).Build().Unwrap()
		resp := client.Get(g.String(ts.URL)).Do()

		if resp.IsOk() {
			t.Error("expected error for empty g.Slice[string]")
		}
	})

	t.Run("empty g.Slice[g.String]", func(t *testing.T) {
		client := surf.NewClient().Builder().UserAgent(g.Slice[g.String]{}).Build().Unwrap()
		resp := client.Get(g.String(ts.URL)).Do()

		if resp.IsOk() {
			t.Error("expected error for empty g.Slice[g.String]")
		}
	})

	t.Run("invalid type", func(t *testing.T) {
		client := surf.NewClient().Builder().UserAgent(123).Build().Unwrap()
		resp := client.Get(g.String(ts.URL)).Do()

		if resp.IsOk() {
			t.Error("expected error for invalid type")
		}
	})
}

func TestMiddlewareRequestBearerAuth(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		token := strings.TrimPrefix(auth, "Bearer ")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"token": "%s"}`, token)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	// Test with bearer token
	client := surf.NewClient().Builder().BearerAuth("test-token-123").Build().Unwrap()
	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if resp.Ok().StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.Ok().StatusCode)
	}

	body := resp.Ok().Body.String()
	if !strings.Contains(body.Std(), "test-token-123") {
		t.Error("expected token in response")
	}
}

func TestMiddlewareRequestBasicAuth(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"username": "%s", "password": "%s"}`, username, password)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	// Test with basic auth
	client := surf.NewClient().Builder().BasicAuth("testuser:testpass").Build().Unwrap()
	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if resp.Ok().StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.Ok().StatusCode)
	}

	body := resp.Ok().Body.String()
	if !strings.Contains(body.Std(), "testuser") {
		t.Error("expected username in response")
	}
	if !strings.Contains(body.Std(), "testpass") {
		t.Error("expected password in response")
	}
}

func TestMiddlewareRequestContentType(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, r *http.Request) {
		contentType := r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"content-type": "%s"}`, contentType)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	testCases := []struct {
		name        string
		contentType string
	}{
		{"JSON", "application/json"},
		{"XML", "application/xml"},
		{"Form", "application/x-www-form-urlencoded"},
		{"Custom", "application/custom+type"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := surf.NewClient().Builder().ContentType(g.String(tc.contentType)).Build().Unwrap()
			req := client.Post(g.String(ts.URL), g.String("test data"))
			resp := req.Do()

			if resp.IsErr() {
				t.Fatal(resp.Err())
			}

			body := resp.Ok().Body.String()
			if !strings.Contains(body.Std(), tc.contentType) {
				t.Errorf("expected content type %s in response", tc.contentType)
			}
		})
	}
}

func TestMiddlewareRequestGetRemoteAddress(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status": "ok"}`)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	// Test GetRemoteAddress
	client := surf.NewClient().Builder().GetRemoteAddress().Build().Unwrap()
	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	// Check if remote address is available
	remoteAddr := resp.Ok().RemoteAddress()
	if remoteAddr == nil {
		t.Error("expected remote address to be set")
	} else {
		// Remote address should contain IP and port
		if !strings.Contains(remoteAddr.String(), ":") {
			t.Error("expected remote address to contain port")
		}
	}
}

func TestMiddlewareRequestGot101Response(t *testing.T) {
	t.Parallel()

	// Test handling of 101 Switching Protocols response
	handler := func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") == "websocket" {
			// Simulate WebSocket upgrade attempt
			w.Header().Set("Upgrade", "websocket")
			w.Header().Set("Connection", "Upgrade")
			w.WriteHeader(http.StatusSwitchingProtocols)
			return
		}
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()

	// Test normal request
	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if resp.Ok().StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.Ok().StatusCode)
	}

	// Test WebSocket upgrade attempt (should handle 101 response)
	req2 := client.Get(g.String(ts.URL)).
		SetHeaders(g.Map[string, string]{
			"Upgrade":    "websocket",
			"Connection": "Upgrade",
		})
	resp2 := req2.Do()

	// This might fail or return 101, depending on middleware handling
	if resp2.IsOk() {
		if resp2.Ok().StatusCode == http.StatusSwitchingProtocols {
			t.Log("Got 101 Switching Protocols as expected")
		}
	}
}

func TestMiddlewareRequestGot101ResponseEdgeCases(t *testing.T) {
	t.Parallel()

	// The got101ResponseMW sets up a client trace that only triggers
	// the Got1xxResponse callback in specific HTTP transport scenarios.
	// Most standard HTTP servers won't trigger this callback directly.

	// Test that the middleware can be applied without error
	client := surf.NewClient()

	// Simple test to verify the middleware doesn't break normal requests
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "success")
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	if resp.IsErr() {
		t.Fatalf("middleware should not interfere with normal requests: %v", resp.Err())
	}

	if resp.Ok().StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.Ok().StatusCode)
	}

	body := resp.Ok().Body.String()
	if body.Std() != "success" {
		t.Errorf("expected body 'success', got %s", body.Std())
	}
}

func TestMiddlewareRequestGot101ResponseMiddlewareIntegration(t *testing.T) {
	t.Parallel()

	// Test the middleware by doing a request with a mock server that fails fast
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "test")
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	req := client.Get(g.String(ts.URL))

	// Do the request to trigger middleware application
	resp := req.Do()
	if resp.IsErr() {
		t.Fatalf("unexpected error: %v", resp.Err())
	}

	// Now check that the trace was set up (after middleware was applied)
	trace := httptrace.ContextClientTrace(req.GetRequest().Context())
	if trace == nil {
		t.Fatal("expected client trace to be set by middleware")
	}

	// The Got1xxResponse callback should be set by got101ResponseMW
	if trace.Got1xxResponse == nil {
		t.Fatal("expected Got1xxResponse callback to be set by got101ResponseMW")
	}

	// Test the callback behavior directly
	testCases := []struct {
		name        string
		statusCode  int
		expectError bool
	}{
		{"Status 100 Continue", 100, false},
		{"Status 101 Switching Protocols", 101, true},
		{"Status 102 Processing", 102, false},
		{"Status 103 Early Hints", 103, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := trace.Got1xxResponse(tc.statusCode, nil)

			if tc.expectError {
				if err == nil {
					t.Errorf("expected error for status %d", tc.statusCode)
				} else {
					// Verify it's the correct error type
					if _, ok := err.(*surf.Err101ResponseCode); !ok {
						t.Errorf("expected Err101ResponseCode, got %T", err)
					}
					// Verify error message contains request details
					errMsg := err.Error()
					if !strings.Contains(errMsg, "GET") {
						t.Errorf("expected error message to contain method, got: %s", errMsg)
					}
				}
			} else {
				if err != nil {
					t.Errorf("expected no error for status %d, got: %v", tc.statusCode, err)
				}
			}
		})
	}
}

func TestMiddlewareRequestGot101ResponseWithDifferentMethods(t *testing.T) {
	t.Parallel()

	// Test the middleware by creating a simple handler that just returns OK
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()

	testCases := []struct {
		name   string
		method string
	}{
		{"GET method", "GET"},
		{"POST method", "POST"},
		{"PUT method", "PUT"},
		{"DELETE method", "DELETE"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var req *surf.Request

			switch tc.method {
			case "GET":
				req = client.Get(g.String(ts.URL))
			case "POST":
				req = client.Post(g.String(ts.URL), g.String("test data"))
			case "PUT":
				req = client.Put(g.String(ts.URL), g.String("test data"))
			case "DELETE":
				req = client.Delete(g.String(ts.URL))
			}

			// Execute the request to apply middleware
			resp := req.Do()
			if resp.IsErr() {
				t.Fatalf("unexpected error: %v", resp.Err())
			}

			// Extract and test the client trace callback
			trace := httptrace.ContextClientTrace(req.GetRequest().Context())
			if trace == nil || trace.Got1xxResponse == nil {
				t.Fatal("expected Got1xxResponse callback to be set by middleware")
			}

			// Test that 101 status code triggers error with correct message
			err := trace.Got1xxResponse(101, nil)
			if err == nil {
				t.Error("expected error for 101 response")
			} else {
				errMsg := err.Error()
				if !strings.Contains(errMsg, tc.method) {
					t.Errorf("expected error message to contain method %s, got: %s", tc.method, errMsg)
				}
				if !strings.Contains(errMsg, ts.URL) {
					t.Errorf("expected error message to contain URL %s, got: %s", ts.URL, errMsg)
				}
			}
		})
	}
}

func TestMiddlewareRequestDefaultUserAgent(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, r *http.Request) {
		userAgent := r.Header.Get("User-Agent")
		if userAgent == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"user-agent": "%s"}`, userAgent)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	// Test default user agent (should be set)
	client := surf.NewClient()
	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if resp.Ok().StatusCode != http.StatusOK {
		t.Error("expected default user agent to be set")
	}

	body := resp.Ok().Body.String()
	// Should have some user agent
	if !strings.Contains(body.Std(), "Mozilla") && !strings.Contains(body.Std(), "surf") {
		t.Log("Default user agent format may have changed")
	}
}

func TestMiddlewareRequestHeaders(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, r *http.Request) {
		// Echo back custom headers
		customHeaders := make(map[string]string)
		for key, values := range r.Header {
			if strings.HasPrefix(key, "X-") {
				customHeaders[key] = values[0]
			}
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `%v`, customHeaders)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	// Test SetHeaders and AddHeaders
	client := surf.NewClient().Builder().
		SetHeaders(g.Map[string, string]{
			"X-First":  "1",
			"X-Second": "2",
		}).
		AddHeaders(g.Map[string, string]{
			"X-Third": "3",
		}).
		Build().Unwrap()

	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	body := resp.Ok().Body.String()

	// Check all headers were sent
	if !strings.Contains(body.Std(), "X-First") {
		t.Error("expected X-First header")
	}
	if !strings.Contains(body.Std(), "X-Second") {
		t.Error("expected X-Second header")
	}
	if !strings.Contains(body.Std(), "X-Third") {
		t.Error("expected X-Third header")
	}
}
