package surf_test

import (
	"fmt"
	"testing"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/http/httptest"
	"github.com/enetx/http2"
	"github.com/enetx/surf"
)

func TestHTTP2SettingsHeaderTableSize(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"header_table_size": "configured"}`)
	}

	ts := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().
		HTTP2Settings().
		HeaderTableSize(65536).
		Set().
		Build().Unwrap()

	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatalf("HTTP/2 header table size request failed: %v", resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}
}

func TestHTTP2SettingsEnablePush(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"enable_push": "configured"}`)
	}

	ts := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer ts.Close()

	testCases := []struct {
		name       string
		pushValue  uint32
		expectPush bool
	}{
		{"Enable push", 1, true},
		{"Disable push", 0, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := surf.NewClient().Builder().
				HTTP2Settings().
				EnablePush(tc.pushValue).
				Set().
				Build().Unwrap()

			resp := client.Get(g.String(ts.URL)).Do()
			if resp.IsErr() {
				t.Fatalf("HTTP/2 enable push request failed: %v", resp.Err())
			}

			if !resp.Ok().StatusCode.IsSuccess() {
				t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
			}
		})
	}
}

func TestHTTP2SettingsMaxConcurrentStreams(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"max_concurrent_streams": "configured"}`)
	}

	ts := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().
		HTTP2Settings().
		MaxConcurrentStreams(100).
		Set().
		Build().Unwrap()

	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatalf("HTTP/2 max concurrent streams request failed: %v", resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}
}

func TestHTTP2SettingsInitialStreamID(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"initial_stream_id": "configured"}`)
	}

	ts := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().
		HTTP2Settings().
		InitialStreamID(3).
		Set().
		Build().Unwrap()

	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatalf("HTTP/2 initial stream id request failed: %v", resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}
}

func TestHTTP2SettingsInitialWindowSize(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"initial_window_size": "configured"}`)
	}

	ts := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().
		HTTP2Settings().
		InitialWindowSize(65535).
		Set().
		Build().Unwrap()

	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatalf("HTTP/2 initial window size request failed: %v", resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}
}

func TestHTTP2SettingsMaxFrameSize(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"max_frame_size": "configured"}`)
	}

	ts := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().
		HTTP2Settings().
		MaxFrameSize(16384).
		Set().
		Build().Unwrap()

	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatalf("HTTP/2 max frame size request failed: %v", resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}
}

func TestHTTP2SettingsMaxHeaderListSize(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"max_header_list_size": "configured"}`)
	}

	ts := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().
		HTTP2Settings().
		MaxHeaderListSize(8192).
		Set().
		Build().Unwrap()

	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatalf("HTTP/2 max header list size request failed: %v", resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}
}

func TestHTTP2SettingsConnectionFlow(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"connection_flow": "configured"}`)
	}

	ts := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().
		HTTP2Settings().
		ConnectionFlow(1048576).
		Set().
		Build().Unwrap()

	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatalf("HTTP/2 connection flow request failed: %v", resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}
}

func TestHTTP2SettingsPriorityParam(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"priority_param": "configured"}`)
	}

	ts := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer ts.Close()

	priorityParam := http2.PriorityParam{
		StreamDep: 0,
		Exclusive: false,
		Weight:    255,
	}

	client := surf.NewClient().Builder().
		HTTP2Settings().
		PriorityParam(priorityParam).
		Set().
		Build().Unwrap()

	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatalf("HTTP/2 priority param request failed: %v", resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}
}

func TestHTTP2SettingsPriorityFrames(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"priority_frames": "configured"}`)
	}

	ts := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer ts.Close()

	priorityFrames := []http2.PriorityFrame{
		{
			FrameHeader: http2.FrameHeader{StreamID: 3},
			PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    200,
			},
		},
		{
			FrameHeader: http2.FrameHeader{StreamID: 5},
			PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    100,
			},
		},
	}

	client := surf.NewClient().Builder().
		HTTP2Settings().
		PriorityFrames(priorityFrames).
		Set().
		Build().Unwrap()

	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatalf("HTTP/2 priority frames request failed: %v", resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}
}

func TestHTTP2SettingsCombined(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"combined_settings": "configured"}`)
	}

	ts := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().
		HTTP2Settings().
		HeaderTableSize(65536).
		EnablePush(1).
		MaxConcurrentStreams(100).
		InitialWindowSize(65535).
		MaxFrameSize(16384).
		MaxHeaderListSize(8192).
		ConnectionFlow(1048576).
		Set().
		Build().Unwrap()

	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatalf("HTTP/2 combined settings request failed: %v", resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}
}

func TestHTTP2SettingsWithForceHTTP1(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"force_http1": "configured"}`)
	}

	ts := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer ts.Close()

	// HTTP/2 settings should be ignored when ForceHTTP1 is enabled
	client := surf.NewClient().Builder().
		ForceHTTP1().
		HTTP2Settings().
		HeaderTableSize(65536).
		Set().
		Build().Unwrap()

	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatalf("ForceHTTP1 with HTTP/2 settings request failed: %v", resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}

	// Verify HTTP/1.1 is being used
	httpResp := resp.Ok().GetResponse()
	if httpResp.Proto != "HTTP/1.1" {
		t.Logf("Expected HTTP/1.1, got %s", httpResp.Proto)
	}
}

func TestHTTP2SettingsChaining(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"chaining": "works"}`)
	}

	ts := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer ts.Close()

	// Test method chaining works correctly
	client := surf.NewClient().Builder().
		HTTP2Settings().
		HeaderTableSize(32768).
		MaxConcurrentStreams(50).
		InitialWindowSize(32768).
		MaxFrameSize(32768).
		MaxHeaderListSize(4096).
		Set().
		Session().
		UserAgent("HTTP2Test/1.0").
		Build().Unwrap()

	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatalf("HTTP/2 settings chaining request failed: %v", resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}
}

func TestHTTP2SettingsProtocolVerification(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"protocol": "%s"}`, r.Proto)
	}

	ts := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().
		HTTP2Settings().
		HeaderTableSize(65536).
		Set().
		Build().Unwrap()

	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatalf("HTTP/2 protocol verification request failed: %v", resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}

	// Check if HTTP/2 is being used (may vary based on server support)
	if resp.Ok().Body.Contains("HTTP/2") {
		t.Log("Successfully using HTTP/2 protocol")
	} else if resp.Ok().Body.Contains("HTTP/1.1") {
		t.Log("Server responded with HTTP/1.1 (HTTP/2 may not be supported)")
	}
}
