package h3transport

import (
	"context"
	"sync"
	"testing"

	"github.com/enetx/http"
	"github.com/enetx/quic-go/http3"
)

func TestResponseProgressRace(t *testing.T) {
	for range 500 {
		p := new(responseProgress)
		var headers, fallback bool
		var wg sync.WaitGroup
		wg.Go(func() { headers = p.observe() })
		wg.Go(func() { fallback = p.allowFallback() })
		wg.Wait()
		if headers == fallback || p.observe() != headers || p.allowFallback() != fallback {
			t.Fatal("headers and TCP fallback must have exactly one persistent winner")
		}
	}
}

func TestResponseProgressCallbackOwnership(t *testing.T) {
	p := new(responseProgress)
	req, _ := http.NewRequestWithContext(context.WithValue(t.Context(), responseProgressKey{}, p), "GET", "https://example.com", nil)
	calls := 0
	config := &http3.WireConfig{OnResponseHeaders: func(*http.Request, *http.Response) error { calls++; return nil }}
	wrapper := responseWireConfig(config)
	if !p.allowFallback() || wrapper.OnResponseHeaders(req, &http.Response{StatusCode: 103}) != context.Canceled || calls != 0 {
		t.Fatal("late QUIC headers reached application after TCP committed")
	}
	if config.OnResponseHeaders(req, nil) != nil || calls != 1 {
		t.Fatal("wrapper mutated caller-owned config")
	}
	req, _ = http.NewRequest("GET", "https://example.com", nil)
	if responseWireConfig(nil).OnResponseHeaders(req, nil) != nil {
		t.Fatal("request without progress must remain usable")
	}
}
