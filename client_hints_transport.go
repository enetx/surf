package surf

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/enetx/http"
	"github.com/enetx/surf/profiles"
)

// clientHintsTransport adds origin-scoped HTTP hint negotiation to an existing transport.
// Configure its public hooks before concurrent use. Available values and cache
// limits are immutable snapshots created by clientHintsConfig.build.
type clientHintsTransport struct {
	// Base owns protocol selection, connections and wire encoding.
	Base http.RoundTripper
	// Jar returns the owning client's current cookie jar. On a critical restart,
	// response cookies are committed before the next request. Nil skips cookies.
	Jar func() http.CookieJar
	// Prepare refreshes logical profile defaults after hints are added. Final
	// layout is applied by the selected protocol's transport boundary.
	// The bool reports a Critical-CH restart. It must support concurrent calls.
	// It must not read the body or mutate shared profile data.
	Prepare func(*http.Request, bool)
	enabled bool
	values  map[string]string
	cache   *clientHintStore
}

type (
	clientHintAttemptKey struct{}
	clientHintAttempt    struct {
		restarted  bool
		generated  http.Header
		navigation *clientHintNavigationState
	}
)

type clientHintNavigationState struct {
	mu        sync.Mutex
	restarted map[string]bool
}

func (n *clientHintNavigationState) take(origin string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.restarted[origin] {
		return false
	}

	n.restarted[origin] = true

	return true
}

func previousClientHintAttempt(req *http.Request) *clientHintAttempt {
	if state, _ := req.Context().Value(clientHintAttemptKey{}).(*clientHintAttempt); state != nil {
		return state
	}

	if req.Response != nil && req.Response.Request != nil {
		state, _ := req.Response.Request.Context().Value(clientHintAttemptKey{}).(*clientHintAttempt)
		return state
	}

	return nil
}

// requestNavigationContext copies navigation and profile-value ownership
// between HTTP adapters, preserving the destination cancellation and deadline.
func requestNavigationContext(destination, source context.Context) context.Context {
	if kind, ok := profiles.RequestKindFromContext(source); ok {
		destination = profiles.WithRequestKind(destination, kind)
	}

	if state, _ := source.Value(clientHintAttemptKey{}).(*clientHintAttempt); state != nil {
		destination = context.WithValue(destination, clientHintAttemptKey{}, state)
	}

	if state, _ := source.Value(profileHeaderKey{}).(*profileHeaderState); state != nil {
		destination = context.WithValue(destination, profileHeaderKey{}, state)
	}

	if redirectResponse := source.Value(profileRedirectKey{}); redirectResponse != nil {
		destination = context.WithValue(destination, profileRedirectKey{}, redirectResponse)
	}

	if dropped, _ := source.Value(profileBodyDroppedKey{}).(bool); dropped {
		destination = context.WithValue(destination, profileBodyDroppedKey{}, true)
	}

	return destination
}

func joinedClientHint(h http.Header, name string) string {
	values, _ := profileHeaderValues(h, name)
	return strings.Join(values, ", ")
}

func containsClientHint(names []string, name string) bool { return slices.Contains(names, name) }

func isClientHintNavigation(req *http.Request) bool {
	mode := joinedClientHint(req.Header, "sec-fetch-mode")
	dest := joinedClientHint(req.Header, "sec-fetch-dest")
	// Preserve explicit scenario headers and the standalone adapter contract.
	// Nil/empty fields suppress emission, not a known navigation context.
	if mode != "" && !strings.EqualFold(mode, "navigate") || dest != "" && !strings.EqualFold(dest, "document") {
		return false
	}

	if mode != "" && dest != "" {
		return true
	}
	// Chromium knows the navigation from NavigationRequest, independently of
	// emitted Fetch Metadata. Standalone clients without a known scenario are
	// not promoted to document navigation solely because the method is GET.
	// https://github.com/chromium/chromium/blob/158.0.8127.18/content/browser/client_hints/critical_client_hints_throttle.cc
	if kind, selected := profiles.RequestKindFromContext(req.Context()); selected && kind != profiles.AutomaticRequest {
		return (profiles.HeaderContext{Request: req, Kind: kind}).Navigation()
	}

	if state := previousProfileHeaders(req); state != nil {
		return state.kind == profiles.NavigationRequest
	}

	return false
}

func (t *clientHintsTransport) prepare(
	req *http.Request,
	nav *clientHintNavigationState,
	enabled []string,
	restarted bool,
) *http.Request {
	clone := req.Clone(req.Context())
	if clone.Header == nil {
		clone.Header = make(http.Header)
	}

	if old := previousClientHintAttempt(req); old != nil {
		for name, value := range old.generated {
			if actual, ok := profileHeaderValues(clone.Header, name); ok && slices.Equal(actual, value) {
				deleteProfileHeader(clone.Header, name)
			}
		}
	}
	// Preset defaults remain profile-owned until a public header setter takes
	// ownership. Replace them with the configured identity, while preserving
	// explicit values even when they equal the original preset value.
	if profile := previousProfileHeaders(req); profile != nil {
		for name, value := range profile.generated {
			if _, available := t.values[name]; !available || !defaultClientHint(name) {
				continue
			}
			if actual, present := profileHeaderValues(clone.Header, name); present && slices.Equal(actual, value) {
				deleteProfileHeader(clone.Header, name)
			}
		}
	}

	state := &clientHintAttempt{restarted: restarted, navigation: nav, generated: make(http.Header)}

	if clientHintTrustworthy(clone.URL) {
		for _, name := range knownClientHintNames {
			if !defaultClientHint(name) && !containsClientHint(enabled, name) {
				continue
			}

			value, available := t.values[name]

			if _, explicit := profileHeaderValues(clone.Header, name); explicit || !available {
				continue
			}

			clone.Header.Set(name, value)
			state.generated[name] = []string{value}
		}
	}

	clone = clone.WithContext(context.WithValue(clone.Context(), clientHintAttemptKey{}, state))
	if t.Prepare != nil {
		t.Prepare(clone, restarted)
	}

	return clone
}

// RoundTrip adds only opted-in hints, learns Accept-CH on document navigations,
// and permits at most one Critical-CH restart per origin in a navigation chain.
// Bodies are replayed only through GetBody; an unreplayable response is returned
// unchanged. Missing, malformed and cross-origin hint policies never leak state.
// https://github.com/chromium/chromium/blob/158.0.8127.18/content/browser/client_hints/critical_client_hints_throttle.cc
func (t *clientHintsTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !t.enabled {
		return t.Base.RoundTrip(req)
	}

	if req == nil || req.URL == nil {
		return nil, errors.New("client hints: request URL is required")
	}

	var nav *clientHintNavigationState
	if state := previousClientHintAttempt(req); state != nil {
		nav = state.navigation
	}

	if nav == nil {
		nav = &clientHintNavigationState{restarted: make(map[string]bool)}
	}

	origin, valid := clientHintOrigin(req.URL)

	var enabled []string
	if valid && clientHintTrustworthy(req.URL) {
		enabled = t.cache.get(origin)
	}

	attempt := t.prepare(req, nav, enabled, false)
	resp, err := t.Base.RoundTrip(attempt)
	if err != nil || resp == nil {
		return resp, err
	}

	if resp.Request == nil {
		resp.Request = attempt
	}

	if !valid || !clientHintTrustworthy(attempt.URL) || !isClientHintNavigation(attempt) || resp.StatusCode < 200 {
		return resp, nil
	}

	accept, present := profileHeaderValues(resp.Header, "accept-ch")
	if !present {
		return resp, nil
	}

	requested, ok := parseClientHints(strings.Join(accept, ", "))
	if !ok {
		return resp, nil
	}

	// A new valid list replaces previous opt-ins, including an empty list.
	t.cache.put(origin, requested)
	criticalValue, present := profileHeaderValues(resp.Header, "critical-ch")
	if !present {
		return resp, nil
	}

	critical, ok := parseClientHints(strings.Join(criticalValue, ", "))
	if !ok {
		return resp, nil
	}

	missing := false
	for _, name := range critical {
		if !defaultClientHint(name) && containsClientHint(requested, name) && !containsClientHint(enabled, name) {
			missing = true
			break
		}
	}

	if !missing || !nav.take(origin) {
		return resp, nil
	}

	retry := t.prepare(attempt, nav, requested, true)

	added := false
	for _, name := range knownClientHintNames {
		_, before := profileHeaderValues(attempt.Header, name)
		_, after := profileHeaderValues(retry.Header, name)
		if !before && after {
			added = true
			break
		}
	}

	if !added || req.Context().Err() != nil {
		return resp, nil
	}

	if req.Body != nil && req.Body != http.NoBody {
		if req.GetBody == nil {
			return resp, nil
		}

		body, err := req.GetBody()
		if err != nil {
			if body != nil {
				body.Close()
			}

			if resp.Body != nil {
				resp.Body.Close()
			}

			return nil, fmt.Errorf("client hints: restoring request body: %w", err)
		}

		if body == nil {
			if resp.Body != nil {
				resp.Body.Close()
			}

			return nil, errors.New("client hints: GetBody returned a nil body")
		}

		retry.Body = body
	}

	t.updateCookies(attempt, retry, resp)
	discardClientHintResponse(resp)

	result, err := t.Base.RoundTrip(retry)
	if result != nil && result.Request == nil {
		result.Request = retry
	}

	if err == nil && result != nil && result.StatusCode >= 200 {
		if value, present := profileHeaderValues(result.Header, "accept-ch"); present {
			if names, valid := parseClientHints(strings.Join(value, ", ")); valid {
				t.cache.put(origin, names)
			}
		}
	}

	return result, err
}

func (t *clientHintsTransport) updateCookies(before, retry *http.Request, resp *http.Response) {
	if t.Jar == nil {
		return
	}

	jar := t.Jar()
	if jar == nil {
		return
	}

	old := jar.Cookies(before.URL)
	jar.SetCookies(before.URL, resp.Cookies())

	values := before.Cookies()
	for _, cookie := range old {
		for i, value := range slices.Backward(values) {
			if value.Name == cookie.Name && value.Value == cookie.Value {
				values = slices.Delete(values, i, i+1)
				break
			}
		}
	}

	deleteProfileHeader(retry.Header, "cookie")

	for _, cookie := range values {
		retry.AddCookie(cookie)
	}

	for _, cookie := range jar.Cookies(retry.URL) {
		retry.AddCookie(cookie)
	}
}

// Hints returns a private copy of remembered opt-ins for a URL's origin.
func (t *clientHintsTransport) Hints(rawURL string) []string {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil
	}

	origin, ok := clientHintOrigin(req.URL)
	if !ok {
		return nil
	}

	return t.cache.get(origin)
}

// Clear drops all remembered origin opt-ins. In-flight requests retain the
// private snapshot they already selected.
func (t *clientHintsTransport) Clear() {
	t.cache.mu.Lock()
	defer t.cache.mu.Unlock()

	clear(t.cache.entries)
	t.cache.lru.Init()
}

// CloseIdleConnections delegates idle-connection management to the base.
func (t *clientHintsTransport) CloseIdleConnections() {
	if closer, ok := t.Base.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

var _ http.RoundTripper = (*clientHintsTransport)(nil)

// Small HTTP/1 response bodies are drained so the restart can reuse the socket.
// Multiplexed streams are canceled independently. The size/time bounds follow
// Chromium's abandoned-response drainer; a streaming peer cannot stall forever.
// https://github.com/chromium/chromium/blob/158.0.8127.18/net/http/http_response_body_drainer.h
func discardClientHintResponse(resp *http.Response) {
	if resp.Body == nil {
		return
	}

	if resp.ProtoMajor == 1 {
		timer := time.AfterFunc(5*time.Second, func() { resp.Body.Close() })
		_, _ = io.CopyN(io.Discard, resp.Body, 16384)
		timer.Stop()
	}

	resp.Body.Close()
}
