package chrome_test

import (
	"testing"

	"github.com/enetx/http"
	"github.com/enetx/surf/header"
	"github.com/enetx/surf/profiles"
	"github.com/enetx/surf/profiles/chrome"
)

// HTTP/3's method suffix must not turn a mobile fetch into a navigation.
func TestAndroidHTTP3PostHeaders(t *testing.T) {
	t.Parallel()

	h := chrome.Mobile.BuildHeaders(profiles.Android)
	chrome.Mobile.Headers(h, http.MethodPost+"http3")
	if got := h.Get(header.ACCEPT).Unwrap(); got != "*/*" {
		t.Errorf("fetch Accept = %q, want */*", got)
	}
	if h.Contains(header.SEC_FETCH_USER) || h.Contains(header.UPGRADE_INSECURE_REQUESTS) {
		t.Error("fetch has navigation-only headers")
	}
}
