package chrome_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/surf/header"
	"github.com/enetx/surf/profiles"
	"github.com/enetx/surf/profiles/chrome"
	utls "github.com/enetx/utls"
)

func TestIOSProfile(t *testing.T) {
	t.Parallel()

	if chrome.IOS.HelloID != utls.HelloSafari_26_3 || chrome.IOS.HelloSpec != &chrome.HelloChrome_158_IOS || chrome.IOS.ShuffleExtensions {
		t.Fatal("iOS must use the native WebKit ClientHello with fixed extension order")
	}
	for _, extension := range chrome.IOS.HelloSpec.Extensions {
		if _, ok := extension.(utls.PreSharedKeyExtension); ok {
			t.Fatal("the captured iOS profile must not add an unverified PSK")
		}
	}
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodGet + "http3", http.MethodPost + "http3"} {
		t.Run(method, func(t *testing.T) {
			h := chrome.IOS.BuildHeaders(profiles.IOS)
			chrome.IOS.Headers(h, method)
			for _, key := range []g.String{header.SEC_CH_UA, header.SEC_CH_UA_MOBILE, header.SEC_CH_UA_PLATFORM, header.SEC_FETCH_USER, header.UPGRADE_INSECURE_REQUESTS, header.CACHE_CONTROL, header.PRAGMA} {
				if h.Contains(key) {
					t.Errorf("iOS must not add %s", key)
				}
			}
			if ua := h.Get(header.USER_AGENT).Unwrap(); !ua.Contains("CriOS/158.0.8127.32") || !ua.Contains("iPhone OS 27_0_1") {
				t.Errorf("iOS UA does not match the release build and retained device OS: %s", ua)
			}
			keys := h.Keys()
			if !slices.Equal(keys[:4], []g.String{":method", ":scheme", ":authority", ":path"}) {
				t.Errorf("iOS pseudo-header order = %v", keys[:4])
			}
			if strings.HasPrefix(method, http.MethodPost) {
				if got := h.Get(header.ACCEPT).Unwrap(); got != "*/*" {
					t.Errorf("fetch Accept = %q", got)
				}
				if got := h.Get(header.SEC_FETCH_DEST).Unwrap(); got != "empty" {
					t.Errorf("fetch destination = %q", got)
				}
			}
		})
	}
}
