package chrome_test

import (
	"fmt"
	"slices"
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
	for _, major := range []int{2, 3} {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			t.Run(fmt.Sprintf("%s/http%d", method, major), func(t *testing.T) {
				h := chrome.IOS.BuildRequestHeaders(profiles.HeaderContext{Request: &http.Request{Method: method}, OS: profiles.IOS, Protocol: major})
				for _, key := range []g.String{header.SEC_CH_UA, header.SEC_CH_UA_MOBILE, header.SEC_CH_UA_PLATFORM, header.SEC_FETCH_USER, header.UPGRADE_INSECURE_REQUESTS, header.CACHE_CONTROL, header.PRAGMA} {
					if h.Get(key).UnwrapOrDefault() != "" {
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
				if method == http.MethodPost {
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
}
