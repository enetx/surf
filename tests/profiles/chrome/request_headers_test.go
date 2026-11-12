package chrome_test

import (
	"io"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/surf/header"
	"github.com/enetx/surf/profiles"
	"github.com/enetx/surf/profiles/chrome"
	"github.com/enetx/surf/profiles/chrome/common"
)

func TestChromeTypedRequestScenarios(t *testing.T) {
	for _, tc := range []struct {
		name, method, mode, priority string
		navigation                   bool
	}{
		{name: "GET navigation", method: http.MethodGet, priority: "u=0, i", navigation: true},
		{name: "HEAD navigation", method: http.MethodHead, priority: "u=0, i", navigation: true},
		{name: "GET fetch", method: http.MethodGet, mode: "cors", priority: "u=1, i"},
		{name: "HEAD fetch", method: http.MethodHead, mode: "cors", priority: "u=1, i"},
		{name: "POST fetch", method: http.MethodPost, priority: "u=1, i"},
		{name: "POST navigation", method: http.MethodPost, mode: "navigate", priority: "u=0, i", navigation: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := &http.Request{Method: tc.method, Header: make(http.Header)}
			if tc.mode != "" {
				req.Header.Set(header.SEC_FETCH_MODE, tc.mode)
			}
			original := req.Header.Clone()
			ctx := profiles.HeaderContext{Request: req, OS: profiles.Windows, Protocol: 2}
			h := chrome.Desktop.BuildRequestHeaders(ctx)
			if got := h.Get(header.PRIORITY).UnwrapOrDefault().Std(); got != tc.priority {
				t.Fatalf("Priority = %q, want %q", got, tc.priority)
			}
			if got := h.Get(header.UPGRADE_INSECURE_REQUESTS).UnwrapOrDefault() != ""; got != tc.navigation {
				t.Fatalf("navigation fields present = %v, want %v", got, tc.navigation)
			}
			if !slices.Equal(h.Keys()[:4], []g.String{":method", ":authority", ":scheme", ":path"}) {
				t.Fatalf("Chrome pseudo-header order: %v", h.Keys()[:4])
			}
			if !reflect.DeepEqual(req.Header, original) {
				t.Fatal("factory mutated the request")
			}
			h.Insert(header.USER_AGENT, "modified")
			if fresh := chrome.Desktop.BuildRequestHeaders(ctx); fresh.Get(header.USER_AGENT).UnwrapOrDefault() == "modified" {
				t.Fatal("factory maps share mutable state")
			}
		})
	}
}

func TestChromeFetchLengthSlotsFollowUploads(t *testing.T) {
	for _, method := range []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"} {
		for _, kind := range []string{"absent", "explicit empty", "known", "unknown"} {
			t.Run(method+"/"+kind, func(t *testing.T) {
				req := &http.Request{Method: method, Header: http.Header{"Sec-Fetch-Mode": {"cors"}}, Body: http.NoBody}
				reader := strings.NewReader("payload")
				switch kind {
				case "explicit empty":
					req.GetBody = func() (io.ReadCloser, error) { panic("factory must not call GetBody") }
				case "known":
					req.Body, req.ContentLength = io.NopCloser(reader), 7
				case "unknown":
					req.Body = io.NopCloser(reader)
				}
				h := common.BuildRequestHeaders(profiles.HeaderContext{Request: req, Protocol: 3})
				want := kind != "absent" || method == http.MethodPost || method == http.MethodPut
				if got := h.Contains(header.CONTENT_LENGTH); got != want {
					t.Fatalf("Content-Length slot = %v, want %v", got, want)
				}
				if h.Get(header.CONTENT_LENGTH).UnwrapOrDefault() != "" || reader.Len() != 7 {
					t.Fatal("factory invented a length or read the body")
				}
			})
		}
	}
}

func TestChromeHeaderCaseAndProtocolAdapterPreserveOwnership(t *testing.T) {
	for _, major := range []int{1, 2, 3} {
		req := &http.Request{Method: http.MethodGet, Header: http.Header{
			"Sec-Ch-Ua-Arch":     {`"arm"`},
			"User-Agent":         {"custom"},
			"X-Custom":           {"keep"},
			http.HeaderOrderKey:  {"x-custom", "sec-ch-ua-arch"},
			http.PHeaderOrderKey: {":path", ":scheme", ":authority", ":method"},
			http.HeaderCaseKey:   {"SEC-CH-UA-ARCH"},
		}}
		original := req.Header.Clone()
		names := common.HeaderCase(profiles.HeaderContext{Request: req, Protocol: major})
		if major == 1 && !slices.Equal(names, []string{header.SEC_CH_UA_ARCH}) || major != 1 && len(names) != 0 {
			t.Fatalf("protocol %d casing %v", major, names)
		}
		if !reflect.DeepEqual(req.Header, original) {
			t.Fatal("pure casing callback mutated the request")
		}
		common.RequestHeaders(req, major)
		for name, value := range original {
			if !reflect.DeepEqual(req.Header[name], value) {
				t.Fatalf("protocol %d changed explicit %s: %v", major, name, req.Header[name])
			}
		}
	}
}

func TestChromeHeaderApplierPreservesCaseInsensitiveValues(t *testing.T) {
	h := g.NewMapOrd[string, string]()
	h.Insert("USER-AGENT", "custom")
	h.Insert("ACCEPT", "application/custom")
	h.Insert("Sec-Fetch-Mode", "cors")
	h.Insert("X-Z", "last")
	h.Insert("X-A", "first")
	chrome.DesktopApplier(&h, http.MethodGet)
	for name, want := range map[string]string{"USER-AGENT": "custom", "ACCEPT": "application/custom", "Sec-Fetch-Mode": "cors"} {
		if got := h.Get(name).UnwrapOrDefault(); got != want {
			t.Fatalf("%s = %q, want %q", name, got, want)
		}
	}
	if got := h.Keys(); !slices.Equal(got[len(got)-2:], []string{"X-A", "X-Z"}) {
		t.Fatalf("unknown fields not in a deterministic tail: %v", got)
	}
	if h.Contains(header.UPGRADE_INSECURE_REQUESTS) || h.Contains(header.SEC_FETCH_USER) {
		t.Fatal("an explicit GET fetch became a navigation")
	}
}
