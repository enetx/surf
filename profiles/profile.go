// Package profiles defines the shared variant contract used by browser profile packages
// (profiles/chrome, profiles/firefox, ...) and consumed by the top-level surf package.
//
// A Variant is the self-contained description of one browser and form-factor combination:
// TLS ClientHello, HTTP/2 + HTTP/3 SETTINGS, header set, User-Agent / sec-ch-ua data per OS.
// The surf.Impersonate dispatcher reads chrome.Desktop / chrome.Mobile / firefox.Desktop /
// firefox.Mobile values, applies the static fields, and runs ConfigureH2/ConfigureH3 against
// adapters that satisfy H2Config / H3Config — without the profile package importing surf.
package profiles

import (
	"github.com/enetx/g"
	"github.com/enetx/http2"
	utls "github.com/refraction-networking/utls"
)

// OSKey identifies the impersonated operating system. Surf's Impersonate stores it directly
// (no separate ImpersonateOS enum). Profile packages use it as a lookup key for UA / Platform.
type OSKey int

const (
	Windows OSKey = iota
	MacOS
	Linux
	Android
	IOS
)

// IsMobile reports whether the OS is a mobile form factor (Android or iOS).
func (k OSKey) IsMobile() bool { return k == Android || k == IOS }

// Mobile returns the value of the sec-ch-ua-mobile header: "?1" for mobile OS, "?0" otherwise.
func (k OSKey) Mobile() g.String {
	if k.IsMobile() {
		return "?1"
	}

	return "?0"
}

// H2Config is the fluent contract used by profile.ConfigureH2 callbacks. It mirrors the
// methods on surf.HTTP2Settings, the surf package provides an adapter that satisfies it.
type H2Config interface {
	HeaderTableSize(uint32) H2Config
	EnablePush(uint32) H2Config
	MaxConcurrentStreams(uint32) H2Config
	InitialWindowSize(uint32) H2Config
	MaxFrameSize(uint32) H2Config
	MaxHeaderListSize(uint32) H2Config
	NoRFC7540Priorities(uint32) H2Config
	ConnectionFlow(uint32) H2Config
	InitialStreamID(uint32) H2Config
	PriorityParam(http2.PriorityParam) H2Config
	PriorityFrames([]http2.PriorityFrame) H2Config
}

// H3Config is the fluent contract used by profile.ConfigureH3 callbacks. It mirrors the
// methods on surf.HTTP3Settings, the surf package provides an adapter that satisfies it.
type H3Config interface {
	QpackMaxTableCapacity(uint64) H3Config
	MaxFieldSectionSize(uint64) H3Config
	QpackBlockedStreams(uint64) H3Config
	EnableConnectProtocol(uint64) H3Config
	SettingsH3Datagram(uint64) H3Config
	H3Datagram(uint64) H3Config
	EnableWebtransport(uint64) H3Config
	Grease() H3Config
}

// Variant is a self-contained description of one browser and form-factor combination.
type Variant struct {
	// HelloSpec takes precedence over HelloID when non-nil.
	HelloSpec *utls.ClientHelloSpec
	HelloID   utls.ClientHelloID

	// Boundary is the multipart boundary generator for this browser. Same reference for both
	// Desktop and Mobile within one profile package (boundary is a per-browser property).
	Boundary func() g.String

	// ConfigureH2 / ConfigureH3 own the fluent SETTINGS chain as code. The surf dispatcher
	// invokes them with adapters and calls Set() afterwards.
	ConfigureH2 func(H2Config)
	ConfigureH3 func(H3Config)

	// BuildHeaders constructs the full ordered header map for one request — pseudo-headers,
	// Accept-Encoding, Accept-Language, authorization/cookie/origin/referer placeholders,
	// sec-ch-ua-* (Chromium only), User-Agent. Profile packages provide one BuildHeaders per
	// Variant so each browser and form-factor has its own single point of substitution for the
	// entire header set (set, values, and order are all browser-specific).
	BuildHeaders func(OSKey) *g.MapOrd[g.String, g.String]

	// Headers applies the per-request header-order pipeline (the same Headers[T ~string]
	// function profile packages export) for the surf request path. Same value for Desktop and
	// Mobile within one profile package — header pipeline differs by mobile bool, not by
	// Variant — but living on Variant lets surf.Builder route through one indirection without
	// importing concrete profile packages from the request hot path.
	Headers HeadersApplier
}
