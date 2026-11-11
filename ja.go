package surf

import (
	"math"

	"github.com/enetx/g"
	"github.com/enetx/surf/internal/specclone"
	"github.com/enetx/surf/profiles/chrome"
	"github.com/enetx/surf/profiles/firefox"

	utls "github.com/refraction-networking/utls"
)

// JA provides JA3/4 TLS fingerprinting capabilities for HTTP clients.
// JA is a method for creating SSL/TLS client fingerprints to identify and classify malware
// or other applications. This struct allows configuring various TLS ClientHello specifications
// to mimic different browsers and applications for advanced HTTP client behavior.
//
// Reference: https://lwthiker.com/networks/2022/06/17/tls-fingerprinting.html
type JA struct {
	spec    utls.ClientHelloSpec // Custom TLS ClientHello specification
	id      utls.ClientHelloID   // Predefined TLS ClientHello identifier
	builder *Builder             // Reference to the parent builder for method chaining
	shuffle bool                 // Re-shuffle the spec's extension order on every connection (Chrome behaviour)
}

// SetHelloID sets a ClientHelloID for the TLS connection.
//
// The provided ClientHelloID is used to customize the TLS handshake. This
// should be a valid identifier that can be mapped to a specific ClientHelloSpec.
//
// It returns a pointer to the Options struct for method chaining. This allows
// additional configuration methods to be called on the result.
//
// Example usage:
//
//	JA().SetHelloID(utls.HelloChrome_Auto)
func (j *JA) SetHelloID(id utls.ClientHelloID) *Builder {
	j.id = id
	return j.build()
}

// SetHelloSpec sets a custom ClientHelloSpec for the TLS connection.
//
// This method allows you to set a custom ClientHelloSpec to be used during the TLS handshake.
// The provided spec should be a valid ClientHelloSpec.
//
// It returns a pointer to the Options struct for method chaining. This allows
// additional configuration methods to be called on the result.
//
// Example usage:
//
//	JA().SetHelloSpec(spec)
func (j *JA) SetHelloSpec(spec utls.ClientHelloSpec) *Builder {
	j.spec = spec
	return j.build()
}

// ShuffleExtensions enables Chromium's per-connection ClientHello extension shuffle: the
// extension order is randomized on every TLS handshake instead of staying fixed for the
// lifetime of the client. GREASE, padding and pre_shared_key keep their positions, as they
// are positionally invariant on the wire.
//
// Chromium shuffles since v110, so a custom Chrome-derived spec needs this to stay
// consistent with the User-Agent it claims. Firefox keeps a fixed order — do not enable it
// there.
//
// Unlike SetHelloID / SetHelloSpec this method is not terminal: it returns the JA struct, so
// it has to be chained before the spec is set.
//
// Example usage:
//
//	JA().ShuffleExtensions().SetHelloSpec(spec)
func (j *JA) ShuffleExtensions() *JA {
	j.shuffle = true
	return j
}

// build applies JA3/4 TLS fingerprinting configuration to the HTTP client.
// This method configures the client with custom TLS settings and proxy support for JA3/4 fingerprinting.
//
// The method performs several key operations:
// 1. Selects the TCP transport, including HTTP/3's fallback transport
// 2. Wraps it with the configured HTTP/1.1 and HTTP/2 TLS fingerprint
// 3. Retains HTTP/3's independently configured QUIC ClientHello
//
// Returns the builder instance for method chaining.
func (j *JA) build() *Builder {
	return j.builder.addCliMW(func(c *Client) error {
		if transport, ok := c.GetTransport().(*uquicTransport); ok {
			base := transport.fallbackTransport
			if previous, ok := base.(*roundtripper); ok {
				// Reapplying JA replaces the previous TCP fingerprint.
				base = previous.http1tr
			}

			transport.fallbackTransport = newRoundTripper(j, base)
			return nil
		}

		// Wrap the transport with JA3/4 fingerprinting round tripper
		c.GetClient().Transport = newRoundTripper(j, c.GetTransport())

		return nil
	}, math.MaxInt)
}

// getSpec determines the ClientHelloSpec to be used for the TLS connection.
//
// The ClientHelloSpec is selected based on the following order of precedence:
// 1. If a custom ClientHelloID is set (via SetHelloID), it attempts to convert this ID to a ClientHelloSpec.
// 2. If none of the above conditions are met, it returns the currently set ClientHelloSpec.
//
// The result is always a private copy, never the source spec, so the per-connection mutations
// below are safe under concurrent dials: the extension order is re-shuffled when
// ShuffleExtensions is enabled. uTLS substitutes GREASE placeholders at handshake time.
//
// This method returns the selected ClientHelloSpec along with an error value. If an error occurs
// during conversion, it returns the error.
func (j *JA) getSpec() g.Result[utls.ClientHelloSpec] {
	var spec *utls.ClientHelloSpec

	if !j.id.IsSet() {
		r := g.ResultOf(utls.UTLSIdToSpec(j.id))
		if r.IsErr() {
			return r
		}

		id := r.Ok()
		spec = &id
	} else {
		spec = specclone.Clone(&j.spec)
	}

	if j.shuffle {
		spec.Extensions = utls.ShuffleChromeTLSExtensions(spec.Extensions)
	}

	return g.Ok(*spec)
}

// Android sets the JA3/4 fingerprint to mimic Android 11 OkHttp client.
func (j *JA) Android() *Builder { return j.SetHelloID(utls.HelloAndroid_11_OkHttp) }

// Chrome applies the current Chrome 157 TLS template.
func (j *JA) Chrome() *Builder { return j.Chrome157() }

// Chrome157 applies the current Chrome TLS template with per-connection shuffling.
func (j *JA) Chrome157() *Builder {
	return j.ShuffleExtensions().SetHelloSpec(chrome.HelloChrome_157)
}

// Edge sets the JA3/4 fingerprint to mimic Microsoft Edge version 85.
func (j *JA) Edge() *Builder { return j.SetHelloID(utls.HelloEdge_85) }

// Edge85 sets the JA3/4 fingerprint to mimic Microsoft Edge version 85.
func (j *JA) Edge85() *Builder { return j.SetHelloID(utls.HelloEdge_85) }

// Edge106 sets the JA3/4 fingerprint to mimic Microsoft Edge version 106.
func (j *JA) Edge106() *Builder { return j.SetHelloID(utls.HelloEdge_106) }

// Firefox sets the current Firefox desktop TLS fingerprint.
func (j *JA) Firefox() *Builder { return j.Firefox160() }

// Firefox55 sets the JA3/4 fingerprint to mimic Firefox version 55.
func (j *JA) Firefox55() *Builder { return j.SetHelloID(utls.HelloFirefox_55) }

// Firefox56 sets the JA3/4 fingerprint to mimic Firefox version 56.
func (j *JA) Firefox56() *Builder { return j.SetHelloID(utls.HelloFirefox_56) }

// Firefox63 sets the JA3/4 fingerprint to mimic Firefox version 63.
func (j *JA) Firefox63() *Builder { return j.SetHelloID(utls.HelloFirefox_63) }

// Firefox65 sets the JA3/4 fingerprint to mimic Firefox version 65.
func (j *JA) Firefox65() *Builder { return j.SetHelloID(utls.HelloFirefox_65) }

// Firefox99 sets the JA3/4 fingerprint to mimic Firefox version 99.
func (j *JA) Firefox99() *Builder { return j.SetHelloID(utls.HelloFirefox_99) }

// Firefox102 sets the JA3/4 fingerprint to mimic Firefox version 102.
func (j *JA) Firefox102() *Builder { return j.SetHelloID(utls.HelloFirefox_102) }

// Firefox105 sets the JA3/4 fingerprint to mimic Firefox version 105.
func (j *JA) Firefox105() *Builder { return j.SetHelloID(utls.HelloFirefox_105) }

// Firefox120 sets the JA3/4 fingerprint to mimic Firefox version 120.
func (j *JA) Firefox120() *Builder { return j.SetHelloID(utls.HelloFirefox_120) }

// Firefox148 sets the JA3/4 fingerprint to mimic Firefox version 148.
func (j *JA) Firefox148() *Builder { return j.SetHelloID(utls.HelloFirefox_148) }

// Firefox160 sets the current Firefox 160 desktop TLS fingerprint.
func (j *JA) Firefox160() *Builder { return j.SetHelloSpec(firefox.HelloFirefox_160) }

// IOS sets the JA3/4 fingerprint to mimic the latest iOS Safari browser (auto-detection).
func (j *JA) IOS() *Builder { return j.SetHelloID(utls.HelloIOS_Auto) }

// IOS11 sets the JA3/4 fingerprint to mimic iOS 11.1 Safari.
func (j *JA) IOS11() *Builder { return j.SetHelloID(utls.HelloIOS_11_1) }

// IOS12 sets the JA3/4 fingerprint to mimic iOS 12.1 Safari.
func (j *JA) IOS12() *Builder { return j.SetHelloID(utls.HelloIOS_12_1) }

// IOS13 sets the JA3/4 fingerprint to mimic iOS 13 Safari.
func (j *JA) IOS13() *Builder { return j.SetHelloID(utls.HelloIOS_13) }

// IOS14 sets the JA3/4 fingerprint to mimic iOS 14 Safari.
func (j *JA) IOS14() *Builder { return j.SetHelloID(utls.HelloIOS_14) }

// Randomized sets a completely randomized JA3/4 fingerprint.
func (j *JA) Randomized() *Builder { return j.SetHelloID(utls.HelloRandomized) }

// RandomizedALPN sets a randomized JA3/4 fingerprint with ALPN (Application-Layer Protocol Negotiation).
func (j *JA) RandomizedALPN() *Builder { return j.SetHelloID(utls.HelloRandomizedALPN) }

// RandomizedNoALPN sets a randomized JA3/4 fingerprint without ALPN.
func (j *JA) RandomizedNoALPN() *Builder { return j.SetHelloID(utls.HelloRandomizedNoALPN) }

// Safari sets the JA3/4 fingerprint to mimic the latest Safari browser (auto-detection).
func (j *JA) Safari() *Builder { return j.SetHelloID(utls.HelloSafari_Auto) }

// Safari26_3 sets the TLS fingerprint to Safari 26.3 (also used by Chrome on iOS).
func (j *JA) Safari26_3() *Builder { return j.SetHelloID(utls.HelloSafari_26_3) }
