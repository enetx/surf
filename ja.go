package surf

import (
	"math"

	"github.com/enetx/g"
	"github.com/enetx/surf/internal/specclone"
	"github.com/enetx/surf/profiles/chrome"
	"github.com/enetx/surf/profiles/firefox"

	utls "github.com/enetx/utls"
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

// build applies JA3/4 TLS fingerprinting configuration to the HTTP client.
// This method configures the client with custom TLS settings and proxy support for JA3/4 fingerprinting.
//
// The method performs several key operations:
// 1. Skips configuration if HTTP/3 is being used (JA3/4 only works with HTTP/1.1 and HTTP/2)
// 2. Adds connection cleanup middleware if not using singleton pattern
// 3. Wraps the transport with a custom round tripper that implements JA3/4 fingerprinting
//
// Returns the builder instance for method chaining.
func (j *JA) build() *Builder {
	return j.builder.addCliMW(func(c *Client) error {
		// JA3 fingerprinting is not compatible with HTTP/3 - skip if HTTP/3 is used
		if _, ok := c.GetTransport().(*uquicTransport); ok {
			return nil
		}

		if !j.builder.singleton {
			j.builder.addRespMW(closeIdleConnectionsMW, 0)
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
// This method returns the selected ClientHelloSpec along with an error value. If an error occurs
// during conversion, it returns the error.
func (j *JA) getSpec() g.Result[utls.ClientHelloSpec] {
	if !j.id.IsSet() {
		return g.ResultOf(utls.UTLSIdToSpec(j.id))
	}

	spec := specclone.Clone(&j.spec)
	return g.Ok(*spec)
}

// Browser and application fingerprinting methods.
// These methods provide convenient shortcuts to mimic various popular browsers and applications
// by setting predefined ClientHelloID values that match their TLS fingerprints.

// Android sets the JA3/4 fingerprint to mimic Android 11 OkHttp client.
func (j *JA) Android() *Builder { return j.SetHelloID(utls.HelloAndroid_11_OkHttp) }

// Chrome sets the JA3/4 fingerprint to mimic the latest Chrome browser (auto-detection).
func (j *JA) Chrome() *Builder { return j.SetHelloID(utls.HelloChrome_Auto) }

// Chrome58 sets the JA3/4 fingerprint to mimic Chrome version 58.
func (j *JA) Chrome58() *Builder { return j.SetHelloID(utls.HelloChrome_58) }

// Chrome62 sets the JA3/4 fingerprint to mimic Chrome version 62.
func (j *JA) Chrome62() *Builder { return j.SetHelloID(utls.HelloChrome_62) }

// Chrome70 sets the JA3/4 fingerprint to mimic Chrome version 70.
func (j *JA) Chrome70() *Builder { return j.SetHelloID(utls.HelloChrome_70) }

// Chrome72 sets the JA3/4 fingerprint to mimic Chrome version 72.
func (j *JA) Chrome72() *Builder { return j.SetHelloID(utls.HelloChrome_72) }

// Chrome83 sets the JA3/4 fingerprint to mimic Chrome version 83.
func (j *JA) Chrome83() *Builder { return j.SetHelloID(utls.HelloChrome_83) }

// Chrome87 sets the JA3/4 fingerprint to mimic Chrome version 87.
func (j *JA) Chrome87() *Builder { return j.SetHelloID(utls.HelloChrome_87) }

// Chrome96 sets the JA3/4 fingerprint to mimic Chrome version 96.
func (j *JA) Chrome96() *Builder { return j.SetHelloID(utls.HelloChrome_96) }

// Chrome100 sets the JA3/4 fingerprint to mimic Chrome version 100.
func (j *JA) Chrome100() *Builder { return j.SetHelloID(utls.HelloChrome_100) }

// Chrome102 sets the JA3/4 fingerprint to mimic Chrome version 102.
func (j *JA) Chrome102() *Builder { return j.SetHelloID(utls.HelloChrome_102) }

// Chrome106 sets the JA3/4 fingerprint to mimic Chrome version 106 with shuffled extensions.
func (j *JA) Chrome106() *Builder { return j.SetHelloID(utls.HelloChrome_106_Shuffle) }

// Chrome120 sets the JA3/4 fingerprint to mimic Chrome version 120.
func (j *JA) Chrome120() *Builder { return j.SetHelloID(utls.HelloChrome_120) }

// Chrome120PQ sets the JA3/4 fingerprint to mimic Chrome version 120 with post-quantum cryptography support.
func (j *JA) Chrome120PQ() *Builder { return j.SetHelloID(utls.HelloChrome_120_PQ) }

// Chrome144 sets the JA3/4 fingerprint to mimic Chrome version 144.
func (j *JA) Chrome144() *Builder { return j.SetHelloSpec(chrome.HelloChrome_144) }

// Edge sets the JA3/4 fingerprint to mimic Microsoft Edge version 85.
func (j *JA) Edge() *Builder { return j.SetHelloID(utls.HelloEdge_85) }

// Edge85 sets the JA3/4 fingerprint to mimic Microsoft Edge version 85.
func (j *JA) Edge85() *Builder { return j.SetHelloID(utls.HelloEdge_85) }

// Edge106 sets the JA3/4 fingerprint to mimic Microsoft Edge version 106.
func (j *JA) Edge106() *Builder { return j.SetHelloID(utls.HelloEdge_106) }

// Firefox sets the JA3/4 fingerprint to mimic the latest Firefox browser (auto-detection).
func (j *JA) Firefox() *Builder { return j.SetHelloID(utls.HelloFirefox_Auto) }

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

// Firefox141 sets the JA3/4 fingerprint to mimic Firefox version 141.
func (j *JA) Firefox141() *Builder { return j.SetHelloID(utls.HelloFirefox_141) }

// Firefox147 sets the JA3/4 fingerprint to mimic Firefox version 147.
func (j *JA) Firefox147() *Builder { return j.SetHelloSpec(firefox.HelloFirefox_147) }

// FirefoxPrivate147 sets the JA3/4 fingerprint to mimic Firefox private version 147.
func (j *JA) FirefoxPrivate147() *Builder { return j.SetHelloSpec(firefox.HelloFirefoxPrivate_147) }

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
