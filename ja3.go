package surf

import (
	"context"
	"math/rand"
	"net"

	"github.com/enetx/http"
	"github.com/enetx/surf/internal/ja3c"
	"github.com/enetx/surf/pkg/connectproxy"

	utls "github.com/refraction-networking/utls"
)

// https://lwthiker.com/networks/2022/06/17/tls-fingerprinting.html
type ja3 struct {
	spec    utls.ClientHelloSpec
	id      utls.ClientHelloID
	builder *builder
	str     string
}

// SetHelloStr sets a custom JA3 string for the TLS connection.
//
// This method allows you to set a custom JA3 string to be used during the TLS handshake.
// The provided string should be a valid JA3 string.
//
// It returns a pointer to the Options struct for method chaining. This allows
// additional configuration methods to be called on the result.
//
// Example usage:
//
//	JA3.SetHelloStr("customJA3")
func (j *ja3) SetHelloStr(str string) *builder {
	j.str = str
	return j.build()
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
//	JA3.SetHelloID(utls.HelloChrome_Auto)
func (j *ja3) SetHelloID(id utls.ClientHelloID) *builder {
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
//	JA3.SetHelloSpec(spec)
func (j *ja3) SetHelloSpec(spec utls.ClientHelloSpec) *builder {
	j.spec = spec
	return j.build()
}

func (j *ja3) build() *builder {
	return j.builder.addCliMW(0, func(c *Client) {
		if !j.builder.singleton {
			j.builder.addRespMW(closeIdleConnectionsMW)
		}

		if j.builder.proxy != nil {
			var tp string
			switch p := j.builder.proxy.(type) {
			case string:
				tp = p
			case []string:
				tp = p[rand.Intn(len(p))]
			}

			if dialer, err := connectproxy.NewDialer(tp); err != nil {
				c.GetTransport().(*http.Transport).DialContext = func(context.Context, string, string) (net.Conn, error) { return nil, err }
			} else {
				c.GetTransport().(*http.Transport).DialContext = dialer.DialContext
			}
		}

		c.GetClient().Transport = newRoundTripper(j, c.GetTransport())
	})
}

// getSpec determines the ClientHelloSpec to be used for the TLS connection.
//
// The ClientHelloSpec is selected based on the following order of precedence:
// 1. If a custom JA3 string is set (via SetHelloStr), it attempts to convert this string to a ClientHelloSpec.
// 2. If a custom ClientHelloID is set (via SetHelloID), it attempts to convert this ID to a ClientHelloSpec.
// 3. If none of the above conditions are met, it returns the currently set ClientHelloSpec.
//
// This method returns the selected ClientHelloSpec along with an error value. If an error occurs
// during conversion, it returns the error.
func (j *ja3) getSpec() (utls.ClientHelloSpec, error) {
	switch {
	case j.str != "":
		spec, err := ja3c.CreateSpecWithStr(j.str)
		if err != nil {
			return utls.ClientHelloSpec{}, err
		}
		return ja3c.ProcessSpec(spec), nil
	case !j.id.IsSet():
		return utls.UTLSIdToSpec(j.id)
	}

	return j.spec, nil
}

func (j *ja3) Android() *builder          { return j.SetHelloID(utls.HelloAndroid_11_OkHttp) }
func (j *ja3) Chrome() *builder           { return j.SetHelloID(utls.HelloChrome_Auto) }
func (j *ja3) Chrome58() *builder         { return j.SetHelloID(utls.HelloChrome_58) }
func (j *ja3) Chrome62() *builder         { return j.SetHelloID(utls.HelloChrome_62) }
func (j *ja3) Chrome70() *builder         { return j.SetHelloID(utls.HelloChrome_70) }
func (j *ja3) Chrome72() *builder         { return j.SetHelloID(utls.HelloChrome_72) }
func (j *ja3) Chrome83() *builder         { return j.SetHelloID(utls.HelloChrome_83) }
func (j *ja3) Chrome87() *builder         { return j.SetHelloID(utls.HelloChrome_87) }
func (j *ja3) Chrome96() *builder         { return j.SetHelloID(utls.HelloChrome_96) }
func (j *ja3) Chrome100() *builder        { return j.SetHelloID(utls.HelloChrome_100) }
func (j *ja3) Chrome102() *builder        { return j.SetHelloID(utls.HelloChrome_102) }
func (j *ja3) Chrome106() *builder        { return j.SetHelloID(utls.HelloChrome_106_Shuffle) }
func (j *ja3) Chrome120() *builder        { return j.SetHelloID(utls.HelloChrome_120) }
func (j *ja3) Chrome120PQ() *builder      { return j.SetHelloID(utls.HelloChrome_120_PQ) }
func (j *ja3) Edge() *builder             { return j.SetHelloID(utls.HelloEdge_85) }
func (j *ja3) Edge85() *builder           { return j.SetHelloID(utls.HelloEdge_85) }
func (j *ja3) Edge106() *builder          { return j.SetHelloID(utls.HelloEdge_106) }
func (j *ja3) Firefox() *builder          { return j.SetHelloID(utls.HelloFirefox_Auto) }
func (j *ja3) Firefox55() *builder        { return j.SetHelloID(utls.HelloFirefox_55) }
func (j *ja3) Firefox56() *builder        { return j.SetHelloID(utls.HelloFirefox_56) }
func (j *ja3) Firefox63() *builder        { return j.SetHelloID(utls.HelloFirefox_63) }
func (j *ja3) Firefox65() *builder        { return j.SetHelloID(utls.HelloFirefox_65) }
func (j *ja3) Firefox99() *builder        { return j.SetHelloID(utls.HelloFirefox_99) }
func (j *ja3) Firefox102() *builder       { return j.SetHelloID(utls.HelloFirefox_102) }
func (j *ja3) Firefox105() *builder       { return j.SetHelloID(utls.HelloFirefox_105) }
func (j *ja3) Firefox120() *builder       { return j.SetHelloID(utls.HelloFirefox_120) }
func (j *ja3) IOS() *builder              { return j.SetHelloID(utls.HelloIOS_Auto) }
func (j *ja3) IOS11() *builder            { return j.SetHelloID(utls.HelloIOS_11_1) }
func (j *ja3) IOS12() *builder            { return j.SetHelloID(utls.HelloIOS_12_1) }
func (j *ja3) IOS13() *builder            { return j.SetHelloID(utls.HelloIOS_13) }
func (j *ja3) IOS14() *builder            { return j.SetHelloID(utls.HelloIOS_14) }
func (j *ja3) Randomized() *builder       { return j.SetHelloID(utls.HelloRandomized) }
func (j *ja3) RandomizedALPN() *builder   { return j.SetHelloID(utls.HelloRandomizedALPN) }
func (j *ja3) RandomizedNoALPN() *builder { return j.SetHelloID(utls.HelloRandomizedNoALPN) }
func (j *ja3) Safari() *builder           { return j.SetHelloID(utls.HelloSafari_Auto) }
