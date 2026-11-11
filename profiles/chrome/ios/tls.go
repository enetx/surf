package ios

import utls "github.com/enetx/utls"

// HelloID selects WebKit TLS with fixed extension order for Chrome on iOS.
var HelloID = utls.HelloSafari_26_3

// NewClientHelloSpec keeps the captured WebKit handshake and fixed extension
// order. The verified iOS captures do not offer PSK session resumption.
func NewClientHelloSpec() utls.ClientHelloSpec {
	spec, err := utls.UTLSIdToSpec(HelloID)
	if err != nil {
		panic("chrome iOS profile: " + err.Error())
	}

	return spec
}
