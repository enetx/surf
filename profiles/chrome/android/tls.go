package android

import utls "github.com/enetx/utls"

// NewClientHelloSpec creates an independent Chrome 157 android TLS template.
// Official uTLS supplies these wire fields through its older constructor name.
// The current 157 captures freeze the result; no older Surf profile is exposed.
func NewClientHelloSpec() utls.ClientHelloSpec {
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_155)
	if err != nil {
		panic("chrome profile: " + err.Error())
	}

	// Keep optional session resumption support; fresh connections omit an empty PSK.
	spec.Extensions = append(spec.Extensions, &utls.UtlsPreSharedKeyExtension{})

	return spec
}
