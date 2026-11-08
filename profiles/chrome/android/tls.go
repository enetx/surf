package android

import utls "github.com/refraction-networking/utls"

// NewClientHelloSpec creates an independent Chrome 156 android TLS template.
// The native Chrome 155 TLS fields match the current profile.
func NewClientHelloSpec() utls.ClientHelloSpec {
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_155)
	if err != nil {
		panic("chrome profile: " + err.Error())
	}
	// Keep optional session resumption support; fresh connections omit an empty PSK.
	spec.Extensions = append(spec.Extensions, &utls.UtlsPreSharedKeyExtension{})
	return spec
}
