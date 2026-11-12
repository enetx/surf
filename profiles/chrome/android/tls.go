package android

import utls "github.com/enetx/utls"

// NewClientHelloSpec creates an independent Chrome 158 Android TLS template.
// It shares Chromium 158's TLS fields; a native Android capture remains pending.
// https://github.com/google/boringssl/blob/ea9f3a34c3977144c45d272be81842fd891a0bdb/ssl/extensions.cc
func NewClientHelloSpec() utls.ClientHelloSpec {
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_155)
	if err != nil {
		panic("chrome profile: " + err.Error())
	}

	// Keep optional session resumption support; fresh connections omit an empty PSK.
	spec.Extensions = append(spec.Extensions,
		&utls.GenericExtension{Id: 0x12e0, Data: []byte{0, 0}},
		&utls.UtlsPreSharedKeyExtension{},
	)

	return spec
}
