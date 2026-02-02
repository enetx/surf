package main

import (
	"fmt"

	"github.com/enetx/surf"
)

func main() {
	r := surf.NewClient().Get("https://google.com").Do().Unwrap()

	fmt.Println(r.TLSGrabber().CommonName)
	fmt.Println(r.TLSGrabber().DNSNames)
	fmt.Println(r.TLSGrabber().Emails)
	fmt.Println(r.TLSGrabber().ExtensionServerName)
	fmt.Println(r.TLSGrabber().FingerprintSHA256)
	fmt.Println(r.TLSGrabber().FingerprintSHA256OpenSSL)
	fmt.Println(r.TLSGrabber().IssuerCommonName)
	fmt.Println(r.TLSGrabber().IssuerOrg)
	fmt.Println(r.TLSGrabber().Organization)
	fmt.Println(r.TLSGrabber().TLSVersion)
}
