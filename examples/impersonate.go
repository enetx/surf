package main

import (
	"log"

	"gitlab.com/x0xO/surf"
)

func main() {
	url := "https://tls.peet.ws/api/all"
	// url := "https://www.google.com"

	opt := surf.NewOptions()

	// "ja3_hash": random
	// "ja4": "t13d1516h2_8daaf6152771_5fb3489db586",
	// "akamai_fingerprint_hash": "46cedabdca2073198a42fa10ca4494d0"
	// opt.Impersonate().Chrome()

	// "ja3_hash": "579ccef312d18482fc42e2b822ca2430"
	// "ja4": "t13d1715h1_5b57614c22b0_5a7a167d0339",
	// "akamai_fingerprint_hash": "fd4f649c50a64e33cc9e2407055bafbe"
	opt.Impersonate().FireFox()

	// opt.Proxy("socks5://localhost:9050")

	r, err := surf.NewClient().SetOptions(opt).Get(url).
		Do()
	if err != nil {
		log.Fatal(err)
	}

	r.Body.String().Print()
}
