package main

import (
	"fmt"
	"log"

	"gitlab.com/x0xO/surf"
)

func main() {
	opt := surf.NewOptions()

	// opt.DNS("127.0.0.1:53") // local dns
	opt.DNS("1.1.1.1:53") // cloudflare dns
	// opt.DNS("127.0.0.1:9053") // tor dns
	// opt.DNS("8.8.8.8:53") // google dns
	// opt.DNS("9.9.9.9:53") // quad9 dns

	r, err := surf.NewClient().SetOptions(opt).Get("http://httpbingo.org/get").Do()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(r.Body.String())
}
