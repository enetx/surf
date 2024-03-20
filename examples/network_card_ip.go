package main

import (
	"fmt"
	"log"

	"github.com/enetx/surf"
)

func main() {
	opt := surf.NewOptions()
	opt.InterfaceAddr("127.0.0.1") // network adapter ip address

	r, err := surf.NewClient().SetOptions(opt).Get("http://myip.dnsomatic.com").Do()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(r.Body.String())
}
