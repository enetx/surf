package main

import (
	"fmt"
	"log"

	"github.com/enetx/surf"
)

func main() {
	r := surf.NewClient().
		Builder().
		InterfaceAddr("127.0.0.1"). // network adapter ip address
		Build().
		Unwrap().
		Get("http://myip.dnsomatic.com").
		Do()

	if r.IsErr() {
		log.Fatal(r.Err())
	}

	fmt.Println(r.Ok().Body.String())
}
