package main

import (
	"fmt"
	"log"

	"gitlab.com/x0xO/surf"
)

func main() {
	opt := surf.NewOptions().UnixDomainSocket("/tmp/surf_echo.sock")

	r, err := surf.NewClient().SetOptions(opt).Get("unix").Do()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(r.Body.String())
}
