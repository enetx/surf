package main

import (
	"fmt"
	"log"

	"github.com/enetx/surf"
)

func main() {
	r := surf.NewClient().
		Builder().
		UnixDomainSocket("/tmp/surf_echo.sock").
		Build().
		Get("unix").
		Do()

	if r.IsErr() {
		log.Fatal(r.Err())
	}

	fmt.Println(r.Ok().Body.String())
}
