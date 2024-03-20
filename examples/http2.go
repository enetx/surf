package main

import (
	"fmt"
	"log"

	"github.com/enetx/surf"
)

func main() {
	r, err := surf.NewClient().
		// SetOptions(surf.NewOptions().ForceHTTP1()).
		Get("https://tls.peet.ws/api/all").
		Do()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(r.Proto)

	r.Debug().Request().Response(true).Print()
}
