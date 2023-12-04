package main

import (
	"fmt"
	"log"

	"gitlab.com/x0xO/surf"
)

func main() {
	r, err := surf.NewClient().
		SetOptions(surf.NewOptions()).
		Get("https://http2.pro/api/v1").
		Do()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(r.Proto)

	r.Debug().Request().Response(true).Print()
}
