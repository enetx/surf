package main

import (
	"log"

	"gitlab.com/x0xO/surf"
)

func main() {
	r, err := surf.NewClient().
		SetOptions(surf.NewOptions().DisableKeepAlive()).
		Get("http://www.keycdn.com").
		Do()
	if err != nil {
		log.Fatal(err)
	}

	r.Debug().Response().Print() // Connection: close
}
