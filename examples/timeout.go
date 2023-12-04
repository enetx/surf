package main

import (
	"fmt"
	"log"
	"time"

	"gitlab.com/x0xO/surf"
)

func main() {
	r, err := surf.NewClient().
		SetOptions(surf.NewOptions().Timeout(time.Second)).
		Get("httpbingo.org/delay/2").
		Do()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(r.StatusCode)
}
