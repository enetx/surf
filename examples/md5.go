package main

import (
	"fmt"
	"log"

	"gitlab.com/x0xO/surf"
)

func main() {
	r, err := surf.NewClient().Get("http://google.com").Do()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(r.Body.MD5())
}
