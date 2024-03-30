package main

import (
	"fmt"

	"github.com/enetx/surf"
)

func main() {
	// url := "giayluoinam.edu.vn"
	// url := "g3net.website" // 101 stream error
	// url := "danielfdyer.xyz"
	// url := "louiejparkinson.xyz"
	url := "juliogroup.uk" // 101 proxy
	// url := "bompreco.cloud" // 101 websocket

	r := surf.NewClient().Get(url).Do()
	if r.IsErr() {
		fmt.Println(r.Err())
		return
	}

	r.Ok().Debug().Request(true).Response().Print()
}
