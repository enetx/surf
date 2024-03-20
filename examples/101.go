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

	opt := surf.NewOptions()

	r, err := surf.NewClient().SetOptions(opt).Get(url).Do()
	if err != nil {
		fmt.Println(err)
		return
	}

	r.Debug().Request(true).Response().Print()
}
