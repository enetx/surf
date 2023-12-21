package main

import (
	"fmt"

	"gitlab.com/x0xO/surf"
)

func main() {
	// giayluoinam.edu.vn
	// g3net.website
	// danielfdyer.xyz
	// louiejparkinson.xyz
	// juliogroup.uk

	// url := "juliogroup.uk" // 101 stream error
	url := "bompreco.cloud" // 101 websocket

	opt := surf.NewOptions()

	r, err := surf.NewClient().SetOptions(opt).Get(url).Do()
	if err != nil {
		fmt.Println(err)
		return
	}

	r.Debug().Request(true).Response().Print()
}
