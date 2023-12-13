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
	url := "playtoto.asia" // 101 websocket
	// url := "bompreco.cloud" // 101 websocket

	opt := surf.NewOptions()
	opt.Impersonate().Chrome()

	cli := surf.NewClient()

	r, err := cli.SetOptions(opt).Get(url).Do()
	if err != nil {
		fmt.Println(err)
		return
	}

	r.Debug().Request(true).Response().Print()
}
