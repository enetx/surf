package main

import (
	"fmt"

	"gitlab.com/x0xO/surf"
)

func main() {
	url := "playtoto.asia" // 101

	opt := surf.NewOptions().Impersonate().Chrome()

	cli := surf.NewClient().SetOptions(opt)

	r, err := cli.Get(url).Do()
	if err != nil {
		fmt.Println(err)
		return
	}

	r.Body.String().Print()
}
