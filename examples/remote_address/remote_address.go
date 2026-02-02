package main

import (
	"fmt"

	"github.com/enetx/surf"
)

func main() {
	// to get remote server ip address
	cli := surf.NewClient().Builder().GetRemoteAddress().Build().Unwrap()

	r := cli.Get("http://ya.ru").Do()
	if r.IsErr() {
		fmt.Println(r.Err())
		return
	}

	fmt.Println(r.Ok().RemoteAddress())
}
