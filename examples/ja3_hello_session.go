package main

import (
	"fmt"

	"gitlab.com/x0xO/surf"
)

func main() {
	opt := surf.NewOptions().Session()
	// opt.Proxy("socks5://localhost:9050")

	hello := "772,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,5-27-13-35-16-18-43-17513-65281-51-45-11-0-10-23-41,12092-29-23-24,0"
	opt.JA3().SetHelloStr(hello)

	// opt.Impersonate().Chrome()
	// opt.Impersonate().FireFox()

	cli := surf.NewClient().SetOptions(opt)

	url := "https://tls.peet.ws/api/clean"

	json := make(map[string]string)

	// First session request
	r, _ := cli.Get(url).Do()
	r.Body.JSON(&json)
	fmt.Println(json["ja3"])

	// Second session request
	r, _ = cli.Get(url).Do()
	r.Body.JSON(&json)
	fmt.Println(json["ja3"])
}
