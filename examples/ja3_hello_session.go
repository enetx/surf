package main

import (
	"fmt"

	"github.com/enetx/surf"
)

func main() {
	hello := "772,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,5-27-13-35-16-18-43-17513-65281-51-45-11-0-10-23-41,12092-29-23-24,0"

	cli := surf.NewClient().
		Builder().
		Session().
		JA3().SetHelloStr(hello).
		Build()

	url := "https://tls.peet.ws/api/clean"

	json := make(map[string]string)

	// First session request
	r := cli.Get(url).Do().Unwrap()
	r.Body.JSON(&json)
	fmt.Println(json["ja3"])

	// Second session request
	r = cli.Get(url).Do().Unwrap()
	r.Body.JSON(&json)
	fmt.Println(json["ja3"])

	// 771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,5-27-13-35-16-18-43-17513-65281-51-45-11-0-10-23,12092-29-23-24,0
	// 771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,5-27-13-35-16-18-43-17513-65281-51-45-11-0-10-23-41,12092-29-23-24,0
}
