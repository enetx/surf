package main

import (
	"fmt"

	"gitlab.com/x0xO/surf"
)

func main() {
	hello := "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0"
	opt := surf.NewOptions().JA3().SetHelloStr(hello)

	r, err := surf.NewClient().SetOptions(opt).Get("https://tls.peet.ws/api/all").Do()
	if err != nil {
		fmt.Println(err)
		return
	}

	r.Body.String().Print()
}
