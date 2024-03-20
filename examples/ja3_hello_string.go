package main

import (
	"fmt"

	"github.com/enetx/surf"
)

func main() {
	hello := "772,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,13-45-5-35-18-23-0-65281-10-65037-51-16-11-27-43-17513,12092-29-23-24,0"

	opt := surf.NewOptions().JA3().SetHelloStr(hello)

	r, err := surf.NewClient().SetOptions(opt).Get("https://tls.peet.ws/api/all").Do()
	if err != nil {
		fmt.Println(err)
		return
	}

	r.Body.String().Print()
}
