package main

import (
	"fmt"

	"gitlab.com/x0xO/http"
	"gitlab.com/x0xO/surf"
)

func main() {
	URL := "https://httpbingo.org/cookies"

	opt := surf.NewOptions().Session()
	opt.JA3().Chrome87()

	cli := surf.NewClient().SetOptions(opt)

	r, err := cli.Get(URL + "/set?name1=value1&name2=value2").Do()
	if err != nil {
		fmt.Println(err)
		return
	}

	r.Body.Close()

	r.SetCookies(URL, []*http.Cookie{{Name: "root", Value: "cookie"}})

	r, _ = cli.Get(URL).Do()
	r.Body.String().Print()

	// check if cookies in response
	// {
	//   "name1": "value1",
	//   "name2": "value2",
	//   "root": "cookie"
	// }
}
