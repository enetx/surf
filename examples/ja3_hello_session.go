package main

import (
	"fmt"

	"gitlab.com/x0xO/http"
	"gitlab.com/x0xO/surf"
)

func main() {
	URL := "http://httpbingo.org/cookies"

	opt := surf.NewOptions()

	opt.JA3().Chrome87()
	opt.Session()

	r, err := surf.NewClient().SetOptions(opt).Get(URL + "/set?name1=value1&name2=value2").Do()
	if err != nil {
		fmt.Println(err)
		return
	}

	r.Body.Close()

	r.SetCookies(URL, []*http.Cookie{{Name: "root", Value: "cookie"}})

	r, _ = r.Get(URL).Do()
	r.Body.String().Print()

	// check if cookies in response
	// {
	//   "name1": "value1",
	//   "name2": "value2",
	//   "root": "cookie"
	// }
}
