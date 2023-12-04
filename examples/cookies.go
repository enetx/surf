package main

import (
	"fmt"

	"gitlab.com/x0xO/http"
	"gitlab.com/x0xO/surf"
)

func main() {
	URL := "http://httpbingo.org/cookies"

	// cookie before request
	c1 := &http.Cookie{Name: "root1", Value: "cookie1"}
	c2 := &http.Cookie{Name: "root2", Value: "cookie2"}

	r, _ := surf.NewClient().
		SetOptions(surf.NewOptions().Session()).
		Get(URL).
		AddCookies(c1, c2).
		Do()

	r.Debug().Request().Response(true).Print()

	// set cookie after first request
	r.SetCookies(URL, []*http.Cookie{{Name: "root", Value: "cookie"}})

	r, _ = r.Get(URL).Do()
	r.Debug().Request().Response(true).Print()

	fmt.Println(r.GetCookies(URL)) // request url cookies
	fmt.Println(r.Cookies)
}
