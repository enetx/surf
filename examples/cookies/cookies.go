package main

import (
	"fmt"

	"github.com/enetx/http"
	"github.com/enetx/surf"
)

func main() {
	const URL = "http://httpbingo.org/cookies"

	// cookie before request
	c1 := &http.Cookie{Name: "root1", Value: "cookie1"}
	c2 := &http.Cookie{Name: "root2", Value: "cookie2"}

	r := surf.NewClient().
		Builder().
		Session().
		AddCookies(c1, c2).
		Build().
		Unwrap().
		Get(URL).
		Do()

	r.Ok().Debug().Request().Response(true).Print()

	// set cookie after first request
	r.Ok().SetCookies(URL, []*http.Cookie{{Name: "root", Value: "cookie"}})

	r = r.Ok().Get(URL).Do()
	r.Ok().Debug().Request().Response(true).Print()

	fmt.Println(r.Ok().GetCookies(URL)) // request url cookies
	fmt.Println(r.Ok().Cookies)
}
