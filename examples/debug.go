package main

import (
	"fmt"
	"log"

	"github.com/enetx/http"
	"github.com/enetx/surf"
)

func main() {
	url := "http://testasp.vulnweb.com/Login.asp"
	body := "tfUName=user&tfUPass=pass"

	req := surf.NewClient().Post(url, body).AddCookies(&http.Cookie{Name: "test", Value: "rest"})

	r := req.Do()
	if r.IsErr() {
		log.Fatal(r.Err())
	}

	d := r.Ok().Debug()

	d.Request(true) // true for verbose output with request body if set
	d.Response()    // true for verbose output with response body

	d.Print()

	fmt.Println(r.Ok().Time)
}
