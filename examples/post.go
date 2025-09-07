package main

import (
	"fmt"

	"github.com/enetx/g"
	"github.com/enetx/surf"
)

func main() {
	type Post struct {
		Form struct {
			Custemail []string `json:"custemail"`
			Custname  []string `json:"custname"`
			Custtel   []string `json:"custtel"`
		} `json:"form"`
	}

	const URL = "https://httpbingo.org/post"

	// string post data
	// note: don't forget to URL encode your query params if you use string post data!
	// g.String("Hellö Wörld@Golang").Enc().URL()
	// or
	// url.QueryEscape("Hellö Wörld@Golang")
	data := "custname=root&custtel=999999999&custemail=some@email.com"

	r := surf.NewClient().Post(URL, data).Do().Unwrap()

	var post Post

	r.Body.JSON(&post)

	fmt.Println(post.Form.Custname)
	fmt.Println(post.Form.Custtel)
	fmt.Println(post.Form.Custemail)

	// map post data
	// mapData := map[string]string{
	// 	"custname":  "toor",
	// 	"custtel":   "88888888",
	// 	"custemail": "rest@gmail.com",
	// }

	mapData := g.NewMapOrd[string, string]()
	mapData.Set("custname", "toor")
	mapData.Set("custtel", "88888888")
	mapData.Set("custemail", "rest@gmail.com")

	r = surf.NewClient().Post(URL, mapData).Do().Unwrap()

	r.Debug().Request(true).Response().Print()

	r.Body.JSON(&post)

	fmt.Println(post.Form.Custname)
	fmt.Println(post.Form.Custtel)
	fmt.Println(post.Form.Custemail)
}
