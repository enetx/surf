package main

import (
	"fmt"

	"gitlab.com/x0xO/g"
	"gitlab.com/x0xO/surf"
)

func main() {
	type Post struct {
		Form struct {
			Custemail []string `json:"custemail"`
			Custname  []string `json:"custname"`
			Custtel   []string `json:"custtel"`
		} `json:"form"`
	}

	url := "https://httpbingo.org/post"

	// string post data
	// note: don't forget to URL encode your query params if you use string post data!
	// g.String("Hellö Wörld@Golang").Enc().URL()
	// or
	// url.QueryEscape("Hellö Wörld@Golang")
	data := "custname=root&custtel=999999999&custemail=some@email.com"

	r, _ := surf.NewClient().Post(url, data).Do()

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

	mapData := g.NewMap[string, string]().
		Set("custname", "toor").
		Set("custtel", "88888888").
		Set("custemail", "rest@gmail.com")

	r, _ = surf.NewClient().Post(url, mapData).Do()

	r.Body.JSON(&post)

	fmt.Println(post.Form.Custname)
	fmt.Println(post.Form.Custtel)
	fmt.Println(post.Form.Custemail)
}
