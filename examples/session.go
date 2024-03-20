package main

import (
	"fmt"

	"github.com/enetx/surf"
)

func main() {
	URL := "https://httpbingo.org/cookies"

	// need to enable session in options
	opt := surf.NewOptions().Session()

	// example 1
	// chains session
	r, _ := surf.NewClient().SetOptions(opt).Get(URL + "/set?name1=value1&name2=value2").Do()
	r.Body.Close()

	r, _ = r.Get(URL).Do()
	fmt.Println(r.Body.String()) // check if cookies in response {"name1":"value1","name2":"value2"}

	// example 2
	// split session
	cli := surf.NewClient().SetOptions(opt)

	s, _ := cli.Get(URL + "/set?name1=value1&name2=value2").Do()
	s.Body.Close()

	s, _ = cli.Get(URL).Do()
	fmt.Println(s.Body.String()) // check if cookies in response {"name1":"value1","name2":"value2"}
}
