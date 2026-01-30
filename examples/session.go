package main

import (
	"fmt"

	"github.com/enetx/surf"
)

func main() {
	const url = "https://httpbingo.org/cookies"

	// example 1
	// chains session
	r := surf.NewClient().Builder().Session().Build().Unwrap().Get(url + "/set?name1=value1&name2=value2").Do().Unwrap()
	r.Body.Close()

	r = r.Get(url).Do().Unwrap()
	fmt.Println(r.Body.String().Unwrap()) // check if cookies in response {"name1":"value1","name2":"value2"}

	// example 2
	// split session
	cli := surf.NewClient().Builder().Session().Build().Unwrap()

	s := cli.Get(url + "/set?name1=value1&name2=value2").Do().Unwrap()
	s.Body.Close()

	s = cli.Get(url).Do().Unwrap()
	fmt.Println(s.Body.String().Unwrap()) // check if cookies in response {"name1":"value1","name2":"value2"}
}
