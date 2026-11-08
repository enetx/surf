package main

import (
	"fmt"
	"log"

	"github.com/enetx/surf"
)

func main() {
	profile := surf.NewClient().Builder().Impersonate()
	profile.MacOS()
	// profile.Windows()
	// profile.Linux()
	// profile.Android()
	// profile.IOS()

	var builder *surf.Builder
	builder = profile.Firefox()
	// builder = profile.Chrome()

	client := builder.ForceHTTP3().Build().Unwrap()
	defer client.Close()

	result := client.Get("https://fp.impersonate.pro/api/http3").Do()
	if result.IsErr() {
		log.Fatal(result.Err())
	}

	response := result.Ok()
	if response.GetResponse().ProtoMajor != 3 {
		log.Fatalf("endpoint used %s; HTTP/3 is required by this example", response.Proto)
	}

	body := response.Body.String()
	if body.IsErr() {
		log.Fatal(body.Err())
	}

	fmt.Printf("Protocol: %s\n%s\n", response.Proto, body.Ok())
}
