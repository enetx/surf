package main

import (
	"fmt"

	"github.com/enetx/surf"
)

func main() {
	const socket = "/var/run/docker.sock"

	r := surf.NewClient().
		Builder().
		UnixDomainSocket(socket).
		Build().
		Get("http://localhost/v1.41/containers/json").
		Do()

	fmt.Println(r.Unwrap().Body.String())
}
