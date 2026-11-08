package main

import "github.com/enetx/surf"

func main() {
	const url = "https://tls.peet.ws/api/clean"

	cli := surf.NewClient().
		Builder().
		Session(). // Enables TLS session cache: 1st request = full handshake, 2nd = resumed with PSK (ext 41)
		Impersonate().
		// Firefox().
		Chrome().
		// // Disable TLS session.
		// With(func(cli *surf.Client) error {
		// 	cli.GetTLSConfig().ClientSessionCache = nil
		// 	return nil
		// }).
		Build().
		Unwrap()

	r := cli.Get(url).Do()
	r.Ok().Body.String().Unwrap().Println()

	r = cli.Get(url).Do()
	r.Ok().Body.String().Unwrap().Println()
}
