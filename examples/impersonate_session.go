package main

import "github.com/enetx/surf"

func main() {
	const url = "https://tls.peet.ws/api/clean"

	cli := surf.NewClient().
		Builder().
		Singleton().
		Session(). // Enables TLS session cache: 1st request = full handshake, 2nd = resumed with PSK (ext 41)
		Impersonate().
		Chrome().
		DisableHTTP3().
		// FireFox().
		// // Disable TLS session.
		// With(func(cli *surf.Client) error {
		// 	cli.GetTLSConfig().ClientSessionCache = nil
		// 	return nil
		// }).
		Build()

	defer cli.CloseIdleConnections()

	r := cli.Get(url).Do()
	r.Ok().Body.String().Println()

	// "GREASE-772-771|2-1.1|GREASE-4588-29-23-24|1027-2052-1025-1283-2053-1281-2054-1537|1|2|GREASE-4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53|0-10-11-13-16-17613-18-23-27-35-43-45-5-51-65037-65281-GREASE-GREASE",
	// "peetprint_hash": "1d4ffe9b0e34acac0bd883fa7f79d7b5"
	// No extension 41 (pre_shared_key) — this is a full initial handshake

	r = cli.Get(url).Do()
	r.Ok().Body.String().Println()

	// "GREASE-772-771|2-1.1|GREASE-4588-29-23-24|1027-2052-1025-1283-2053-1281-2054-1537|1|2|GREASE-4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53|0-10-11-13-16-17613-18-23-27-35-41-43-45-5-51-65037-65281-GREASE-GREASE",
	// "peetprint_hash": "d44d68f0fce54cd423d6792272a242b8"
	// Includes extension 41 (pre_shared_key) — resumed from saved session
}
