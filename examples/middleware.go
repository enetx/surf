package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/url"

	"github.com/enetx/http/cookiejar"
	"github.com/enetx/surf"
)

func main() {
	const url = "https://yahoo.com"

	cli := surf.NewClient().
		Builder().
		With(jar).
		With(dns).
		With(baseURL).
		With(ua2, 2). // Apply `ua2` middleware with priority 2 (executes after `ua`)
		With(ua).     // Apply `ua` middleware with priority 0 (executes before `ua2`)
		Build()

	r := cli.Get(url).Do()
	if r.IsErr() {
		log.Fatal(r.Err())
	}

	defer r.Ok().Body.Close()

	fmt.Println(r.Ok().URL)
	fmt.Println(r.Ok().UserAgent)
}

func dns(client *surf.Client) error {
	client.GetDialer().Resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "udp", "1.1.1.1:53")
		},
	}

	return nil
}

func jar(client *surf.Client) error {
	client.GetClient().Jar, _ = cookiejar.New(nil)
	return nil
}

func baseURL(req *surf.Request) error {
	u, _ := url.Parse("http://google.com")
	req.GetRequest().URL = u

	return nil
}

func ua(req *surf.Request) error {
	req.SetHeaders(map[string]string{"User-Agent": "11111111111"})
	return nil
}

func ua2(req *surf.Request) error {
	req.SetHeaders(map[string]string{"User-Agent": "222222222222"})
	return nil
}
