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
	url := "https://yahoo.com"

	cli := surf.NewClient().
		Builder().
		With(jar).
		With(dns).
		With(baseURL).
		With(ua).
		Build()

	r := cli.Get(url).Do()
	if r.IsErr() {
		log.Fatal(r.Err())
	}

	defer r.Ok().Body.Close()

	fmt.Println(r.Ok().URL)
	fmt.Println(r.Ok().UserAgent)
}

func dns(client *surf.Client) {
	client.GetDialer().Resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "udp", "1.1.1.1:53")
		},
	}
}

func jar(client *surf.Client) { client.GetClient().Jar, _ = cookiejar.New(nil) }

func baseURL(req *surf.Request) error {
	u, _ := url.Parse("http://google.com")
	req.GetRequest().URL = u

	return nil
}

func ua(req *surf.Request) error {
	req.SetHeaders(map[string]string{"User-Agent": "some custom ua"})
	return nil
}
