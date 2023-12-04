package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/url"

	"gitlab.com/x0xO/http/cookiejar"
	"gitlab.com/x0xO/surf"
)

func main() {
	URL := "https://yahoo.com"

	cli := surf.NewClient().
		ClientMiddleware(jar).
		ClientMiddleware(dns).
		RequestMiddleware(baseURL).
		RequestMiddleware(ua)

	r, err := cli.Get(URL).Do()
	if err != nil {
		log.Fatal(err)
	}

	defer r.Body.Close()

	fmt.Println(r.URL)
	fmt.Println(r.UserAgent)
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
