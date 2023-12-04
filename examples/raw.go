package main

import (
	"log"

	"gitlab.com/x0xO/surf"
)

func main() {
	raw := `GET /images HTTP/1.1
Host: google.com
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/119.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Connection: close`

	r, err := surf.NewClient().Raw(raw, "http").Do()
	if err != nil {
		log.Fatal(err)
	}

	r.Body.String().Print()
}
