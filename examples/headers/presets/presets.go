package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"

	"github.com/enetx/g"
	"github.com/enetx/surf"
	"github.com/enetx/surf/header"
)

func main() {
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(header.CONTENT_TYPE, "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"method":       r.Method,
			"mode":         r.Header.Get(header.SEC_FETCH_MODE),
			"accept":       r.Header.Get(header.ACCEPT),
			"content-type": r.Header.Get(header.CONTENT_TYPE),
		})
	}))
	defer peer.Close()

	client := surf.NewClient().Builder().Proxy("").Impersonate().Windows().Chrome().Build().Unwrap()
	defer client.Close()

	url := g.String(peer.URL)

	// GET/HEAD default to document navigation. Fetch selects its scenario without
	// forcing metadata onto insecure HTTP origins where browsers omit it.
	send(client.Get(url))
	send(client.Get(url).Fetch())

	// Other methods default to fetch. The same POST can be a form navigation.
	send(client.Post(url).Body("name=surf").SetHeaders(header.CONTENT_TYPE, "application/x-www-form-urlencoded"))
	send(client.Post(url).Navigation().Body("name=surf").
		SetHeaders(header.CONTENT_TYPE, "application/x-www-form-urlencoded"))

	// An explicit ordered map controls the wire prefix; unlisted fields follow
	// in alphabetical order. Empty values reserve positions without adding fields.
	// Host and Content-Length values are computed from the actual request.
	ordered := g.NewMapOrd[string, string]()
	ordered.Insert(header.HOST, "")
	ordered.Insert(header.CONTENT_LENGTH, "")
	ordered.Insert(header.CONTENT_TYPE, "application/json")
	ordered.Insert(header.USER_AGENT, "")
	ordered.Insert("x-example", "first")

	send(client.Post(url).Body(`{"name":"surf"}`).SetHeaders(ordered))
}

func send(request *surf.Request) {
	result := request.Do()
	if result.IsErr() {
		log.Fatal(result.Err())
	}

	response := result.Unwrap()
	defer response.Body.Close()

	fmt.Print(response.Body.String().Unwrap())
}
