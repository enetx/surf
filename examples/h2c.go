package main

import (
	"fmt"
	"log"

	"github.com/enetx/http"
	"github.com/enetx/http2"
	"github.com/enetx/http2/h2c"
	"github.com/enetx/surf"
)

func main() {
	http2.VerboseLogs = true

	go H2CServerUpgrade()

	r := surf.NewClient().Builder().H2C().Build().Unwrap().Get("http://localhost:1010").Do()
	if r.IsErr() {
		log.Fatal(r.Err())
	}

	fmt.Println()
	r.Ok().Debug().Request(true).Response(true).Print()
}

func H2CServerUpgrade() {
	h2s := &http2.Server{}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello %s http == %v", r.Proto, r.TLS == nil)
	})

	server := &http.Server{
		Addr:    "0.0.0.0:1010",
		Handler: h2c.NewHandler(handler, h2s),
	}

	server.ListenAndServe()
}
