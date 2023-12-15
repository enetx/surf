package main

import (
	"fmt"
	"log"

	"gitlab.com/x0xO/http"
	"gitlab.com/x0xO/http2"
	"gitlab.com/x0xO/http2/h2c"
	"gitlab.com/x0xO/surf"
)

func main() {
	go H2CServerUpgrade()

	opt := surf.NewOptions().H2C()

	r, err := surf.NewClient().SetOptions(opt).Get("http://localhost:1010").Do()
	if err != nil {
		log.Fatal(err)
	}

	r.Body.String().Print()
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
