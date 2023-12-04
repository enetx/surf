package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"gitlab.com/x0xO/http/httptrace"
	"gitlab.com/x0xO/surf"
)

func init() {
	os.Setenv("GODEBUG", "http2debug=1")
}

func main() {
	traceCtx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{
		GetConn: func(hostPort string) {
			fmt.Printf("Prepare to get a connection for %s.\n", hostPort)
		},
		GotConn: func(info httptrace.GotConnInfo) {
			fmt.Printf("Got a connection: reused: %v, from the idle pool: %v.\n",
				info.Reused, info.WasIdle)
		},
		PutIdleConn: func(err error) {
			if err == nil {
				fmt.Println("Put a connection to the idle pool: ok.")
			} else {
				fmt.Println("Put a connection to the idle pool:", err.Error())
			}
		},
		ConnectStart: func(network, addr string) {
			fmt.Printf("Dialing... (%s:%s).\n", network, addr)
		},
		ConnectDone: func(network, addr string, err error) {
			if err == nil {
				fmt.Printf("Dial is done. (%s:%s)\n", network, addr)
			} else {
				fmt.Printf("Dial is done with error: %s. (%s:%s)\n", err, network, addr)
			}
		},
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			if info.Err == nil {
				fmt.Println("Wrote a request: ok.")
			} else {
				fmt.Println("Wrote a request:", info.Err.Error())
			}
		},
		GotFirstResponseByte: func() {
			fmt.Println("Got the first response byte.")
		},
	})

	r, err := surf.NewClient().Get("https://google.com").WithContext(traceCtx).Do()
	if err != nil {
		log.Fatal(err)
	}

	r.Debug().Request().Response().Print()
}
