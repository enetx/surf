package main

import (
	"fmt"
	"net"

	utls "github.com/enetx/utls"
)

func testServer(serverAddr, serverName string) {
	fmt.Printf("\n=== Testing %s ===\n", serverName)
	cache := utls.NewLRUClientSessionCache(32)

	for i := 1; i <= 3; i++ {
		conn, err := net.Dial("tcp", serverAddr)
		if err != nil {
			fmt.Printf("Connection %d failed: %v\n", i, err)
			continue
		}

		config := &utls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: true,
			ClientSessionCache: cache,
		}

		tlsConn := utls.UClient(conn, config, utls.HelloChrome_120)

		err = tlsConn.Handshake()
		if err != nil {
			fmt.Printf("Handshake %d failed: %v\n", i, err)
			tlsConn.Close()
			continue
		}

		state := tlsConn.ConnectionState()
		fmt.Printf("Connection %d - Version: 0x%04x, Resumed: %v\n",
			i, state.Version, state.DidResume)

		tlsConn.Write([]byte(fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", serverName)))

		buf := make([]byte, 256)
		n, _ := tlsConn.Read(buf)
		if n > 0 {
			fmt.Printf("Got response: %.50s...\n", string(buf[:n]))
		}

		tlsConn.Close()
	}
}

func main() {
	testServer("www.google.com:443", "www.google.com")
	testServer("www.cloudflare.com:443", "www.cloudflare.com")
	testServer("httpbin.org:443", "httpbin.org")
	testServer("tls.peet.ws:443", "tls.peet.ws")
}
