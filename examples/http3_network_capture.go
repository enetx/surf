package main

import (
	"fmt"
	"net"
	"time"

	"github.com/enetx/surf"
)

func main() {
	fmt.Println("=== HTTP/3 Network Fingerprint Capture ===")
	fmt.Println()
	fmt.Println("1. Start Wireshark with filter: udp.port == 443")
	fmt.Println("2. Look for QUIC Initial packets")
	fmt.Println("3. Compare Connection ID lengths and Transport Parameters")
	fmt.Println()

	// Chrome fingerprint
	testWithCapture("Chrome", func() *surf.Client {
		return surf.NewClient().
			Builder().
			HTTP3Settings().
			Chrome().
			Set().
			Build()
	})

	time.Sleep(2 * time.Second)

	// Firefox fingerprint
	testWithCapture("Firefox", func() *surf.Client {
		return surf.NewClient().
			Builder().
			HTTP3Settings().
			Firefox().
			Set().
			Build()
	})
}

func testWithCapture(name string, clientFactory func() *surf.Client) {
	fmt.Printf("Testing %s fingerprint (packet capture ready):\n", name)

	client := clientFactory()
	defer client.CloseIdleConnections()

	if !client.IsHTTP3() {
		fmt.Printf("HTTP/3 not enabled\n")
		return
	}

	// Make request to trigger QUIC handshake
	fmt.Printf("Making request to trigger QUIC Initial packet...\n")

	start := time.Now()
	resp := client.Get("https://cloudflare.com/cdn-cgi/trace").Do()
	duration := time.Since(start)

	if resp.IsErr() {
		fmt.Printf("Request failed: %v\n", resp.Err())
		return
	}

	response := resp.Ok()
	fmt.Printf("Request completed in %v\n", duration)
	fmt.Printf("Status: %d, Proto: %s\n", response.StatusCode, response.Proto)

	// Get local address info for Wireshark filtering
	if localAddr := getLocalAddress(); localAddr != "" {
		fmt.Printf("Local address for Wireshark filter: %s\n", localAddr)
		fmt.Printf("Suggested filter: udp and (ip.src == %s or ip.dst == %s) and udp.port == 443\n",
			localAddr, localAddr)
	}

	fmt.Printf("🕒 Sleeping 3 seconds for packet capture...\n")
	time.Sleep(3 * time.Second)
	fmt.Println()
}

func getLocalAddress() string {
	// Get local IP for Wireshark filtering
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}
