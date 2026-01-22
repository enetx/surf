package main

import (
	"fmt"
	"io"
	"log"
	"time"

	"github.com/enetx/surf"
)

func main() {
	r := surf.NewClient().Get("https://httpbingo.org/stream/10").Do()
	if r.IsErr() {
		log.Fatal(r.Err())
	}

	// IMPORTANT: Call Stream() once and reuse the returned reader.
	// Each call to Stream() creates a new bufio.Reader with its own buffer.
	// Calling Stream() repeatedly in a loop will lose buffered data.
	stream := r.Ok().Body.Stream()

	for {
		line, err := stream.ReadString('\n')
		if err == io.EOF {
			break
		}

		if err != nil {
			fmt.Println(err)
		}

		log.Println(line)
		time.Sleep(time.Second * 1)
	}

	// var bytesRead int
	// buffer := make([]byte, 4096)
	// stream := r.Ok().Body.Stream()
	//
	// for {
	// 	n, err := stream.Read(buffer)
	// 	bytesRead += n
	//
	// 	if err == io.EOF {
	// 		break
	// 	}
	//
	// 	if err != nil {
	// 		log.Fatal(err)
	// 	}
	//
	// 	log.Println(string(buffer[:n]))
	// 	time.Sleep(time.Second * 1)
	// }
}
