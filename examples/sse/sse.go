package main

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/enetx/surf"
	"github.com/enetx/surf/pkg/sse"
)

func main() {
	type SSE struct {
		ID        int   `json:"id"`
		Timestamp int64 `json:"timestamp"`
	}

	r := surf.NewClient().Get("https://httpbingo.org/sse?delay=1s&duration=5s&count=10").Do()

	switch {
	case r.IsOk():
		r.Ok().Body.SSE(func(event *sse.Event) bool {
			if event.Skip() {
				return true
			}

			if event.Done() {
				return false
			}

			var s SSE
			json.Unmarshal(event.Data.Bytes(), &s)

			fmt.Println(s.ID, s.Timestamp)

			return true
		})
	case r.IsErr():
		log.Fatal(r.Err())
	}
}
