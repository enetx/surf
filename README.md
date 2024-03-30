<p align="center">
  <img src="https://user-images.githubusercontent.com/65846651/233453773-33f38b64-0adc-41b4-8e13-a49c89bf9db6.png">
</p>

# 🤖👋 Surf: makes HTTP fun and easy!
[![Go Reference](https://pkg.go.dev/badge/github.com/enetx/surf.svg)](https://pkg.go.dev/github.com/enetx/surf)
[![Go Report Card](https://goreportcard.com/badge/github.com/enetx/surf)](https://goreportcard.com/report/github.com/enetx/surf)
[![Go](https://github.com/enetx/surf/actions/workflows/go.yml/badge.svg)](https://github.com/enetx/surf/actions/workflows/go.yml)

Surf is a fun, user-friendly, and lightweight Go library that allows you to interact with HTTP services as if you were chatting with them face-to-face! 😄
Imagine if you could make HTTP requests by simply asking a server politely, and receiving responses as if you were having a delightful conversation with a friend. That's the essence of surf!

## 🌟 Features
1. 💬 **Simple and Expressive:** Surf's API is designed to make your code look like a conversation, making it easier to read and understand.
2. 💾 **Caching and Streaming:** Efficiently cache response bodies and stream data on the fly, like a superhero saving the world from slow internet connections.
3. 📉 **Limit and Deflate:** Limit the amount of data you receive and decompress it on the fly, giving you more control over your HTTP interactions.
4. 🎩 **Flexible:** Customize headers, query parameters, timeouts, and more for a truly tailor-made experience.
5. 🔍 **Browser Impersonation:** Mimic various browsers such as Chrome, Firefox, and others, with a wide range of possible fingerprints for enhanced privacy and compatibility.

## 💻 Example
Here's a fun and friendly example of how surf makes HTTP requests look like a conversation:
```Go
package main

import (
	"fmt"
	"log"

	"github.com/enetx/surf"
)

func main() {
	resp := surf.NewClient().Get("https://api.example.com/jokes/random").Do() // A simple GET request
	if r.IsErr() { log.Fatal(r.Err()) }

	joke := struct {
		ID     int    `json:"id"`
		Setup  string `json:"setup"`
		Punch  string `json:"punch"`
	}{}

	resp.Ok().Body.JSON(&joke)

	fmt.Println("Joke of the day:")
	fmt.Printf("%s\n%s\n", joke.Setup, joke.Punch)
}
```

## 🚀 Getting Started
To start making friends with HTTP services, follow these simple steps:
1. Install the surf package using **go get:**
```bash
go get -u github.com/enetx/surf
```
2. Import the package into your project:
```Go
import "github.com/enetx/surf"
```
3. Start making requests and have fun! 😄

Give surf a try, and watch your HTTP conversations come to life!

## Requires GOEXPERIMENT=rangefunc.
