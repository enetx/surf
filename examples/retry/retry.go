package main

import (
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/enetx/surf"
)

func main() {
	// Example 1: Simple GET retry
	fmt.Println("=== Example 1: GET retry ===")
	simpleGetRetry()

	// Example 2: POST retry with body preservation
	fmt.Println("\n=== Example 2: POST retry with body ===")
	postRetryWithBody()

	// Example 3: Multipart retry with body preservation
	fmt.Println("\n=== Example 3: Multipart retry ===")
	multipartRetry()
}

func simpleGetRetry() {
	cli := surf.NewClient().Builder().
		Retry(3, 100*time.Millisecond, 500, 503).
		Build().
		Unwrap()

	r := cli.Get("http://httpbingo.org/unstable").Do()
	if r.IsErr() {
		fmt.Println("Error:", r.Err())
		return
	}

	fmt.Println("StatusCode:", r.Ok().StatusCode, "Attempts:", r.Ok().Attempts)
}

func postRetryWithBody() {
	// Start local test server that fails first 2 requests
	var attempts atomic.Int32

	server := http.Server{Addr: ":18080", Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt := attempts.Add(1)

		body, _ := io.ReadAll(r.Body)
		fmt.Printf("  Server received attempt %d, body: %q\n", attempt, string(body))

		if attempt <= 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	})}

	go server.ListenAndServe()
	defer server.Close()

	time.Sleep(100 * time.Millisecond) // Wait for server to start

	cli := surf.NewClient().Builder().
		Retry(3, 50*time.Millisecond, 503).
		Build().
		Unwrap()

	postData := "important_data=value123"

	r := cli.Post("http://localhost:18080/test").Body(postData).Do()
	if r.IsErr() {
		fmt.Println("Error:", r.Err())
		return
	}

	fmt.Printf("Final StatusCode: %d, Total Attempts: %d\n", r.Ok().StatusCode, r.Ok().Attempts+1)
	fmt.Println("Response:", r.Ok().Body.String().UnwrapOrDefault())
}

func multipartRetry() {
	// Start local test server that fails first request
	var attempts atomic.Int32

	server := http.Server{Addr: ":18081", Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt := attempts.Add(1)

		r.ParseMultipartForm(10 << 20)
		field := r.FormValue("username")
		file, header, _ := r.FormFile("document")

		var fileContent string
		if file != nil {
			data, _ := io.ReadAll(file)
			fileContent = string(data)
			file.Close()
		}

		fmt.Printf("  Server received attempt %d:\n", attempt)
		fmt.Printf("    Field 'username': %q\n", field)
		if header != nil {
			fmt.Printf("    File '%s': %q\n", header.Filename, fileContent)
		}

		if attempt <= 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("upload complete"))
	})}

	go server.ListenAndServe()
	defer server.Close()

	time.Sleep(100 * time.Millisecond) // Wait for server to start

	cli := surf.NewClient().Builder().
		Retry(2, 50*time.Millisecond, 500).
		Build().
		Unwrap()

	mp := surf.NewMultipart().
		Field("username", "john_doe").
		FileString("document", "report.txt", "This is the file content for upload").
		Retry()

	r := cli.Post("http://localhost:18081/upload").Multipart(mp).Do()
	if r.IsErr() {
		fmt.Println("Error:", r.Err())
		return
	}

	fmt.Printf("Final StatusCode: %d, Total Attempts: %d\n", r.Ok().StatusCode, r.Ok().Attempts+1)
	fmt.Println("Response:", r.Ok().Body.String().UnwrapOrDefault())
}
