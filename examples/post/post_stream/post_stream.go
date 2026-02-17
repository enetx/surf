package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/enetx/g"
	"github.com/enetx/surf"
)

func main() {
	const URL = "https://httpbingo.org/post"

	// 1. strings.Reader
	fmt.Println("=== strings.Reader ===")

	sr := strings.NewReader("hello from strings.Reader")
	r := surf.NewClient().Post(URL).Body(sr).Do().Unwrap()
	r.Body.String().Ok().Println()

	// 2. bytes.Reader
	fmt.Println("=== bytes.Reader ===")

	br := bytes.NewReader([]byte("hello from bytes.Reader"))
	r = surf.NewClient().Post(URL).Body(br).Do().Unwrap()
	r.Body.String().Ok().Println()

	// 3. bytes.Buffer
	fmt.Println("=== bytes.Buffer ===")

	buf := bytes.NewBufferString("hello from bytes.Buffer")
	r = surf.NewClient().Post(URL).Body(buf).Do().Unwrap()
	r.Body.String().Ok().Println()

	// 4. io.Pipe (streaming with unknown length, chunked transfer)
	fmt.Println("=== io.Pipe ===")

	pr, pw := io.Pipe()

	go func() {
		fmt.Fprint(pw, "hello from io.Pipe")
		pw.Close()
	}()

	r = surf.NewClient().Post(URL).Body(pr).Do().Unwrap()
	r.Body.String().Ok().Println()

	// 5. *os.File
	fmt.Println("=== *os.File ===")

	tmpfile, err := os.CreateTemp("", "surf-example-*")
	if err != nil {
		panic(err)
	}
	defer os.Remove(tmpfile.Name())

	tmpfile.WriteString("hello from *os.File")
	tmpfile.Seek(0, io.SeekStart)

	r = surf.NewClient().Post(URL).Body(tmpfile).Do().Unwrap()
	r.Body.String().Ok().Println()

	// 6. g.File (using Reader method)
	fmt.Println("=== g.File.Reader ===")

	gf := g.NewFile(g.String(tmpfile.Name()))
	gf.Write("hello from g.File.Reader")

	reader := gf.Reader().Unwrap()

	r = surf.NewClient().Post(URL).Body(reader).Do().Unwrap()
	r.Body.String().Ok().Println()

	// 7. io.NopCloser wrapping a reader
	fmt.Println("=== io.NopCloser ===")

	rc := io.NopCloser(strings.NewReader("hello from io.NopCloser"))
	r = surf.NewClient().Post(URL).Body(rc).Do().Unwrap()
	r.Body.String().Ok().Println()
}
