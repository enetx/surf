package main

import (
	"github.com/enetx/g"
	"github.com/enetx/surf"
)

func main() {
	const URL = "https://httpbingo.org/anything"

	// Basic multipart with fields only
	mp := surf.NewMultipart().
		Field("name", "John").
		Field("email", "john@example.com")

	surf.NewClient().
		Post(URL).
		Multipart(mp).
		Do().
		Unwrap().
		Body.String().Unwrap().Println()

	// Multipart with physical file
	mp2 := surf.NewMultipart().
		Field("description", "My document").
		File("upload", g.NewFile("multipart.go"))

	surf.NewClient().
		Post(URL).
		Multipart(mp2).
		Do().
		Unwrap().
		Body.String().Unwrap().Println()

	// Multipart with file from string
	mp3 := surf.NewMultipart().
		Field("title", "Report").
		FileString("document", "report.txt", "Hello from surf!")

	surf.NewClient().
		Post(URL).
		Multipart(mp3).
		Do().
		Unwrap().
		Body.String().Unwrap().Println()

	// Multipart with file from bytes
	mp4 := surf.NewMultipart().
		FileBytes("data", "binary.dat", []byte{0x00, 0x01, 0x02})

	surf.NewClient().
		Post(URL).
		Multipart(mp4).
		Do().
		Unwrap().
		Body.String().Unwrap().Println()

	// Multipart with file from io.Reader
	mp5 := surf.NewMultipart().
		FileReader("log", "server.log", g.String("log content here").Reader())

	surf.NewClient().
		Post(URL).
		Multipart(mp5).
		Do()

	// Multipart with custom content-type and filename
	mp6 := surf.NewMultipart().
		Field("metadata", `{"type": "image"}`).
		FileString("image", "photo.dat", "raw image data").
		ContentType("image/png").
		FileName("photo.png")

	surf.NewClient().
		Post(URL).
		Multipart(mp6).
		Do().
		Unwrap().
		Body.String().Unwrap().Println()

	// Combined: multiple files with different sources
	mp7 := surf.NewMultipart().
		Field("user_id", "12345").
		FileString("config", "config.json", `{"debug": true}`).ContentType("application/json").
		FileBytes("avatar", "avatar.png", []byte{0x89, 0x50, 0x4E, 0x47}).ContentType("image/png").
		FileReader("readme", "README.md", g.String("# Title").Reader())

	surf.NewClient().
		Post(URL).
		Multipart(mp7).
		Do().
		Unwrap().
		Body.String().Unwrap().Println()
}
