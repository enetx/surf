package main

import (
	"github.com/enetx/g"
	"github.com/enetx/surf"
)

func main() {
	const URL = "https://httpbingo.org/anything"

	// With physical file
	mp := surf.NewMultipart().
		File("filefield", g.NewFile("/path/to/file.txt"))

	surf.NewClient().
		Post(URL).
		Multipart(mp).
		Do()

	// Without physical file (from string)
	mp2 := surf.NewMultipart().
		FileString("filefield", "info.txt", "Hello from surf!")

	surf.NewClient().
		Post(URL).
		Multipart(mp2).
		Do().Unwrap().Body.String().Unwrap().Print()

	// With form fields and file
	mp3 := surf.NewMultipart().
		Field("_wpcf7", "36484").
		Field("_wpcf7_version", "5.4").
		Field("_wpcf7_locale", "ru_RU").
		Field("_wpcf7_unit_tag", "wpcf7-f36484-o1").
		Field("_wpcf7_container_post", "0").
		Field("_wpcf7_posted_data_hash", "").
		Field("your-name", "name").
		Field("retreat", "P48").
		Field("your-message", "message").
		File("filefield", g.NewFile("/path/to/file.txt"))

	surf.NewClient().
		Post(URL).
		Multipart(mp3).
		Do()

	// With form fields and file from string
	mp4 := surf.NewMultipart().
		Field("_wpcf7", "36484").
		Field("_wpcf7_version", "5.4").
		Field("_wpcf7_locale", "ru_RU").
		Field("_wpcf7_unit_tag", "wpcf7-f36484-o1").
		Field("_wpcf7_container_post", "0").
		Field("_wpcf7_posted_data_hash", "").
		Field("your-name", "name").
		Field("retreat", "P48").
		Field("your-message", "message").
		FileString("filefield", "info.txt", "Hello from surf again!")

	r := surf.NewClient().
		Post(URL).
		Multipart(mp4).
		Do().
		Unwrap()

	r.Debug().Request(true).Response(true).Print()
}
