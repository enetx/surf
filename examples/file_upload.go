package main

import "gitlab.com/x0xO/surf"

func main() {
	URL := "https://httpbingo.org/anything"

	// with file path
	// surf.NewClient().FileUpload(URL, "filefield", "/path/to/file.txt").Do()

	// without physical file
	// r, _ := surf.NewClient().FileUpload(URL, "filefield", "info.txt", "Hello from surf!").Do()

	// with multipart data
	multipartValues := map[string]string{"some": "values"}
	// multipartValues := hg.HMapOf[string, string]("some", "values")

	// with file path
	// surf.NewClient().FileUpload(URL, "filefield", "/path/to/file.txt", multipartValues).Do()

	// without physical file
	r, _ := surf.NewClient().
		FileUpload(URL, "filefield", "info.txt", "Hello from surf!", multipartValues).Do()

	r.Debug().Request(true).Response(true).Print()
}
