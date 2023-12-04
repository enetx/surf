package main

import (
	"log"
	"net/url"
	"path"

	"gitlab.com/x0xO/surf"
)

func main() {
	dURL := "https://jsoncompare.org/LearningContainer/SampleFiles/Video/MP4/Sample-Video-File-For-Testing.mp4"

	r, err := surf.NewClient().Get(dURL).Do()
	if err != nil {
		log.Fatal(err)
	}

	URL, err := url.ParseRequestURI(dURL)
	if err != nil {
		log.Fatal(err)
	}

	r.Body.Dump(path.Base(URL.Path))

	// or
	// r.Body.Dump("/home/user/some_file.zip")
}
