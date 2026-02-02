package main

import (
	"log"
	"net/url"
	"path"

	"github.com/enetx/g"
	"github.com/enetx/surf"
)

func main() {
	const dURL = "https://jsoncompare.org/LearningContainer/SampleFiles/Video/MP4/Sample-Video-File-For-Testing.mp4"

	r := surf.NewClient().Get(dURL).Do()
	if r.IsErr() {
		log.Fatal(r.Err())
	}

	url, err := url.ParseRequestURI(dURL)
	if err != nil {
		log.Fatal(err)
	}

	r.Ok().Body.Dump(g.String(path.Base(url.Path)))

	// or
	// r.Ok().Body.Dump("/home/user/some_file.zip")
}
