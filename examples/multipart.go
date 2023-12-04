package main

import (
	"gitlab.com/x0xO/surf"
)

func main() {
	multipartData := map[string]string{
		"_wpcf7":                  "36484",
		"_wpcf7_version":          "5.4",
		"_wpcf7_locale":           "ru_RU",
		"_wpcf7_unit_tag":         "wpcf7-f36484-o1",
		"_wpcf7_container_post":   "0",
		"_wpcf7_posted_data_hash": "",
		"your-name":               "name",
		"retreat":                 "P48",
		"your-message":            "message",
	}

	r, _ := surf.NewClient().Multipart("http://google.com", multipartData).Do()
	r.Debug().Request(true).Print()
	r.Body.Close()
}
