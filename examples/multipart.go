package main

import (
	"github.com/enetx/g"
	"github.com/enetx/surf"
)

func main() {
	multipartData := g.NewMapOrd[g.String, g.String]()

	multipartData.Set("_wpcf7", "36484")
	multipartData.Set("_wpcf7_version", "5.4")
	multipartData.Set("_wpcf7_locale", "ru_RU")
	multipartData.Set("_wpcf7_unit_tag", "wpcf7-f36484-o1")
	multipartData.Set("_wpcf7_container_post", "0")
	multipartData.Set("_wpcf7_posted_data_hash", "")
	multipartData.Set("your-name", "name")
	multipartData.Set("retreat", "P48")
	multipartData.Set("your-message", "message")

	r := surf.NewClient().
		Builder().
		Impersonate().
		Firefox().
		// Chrome().
		Build().
		Unwrap().
		Multipart("http://google.com", multipartData).
		Do().
		Unwrap()

	r.Debug().Request(true).Print()
	r.Body.Close()
}
