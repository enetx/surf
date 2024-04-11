package surf

import (
	"fmt"
	"io"
	"strings"

	"github.com/enetx/g"
	"github.com/enetx/http/httputil"
)

// debug is a struct that holds debugging information for an HTTP response.
type debug struct {
	print strings.Builder // Debug information text.
	resp  Response        // Associated Response.
}

// Debug returns a debug instance associated with a Response.
func (resp Response) Debug() *debug { return &debug{resp: resp} }

// Print prints the debug information.
func (d *debug) Print() { _, _ = fmt.Println(d.print.String()) }

// Request appends the request details to the debug information.
func (d *debug) Request(verbos ...bool) *debug {
	body, err := httputil.DumpRequestOut(d.resp.request.request, false)
	if err != nil {
		return d
	}

	if d.print.Len() != 0 {
		_, _ = fmt.Fprint(&d.print, "\n")
	}

	_, _ = fmt.Fprintf(&d.print, "%s\n", g.Bytes(body).TrimSpace())

	if len(verbos) != 0 && verbos[0] && d.resp.request.body != nil {
		if bytes, err := io.ReadAll(d.resp.request.body); err == nil {
			reqBody := g.NewBytes(bytes).TrimSpace()
			_, _ = fmt.Fprint(&d.print, reqBody.ToString().Format("\n%s\n").Std())
		}
	}

	return d
}

// Response appends the response details to the debug information.
func (d *debug) Response(verbos ...bool) *debug {
	body, err := httputil.DumpResponse(d.resp.response, false)
	if err != nil {
		return d
	}

	if d.print.Len() != 0 {
		_, _ = fmt.Fprint(&d.print, "\n")
	}

	_, _ = fmt.Fprint(&d.print, g.Bytes(body).TrimSpace().ToString())

	if len(verbos) != 0 && verbos[0] && d.resp.Body != nil {
		_, _ = fmt.Fprint(&d.print, d.resp.Body.String().TrimSpace().Prepend("\n\n"))
	}

	return d
}
