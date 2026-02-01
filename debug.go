package surf

import (
	"github.com/enetx/g"
	"github.com/enetx/http/httputil"
)

// Debug is a struct that holds debugging information for an HTTP response.
type Debug struct {
	print g.Builder // Debug information text.
	resp  Response  // Associated Response.
}

// Debug returns a debug instance associated with a Response.
func (resp Response) Debug() *Debug { return &Debug{resp: resp} }

// Print prints the debug information.
func (d *Debug) Print() { g.Println(d.print.String()) }

// Request appends the request details to the debug information.
func (d *Debug) Request(verbos ...bool) *Debug {
	body, err := httputil.DumpRequestOut(d.resp.request.request, false)
	if err != nil {
		return d
	}

	if d.print.Len() != 0 {
		_ = g.Write(&d.print, "\n")
	}

	_ = g.Writeln(&d.print, "{}", g.String(body).Trim())

	if len(verbos) != 0 && verbos[0] && d.resp.request.bodyBytes != nil {
		reqBody := g.Bytes(d.resp.request.bodyBytes).Trim()
		_ = g.Writeln(&d.print, "\n{}", reqBody.String())
	}

	return d
}

// Response appends the response details to the debug information.
func (d *Debug) Response(verbos ...bool) *Debug {
	body, err := httputil.DumpResponse(d.resp.response, false)
	if err != nil {
		return d
	}

	if d.print.Len() != 0 {
		_ = g.Write(&d.print, "\n")
	}

	_ = g.Write(&d.print, g.String(body).Trim())

	if len(verbos) != 0 && verbos[0] && d.resp.Body != nil {
		if bodyStr := d.resp.Body.String(); bodyStr.IsOk() {
			_ = g.Write(&d.print, bodyStr.Ok().Trim().Prepend("\n\n"))
		}
	}

	return d
}
