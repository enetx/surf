package surf

import (
	"fmt"
	"io"
	"strings"

	"gitlab.com/x0xO/g"
	"gitlab.com/x0xO/http/httputil"
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

// DNSStat appends DNS cache statistics to the debug information.
func (d *debug) DNSStat() *debug {
	if d.resp.opt == nil {
		return d
	}

	if d.resp.opt.dnsCacheStats == nil {
		return d
	}

	stats := d.resp.opt.dnsCacheStats

	if d.print.Len() != 0 {
		_, _ = fmt.Fprint(&d.print, "\n")
	}

	_, _ = fmt.Fprintf(&d.print, "Total Connections: %d\n", stats.totalConn)
	_, _ = fmt.Fprintf(&d.print, "Total DNS Queries: %d\n", stats.dnsQuery)
	_, _ = fmt.Fprintf(&d.print, "Successful DNS Queries: %d\n", stats.successfulDNSQuery)
	_, _ = fmt.Fprintf(&d.print, "Cache Hit: %d\n", stats.cacheHit)
	_, _ = fmt.Fprintf(&d.print, "Cache Miss: %d\n", stats.cacheMiss)

	return d
}

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

	if len(verbos) != 0 && verbos[0] {
		_, _ = fmt.Fprint(&d.print, d.resp.Body.String().TrimSpace().AddPrefix("\n\n"))
	}

	return d
}
