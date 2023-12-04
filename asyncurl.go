package surf

import "gitlab.com/x0xO/http"

// AsyncURL struct represents an asynchronous URL with additional information
// such as context, addHeaders, setHeaders, URL, addCookies, and data.
type AsyncURL struct {
	context    any            // Additional context for the asynchronous URL.
	addHeaders any            // Additional headers to add to the request.
	setHeaders any            // Headers to set for the request.
	url        string         // The URL for the asynchronous request.
	addCookies []*http.Cookie // Additional cookies to add to the request.
	data       []any          // Additional data to include in the request.
}

// asyncResponse struct represents an asynchronous response that embeds a
// *Response pointer and includes an additional context field of type any.
type asyncResponse struct {
	*Response     // Pointer to the associated Response.
	context   any // Additional context for the asynchronous response.
}

// asyncRequest struct represents an asynchronous request that embeds a
// *Request pointer and includes additional fields: context, setHeaders,
// addHeaders, and addCookies, all of type map[string]string.
type asyncRequest struct {
	*Request                  // Pointer to the associated Request.
	context    any            // Additional context for the asynchronous request.
	setHeaders any            // Headers to set for the request.
	addHeaders any            // Additional headers to add to the request.
	addCookies []*http.Cookie // Additional cookies to add to the request.
}

// NewAsyncURL creates a new AsyncURL object with the provided URL string and returns a pointer to it.
func NewAsyncURL(url string) *AsyncURL { return &AsyncURL{url: url} }

// Context sets the context of the AsyncURL object and returns a pointer to the updated object.
func (au *AsyncURL) Context(context any) *AsyncURL {
	au.context = context
	return au
}

// Data sets the data of the AsyncURL object and returns a pointer to the updated object.
func (au *AsyncURL) Data(data ...any) *AsyncURL {
	au.data = data
	return au
}

// SetHeaders sets the headers of the AsyncURL object and returns a pointer to the updated object.
func (au *AsyncURL) SetHeaders(headers any) *AsyncURL {
	au.setHeaders = headers
	return au
}

// AddHeaders adds headers to the AsyncURL object and returns a pointer to the updated object.
func (au *AsyncURL) AddHeaders(headers any) *AsyncURL {
	au.addHeaders = headers
	return au
}

// AddCookies adds cookies to the AsyncURL object and returns a pointer to the updated object.
func (au *AsyncURL) AddCookies(cookies ...*http.Cookie) *AsyncURL {
	au.addCookies = cookies
	return au
}

// Context returns the context of the asyncResponse object.
func (ar asyncResponse) Context() any { return ar.context }
