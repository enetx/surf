package surf

import "context"

// async is a struct that holds information for making asynchronous HTTP requests.
type async struct {
	client *Client         // Pointer to the associated HTTP client.
	ctx    context.Context // Context for the asynchronous request.
}

// WithContext associates the provided context with the async object.
func (a *async) WithContext(ctx context.Context) *async {
	a.ctx = ctx
	return a
}

// processURL is a helper function that processes a single URL and generates an
// asynchronous request using the provided requestFunc function.
// The function returns an asyncRequest object or nil if the context is canceled.
func (a *async) processURL(aURL *AsyncURL, requestFunc func() *Request) *asyncRequest {
	if a.ctx != nil && a.ctx.Err() != nil {
		return nil
	}

	return &asyncRequest{
		Request:    requestFunc(),
		context:    aURL.context,
		setHeaders: aURL.setHeaders,
		addHeaders: aURL.addHeaders,
		addCookies: aURL.addCookies,
	}
}

// processURLs creates a goroutine to process the given URLs.
// It iterates through the URLs based on their type (either chan *AsyncURL or []*AsyncURL)
// and calls the processURL method for each URL.
// The asyncRequest objects generated by the processURL method are sent to the jobs channel.
// Once all URLs have been processed, the jobs channel is closed.
func (a *async) processURLs(urls any, requestFunc func(*AsyncURL) *Request) chan *asyncRequest {
	jobs := make(chan *asyncRequest)

	go func() {
		defer close(jobs)

		switch urlsType := urls.(type) {
		case chan *AsyncURL:
			for aURL := range urlsType {
				job := a.processURL(aURL, func() *Request { return requestFunc(aURL) })
				if job == nil {
					return
				}
				jobs <- job
			}
		case []*AsyncURL:
			for _, aURL := range urlsType {
				job := a.processURL(aURL, func() *Request { return requestFunc(aURL) })
				if job == nil {
					return
				}
				jobs <- job
			}
		}
	}()

	return jobs
}

func (a *async) request(urls any, requestFunc func(*AsyncURL) *Request) *Requests {
	requests := &Requests{jobs: a.processURLs(urls, requestFunc)}
	if a.client.opt != nil {
		requests.useJA3 = a.client.opt.useJA3
	}

	return requests
}

// Get creates asynchronous GET requests for the given URLs and returns a Requests object.
func (a *async) Get(urls any) *Requests {
	return a.request(urls, func(aURL *AsyncURL) *Request { return a.client.Get(aURL.url, aURL.data...) })
}

// Delete creates asynchronous DELETE requests for the given URLs and returns a Requests object.
func (a *async) Delete(urls any) *Requests {
	return a.request(urls, func(aURL *AsyncURL) *Request { return a.client.Delete(aURL.url, aURL.data...) })
}

// Head creates asynchronous HEAD requests for the given URLs and returns a Requests object.
func (a *async) Head(urls any) *Requests {
	return a.request(urls, func(aURL *AsyncURL) *Request { return a.client.Head(aURL.url) })
}

// Post creates asynchronous POST requests for the given URLs and returns a Requests object.
func (a *async) Post(urls any) *Requests {
	return a.request(urls, func(aURL *AsyncURL) *Request { return a.client.Post(aURL.url, aURL.data[0]) })
}

// Put creates asynchronous PUT requests for the given URLs and returns a Requests object.
func (a *async) Put(urls any) *Requests {
	return a.request(urls, func(aURL *AsyncURL) *Request { return a.client.Put(aURL.url, aURL.data[0]) })
}

// Patch creates asynchronous PATCH requests for the given URLs and returns a Requests object.
func (a *async) Patch(urls any) *Requests {
	return a.request(urls, func(aURL *AsyncURL) *Request { return a.client.Patch(aURL.url, aURL.data[0]) })
}

// Multipart creates asynchronous multipart requests for the given URLs and returns a Requests
// object.
func (a *async) Multipart(urls any) *Requests {
	return a.request(
		urls,
		func(aURL *AsyncURL) *Request { return a.client.Multipart(aURL.url, aURL.data[0].(map[string]string)) },
	)
}
