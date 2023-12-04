package surf

type (
	clientMiddleware   func(*Client)         // clientMiddleware represents a middleware function for the Client.
	requestMiddleware  func(*Request) error  // requestMiddleware represents a middleware function for the Request.
	responseMiddleware func(*Response) error // responseMiddleware represents a middleware function for the Response.
)

// applyReqMW applies request middlewares to the Client's request.
func (c *Client) applyReqMW(req *Request) error {
	for _, m := range c.reqMW {
		if err := m(req); err != nil {
			return err
		}
	}

	return nil
}

// applyRespMW applies response middlewares to the Client's response.
func (c *Client) applyRespMW(resp *Response) error {
	for _, m := range c.respMW {
		if err := m(resp); err != nil {
			return err
		}
	}

	return nil
}

// applyReqMW applies request middlewares to the Options' request.
func (opt *Options) applyReqMW(req *Request) error {
	for _, m := range opt.reqMW {
		if err := m(req); err != nil {
			return err
		}
	}

	return nil
}
