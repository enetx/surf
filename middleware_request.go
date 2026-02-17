package surf

import (
	"errors"
	"fmt"
	"math/rand"
	"net/textproto"

	"github.com/enetx/g"
	"github.com/enetx/http/httptrace"
	"github.com/enetx/surf/header"
)

// defaultUserAgentMW sets the default User-Agent header for surf requests.
// Only sets the header if no User-Agent is already present in the request.
// Uses the predefined _userAgent constant as the default value.
func defaultUserAgentMW(req *Request) error {
	if headers := req.GetRequest().Header; headers.Get(header.USER_AGENT) == "" {
		// Set the default user-agent header.
		headers.Set(header.USER_AGENT, _userAgent)
	}

	return nil
}

// userAgentMW configures a custom User-Agent header for HTTP requests.
// Supports various input types for flexibility:
// - string or g.String: Uses the value directly
// - []string or g.Slice[string]: Randomly selects from the slice (useful for rotation)
// - g.Slice[g.String]: Randomly selects from g.String slice
// Returns an error for unsupported types or empty slices.
func userAgentMW(req *Request, userAgent any) error {
	var ua string

	switch v := userAgent.(type) {
	case string:
		ua = v
	case g.String:
		ua = v.Std()
	case []string:
		if len(v) == 0 {
			return &ErrUserAgentType{"cannot select a random user agent from an empty slice"}
		}
		ua = v[rand.Intn(len(v))]
	case g.Slice[string]:
		if v.IsEmpty() {
			return &ErrUserAgentType{"cannot select a random user agent from an empty slice"}
		}
		ua = v.Random()
	case g.Slice[g.String]:
		if v.IsEmpty() {
			return &ErrUserAgentType{"cannot select a random user agent from an empty slice"}
		}
		ua = v.Random().Std()
	default:
		return &ErrUserAgentType{fmt.Sprintf("'%T' %v", v, v)}
	}

	req.GetRequest().Header.Set(header.USER_AGENT, ua)

	return nil
}

// got101ResponseMW configures request tracing to handle HTTP 101 Switching Protocols responses.
// Sets up client trace callbacks to detect and handle protocol switching responses.
// Returns an error specifically for HTTP 101 responses to allow special handling of protocol upgrades.
// Other 1xx responses are ignored and allowed to proceed normally.
func got101ResponseMW(req *Request) error {
	req.WithContext(httptrace.WithClientTrace(req.GetRequest().Context(),
		&httptrace.ClientTrace{
			Got1xxResponse: func(code int, _ textproto.MIMEHeader) error {
				if code != 101 {
					return nil
				}

				return &Err101ResponseCode{
					fmt.Sprintf(`%s "%s" error:`, req.request.Method, req.request.URL.String()),
				}
			},
		},
	))

	return nil
}

// remoteAddrMW configures request tracing to capture the remote server address.
// Sets up client trace callbacks to extract and store the remote address
// of the server connection for later access. This information can be useful
// for logging, debugging, or connection analysis purposes.
func remoteAddrMW(req *Request) error {
	req.WithContext(httptrace.WithClientTrace(req.GetRequest().Context(),
		&httptrace.ClientTrace{
			GotConn: func(info httptrace.GotConnInfo) { req.remoteAddr = info.Conn.RemoteAddr() },
		},
	))

	return nil
}

// bearerAuthMW configures Bearer token authentication for HTTP requests.
// Adds an Authorization header with the Bearer token format if a token is provided.
// Only sets the header if the token is not empty, allowing conditional authentication.
func bearerAuthMW(req *Request, token g.String) error {
	if !token.IsEmpty() {
		req.AddHeaders(g.Map[g.String, g.String]{header.AUTHORIZATION: "Bearer " + token})
	}

	return nil
}

// basicAuthMW configures HTTP Basic Authentication for requests.
// Expects authentication string in "username:password" format.
// Skips setting auth if Authorization header already exists.
// Returns an error if username or password fields are empty.
func basicAuthMW(req *Request, authentication g.String) error {
	if req.GetRequest().Header.Get(header.AUTHORIZATION) != "" {
		return nil
	}

	var username, password g.String

	if idx := authentication.Index(":"); idx != -1 {
		username = authentication[:idx]
		password = authentication[idx+1:]
	}

	if username == "" || password == "" {
		return errors.New("basic authorization fields cannot be empty")
	}

	req.GetRequest().SetBasicAuth(username.Std(), password.Std())

	return nil
}

// contentTypeMW configures the Content-Type header for HTTP requests.
// Sets the MIME type of the request body content to inform the server
// how to interpret the request data. Returns an error if contentType is empty.
func contentTypeMW(req *Request, contentType g.String) error {
	if contentType.IsEmpty() {
		return fmt.Errorf("Content-Type is empty")
	}

	req.SetHeaders(g.Map[g.String, g.String]{header.CONTENT_TYPE: contentType})

	return nil
}
