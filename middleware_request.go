package surf

import (
	"errors"
	"fmt"
	"math/rand"
	"net/textproto"
	"strings"

	"gitlab.com/x0xO/http/httptrace"
)

// default user-agent for surf.
func defaultUserAgentMW(req *Request) error {
	if req.GetRequest().Header.Get("User-Agent") == "" {
		// Set the default user-agent header.
		req.SetHeaders(map[string]string{"User-Agent": _userAgent})
	}

	return nil
}

// userAgentMW sets the "User-Agent" header for the given Request. The userAgent parameter
// can be a string or a slice of strings. If it is a slice, a random user agent is selected
// from the slice. If the userAgent is not a string or a slice of strings, an error is returned.
// The function updates the request headers with the selected or given user agent.
func userAgentMW(req *Request, userAgent any) error {
	var ua string

	switch v := userAgent.(type) {
	case string:
		ua = v
	case []string:
		ua = v[rand.Intn(len(v))]
	default:
		return fmt.Errorf("unsupported user agent type")
	}

	req.SetHeaders(map[string]string{"User-Agent": ua})

	return nil
}

// got101ResponseMW configures the request's context to handle 1xx responses.
// It sets up a client trace for capturing 1xx responses and returns any error encountered.
func got101ResponseMW(req *Request) error {
	req.WithContext(httptrace.WithClientTrace(req.GetRequest().Context(),
		&httptrace.ClientTrace{
			Got1xxResponse: func(code int, _ textproto.MIMEHeader) error {
				if code != 101 {
					return nil
				}

				return errors.New("101 status code")
			},
		},
	))

	return nil
}

// remoteAddrMW configures the request's context to get the remote address
// of the server if the 'remoteAddrMW' option is enabled.
func remoteAddrMW(req *Request) error {
	req.WithContext(httptrace.WithClientTrace(req.GetRequest().Context(),
		&httptrace.ClientTrace{
			GotConn: func(info httptrace.GotConnInfo) { req.remoteAddr = info.Conn.RemoteAddr() },
		},
	))

	return nil
}

// bearerAuthMW adds a Bearer token to the Authorization header of the given request.
func bearerAuthMW(req *Request, authentication string) error {
	if authentication != "" {
		req.AddHeaders(map[string]string{"Authorization": "Bearer " + authentication})
	}

	return nil
}

// basicAuthMW sets basic authentication for the request based on the client's options.
func basicAuthMW(req *Request, authentication any) error {
	if req.GetRequest().Header.Get("Authorization") != "" {
		return nil
	}

	var user, password string

	switch auth := authentication.(type) {
	case string:
		parts := strings.SplitN(auth, ":", 2)
		if len(parts) != 2 {
			return fmt.Errorf("malformed basic authorization string: %s", auth)
		}

		user, password = parts[0], parts[1]
	case []string:
		if len(auth) != 2 {
			return fmt.Errorf("basic authorization slice should contain two elements: %v", auth)
		}

		user, password = auth[0], auth[1]
	case map[string]string:
		if len(auth) != 1 {
			return fmt.Errorf("basic authorization map should contain one element: %v", auth)
		}

		for k, v := range auth {
			user, password = k, v
		}
	default:
		return fmt.Errorf("unsupported basic authorization option type: %T", auth)
	}

	if user == "" || password == "" {
		return errors.New("basic authorization fields cannot be empty")
	}

	req.GetRequest().SetBasicAuth(user, password)

	return nil
}

// contentTypeMW sets the Content-Type header for the given HTTP request.
func contentTypeMW(req *Request, contentType string) error {
	if contentType != "" {
		req.SetHeaders(map[string]string{"Content-Type": contentType})
	}

	return nil
}
