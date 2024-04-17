package surf

import (
	"fmt"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/g/cmp"
	"github.com/enetx/http"
)

type builder struct {
	cli                      *Client
	proxy                    any                                        // Proxy configuration.
	checkRedirect            func(*http.Request, []*http.Request) error // Redirect policy.
	http2s                   *http2s                                    // HTTP2 settings.
	retryCodes               g.Slice[int]                               // Codes for retry attempts.
	cliMWs                   g.MapOrd[int, func(*Client)]               // Client-level middlewares.
	retryWait                time.Duration                              // Wait time between retries.
	retryMax                 int                                        // Maximum retry attempts.
	maxRedirects             int                                        // Maximum number of redirects to follow.
	forseHTTP1               bool                                       // Use HTTP/1.1.
	cacheBody                bool                                       // Cache response bodies.
	followOnlyHostRedirects  bool                                       // Follow redirects only to the same host.
	forwardHeadersOnRedirect bool                                       // Forward headers on redirects.
	ja3                      bool                                       // Use JA3.
	session                  bool                                       // Use Session.
	singleton                bool                                       // Use Singleton.
}

// Build sets the provided settings for the client and returns the updated client.
// It configures various settings like HTTP2, sessions, keep-alive, dial TLS, resolver,
// interface address, timeout, and redirect policy.
func (b *builder) Build() *Client {
	// sorting client middleware by priority
	b.cliMWs.SortBy(func(a, b g.Pair[int, func(*Client)]) cmp.Ordering { return cmp.Cmp(a.Key, b.Key) })
	b.cliMWs.Iter().ForEach(func(_ int, m func(*Client)) { b.cli.applyCliMW(m) })

	return b.cli
}

// With adds middleware to the client.
// It accepts various types of middleware functions and adds them to the client builder.
//
// Parameters:
//   - middleware: The middleware function to add. It can be one of the following types:
//     1. func(*surf.Client): Client middleware function, which modifies the client itself.
//     2. func(*surf.Request) error: Request middleware function, which intercepts and potentially modifies outgoing requests.
//     3. func(*surf.Response) error: Response middleware function, which intercepts and potentially modifies incoming responses.
//   - priority (optional): Priority of the middleware. Defaults to 0 if not provided.
//
// If the provided middleware is of an unsupported type, With panics with an error message indicating the invalid middleware type.
//
// Example usage:
//
//	// Adding client middleware to modify client settings.
//	.With(func(client *surf.Client) {
//	    // Custom logic to modify the client settings.
//	})
//
//	// Adding request middleware to intercept outgoing requests.
//	.With(func(req *surf.Request) error {
//	    // Custom logic to modify outgoing requests.
//	    return nil
//	})
//
//	// Adding response middleware to intercept incoming responses.
//	.With(func(resp *surf.Response) error {
//	    // Custom logic to handle incoming responses.
//	    return nil
//	})
//
// Note: Ensure that middleware functions adhere to the specified function signatures to work correctly with the With method.
func (b *builder) With(middleware any, priority ...int) *builder {
	switch v := middleware.(type) {
	case func(*Client):
		pr := 0
		if len(priority) != 0 {
			pr = priority[0]
		}
		b.addCliMW(pr, v)
	case func(*Request) error:
		b.addReqMW(v)
	case func(*Response) error:
		b.addRespMW(v)
	default:
		panic(fmt.Sprintf("invalid middleware type: %T", v))
	}

	return b
}

// addCliMW adds a client middleware to the ClientBuilder.
func (b *builder) addCliMW(priority int, m func(*Client)) *builder {
	for b.cliMWs.Contains(priority) {
		priority++
	}

	b.cliMWs.Set(priority, m)

	return b
}

// addReqMW adds a request middleware to the ClientBuilder.
func (b *builder) addReqMW(m func(*Request) error) *builder {
	b.cli.addReqMW(m)
	return b
}

// addRespMW adds a response middleware to the ClientBuilder.
func (b *builder) addRespMW(m func(*Response) error) *builder {
	b.cli.addRespWM(m)
	return b
}

// Singleton configures the client to use a singleton instance, ensuring there's only one client instance.
// This is needed specifically for JA3 or Impersonate functionalities.
func (b *builder) Singleton() *builder {
	b.singleton = true
	return b
}

// H2C configures the client to handle HTTP/2 Cleartext (h2c).
func (b *builder) H2C() *builder { return b.addCliMW(999, h2cMW) }

// HTTP2Settings configures settings related to HTTP/2 and returns an http2s struct.
func (b *builder) HTTP2Settings() *http2s {
	h2 := &http2s{builder: b}
	b.http2s = h2

	return h2
}

// Impersonate configures something related to impersonation and returns an impersonate struct.
func (b *builder) Impersonate() *impersonate { return &impersonate{builder: b} }

// JA3 configures the client to use a specific TLS fingerprint.
func (b *builder) JA3() *ja3 {
	b.ja3 = true
	return &ja3{builder: b}
}

// UnixDomainSocket sets the path for a Unix domain socket.
// This allows the HTTP client to connect to the server using a Unix domain
// socket instead of a traditional TCP/IP connection.
func (b *builder) UnixDomainSocket(socketPath string) *builder {
	return b.addCliMW(0, func(client *Client) { unixDomainSocketMW(client, socketPath) })
}

// DNS sets the custom DNS resolver address.
func (b *builder) DNS(dns string) *builder {
	return b.addCliMW(0, func(client *Client) { dnsMW(client, dns) })
}

// DNSOverTLS configures the client to use DNS over TLS.
func (b *builder) DNSOverTLS() *dnsOverTLS { return &dnsOverTLS{builder: b} }

// Timeout sets the timeout duration for the client.
func (b *builder) Timeout(timeout time.Duration) *builder {
	return b.addCliMW(0, func(client *Client) { timeoutMW(client, timeout) })
}

// InterfaceAddr sets the network interface address for the client.
func (b *builder) InterfaceAddr(address string) *builder {
	return b.addCliMW(0, func(client *Client) { interfaceAddrMW(client, address) })
}

// Proxy sets the proxy settings for the client.
func (b *builder) Proxy(proxy any) *builder {
	b.proxy = proxy
	return b.addCliMW(0, func(client *Client) { proxyMW(client, proxy) })
}

// BasicAuth sets the basic authentication credentials for the client.
func (b *builder) BasicAuth(authentication any) *builder {
	return b.addReqMW(func(req *Request) error { return basicAuthMW(req, authentication) })
}

// BearerAuth sets the bearer token for the client.
func (b *builder) BearerAuth(authentication string) *builder {
	return b.addReqMW(func(req *Request) error { return bearerAuthMW(req, authentication) })
}

// UserAgent sets the user agent for the client.
func (b *builder) UserAgent(userAgent any) *builder {
	return b.addReqMW(func(req *Request) error { return userAgentMW(req, userAgent) })
}

// ContentType sets the content type for the client.
func (b *builder) ContentType(contentType string) *builder {
	return b.addReqMW(func(req *Request) error { return contentTypeMW(req, contentType) })
}

// CacheBody configures whether the client should cache the body of the response.
func (b *builder) CacheBody() *builder {
	b.cacheBody = true
	return b
}

// GetRemoteAddress configures whether the client should get the remote address.
func (b *builder) GetRemoteAddress() *builder { return b.addReqMW(remoteAddrMW) }

// DisableKeepAlive disable keep-alive connections.
func (b *builder) DisableKeepAlive() *builder { return b.addCliMW(0, disableKeepAliveMW) }

// DisableCompression disables compression for the HTTP client.
func (b *builder) DisableCompression() *builder { return b.addCliMW(0, disableCompressionMW) }

// Retry configures the retry behavior of the client.
//
// Parameters:
//
//	retryMax: Maximum number of retries to be attempted.
//	retryWait: Duration to wait between retries.
//	codes: Optional list of HTTP status codes that trigger retries.
//	       If no codes are provided, default codes will be used
//	       (500, 429, 503 - Internal Server Error, Too Many Requests, Service Unavailable).
func (b *builder) Retry(retryMax int, retryWait time.Duration, codes ...int) *builder {
	b.retryMax = retryMax
	b.retryWait = retryWait

	if len(codes) == 0 {
		b.retryCodes = g.SliceOf(
			http.StatusInternalServerError,
			http.StatusTooManyRequests,
			http.StatusServiceUnavailable,
		)
	} else {
		b.retryCodes = g.SliceOf(codes...)
	}

	return b
}

// ForceHTTP1MW configures the client to use HTTP/1.1 forcefully.
func (b *builder) ForceHTTP1() *builder {
	b.forseHTTP1 = true
	return b.addCliMW(0, forseHTTP1MW)
}

// Session configures whether the client should maintain a session.
func (b *builder) Session() *builder {
	b.session = true
	return b.addCliMW(0, sessionMW)
}

// MaxRedirects sets the maximum number of redirects the client should follow.
func (b *builder) MaxRedirects(maxRedirects int) *builder {
	b.maxRedirects = maxRedirects
	return b.addCliMW(0, redirectPolicyMW)
}

// NotFollowRedirects disables following redirects for the client.
func (b *builder) NotFollowRedirects() *builder {
	return b.RedirectPolicy(func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse })
}

// FollowOnlyHostRedirects configures whether the client should only follow redirects within the
// same host.
func (b *builder) FollowOnlyHostRedirects() *builder {
	b.followOnlyHostRedirects = true
	return b.addCliMW(0, redirectPolicyMW)
}

// ForwardHeadersOnRedirect adds a middleware to the ClientBuilder object that ensures HTTP headers are
// forwarded during a redirect.
func (b *builder) ForwardHeadersOnRedirect() *builder {
	b.forwardHeadersOnRedirect = true
	return b.addCliMW(0, redirectPolicyMW)
}

// RedirectPolicy sets a custom redirect policy for the client.
func (b *builder) RedirectPolicy(f func(*http.Request, []*http.Request) error) *builder {
	b.checkRedirect = f
	return b.addCliMW(0, redirectPolicyMW)
}

// String generate a string representation of the ClientBuilder instance.
func (b builder) String() string { return fmt.Sprintf("%#v", b) }
