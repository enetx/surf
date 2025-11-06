package surf

import (
	"context"
	"fmt"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
)

// browser represents the browser type being impersonated for fingerprinting.
type browser int

const (
	unknownBrowser   browser = iota // No specific browser fingerprinting
	chromeBrowser                   // Chrome browser fingerprinting
	firefoxBrowser                  // Firefox browser fingerprinting
	chromeBrowserUB                 // Chrome browser for ub
	firefoxBrowserUB                // Firefox browser for ub
)

// Builder provides a fluent interface for configuring HTTP clients with various advanced features
// including proxy settings, TLS fingerprinting, HTTP/2 and HTTP/3 support, retry logic,
// redirect handling, and browser impersonation capabilities.
type Builder struct {
	cli                      *Client                                    // The client being configured
	proxy                    any                                        // Proxy configuration (static string/slice or dynamic function)
	checkRedirect            func(*http.Request, []*http.Request) error // Custom redirect policy function
	http2settings            *HTTP2Settings                             // HTTP/2 specific settings
	http3settings            *HTTP3Settings                             // HTTP/3 specific settings
	retryCodes               g.Slice[int]                               // HTTP status codes that trigger retries
	cliMWs                   *middleware[*Client]                       // Priority-ordered client middlewares
	retryWait                time.Duration                              // Wait duration between retry attempts
	retryMax                 int                                        // Maximum number of retry attempts
	maxRedirects             int                                        // Maximum number of redirects to follow
	forceHTTP1               bool                                       // Force HTTP/1.1 protocol usage
	cacheBody                bool                                       // Enable response body caching
	followOnlyHostRedirects  bool                                       // Only follow redirects within same host
	forwardHeadersOnRedirect bool                                       // Preserve headers during redirects
	ja                       bool                                       // Enable JA3 TLS fingerprinting
	singleton                bool                                       // Use singleton pattern for connection reuse
	browser                  browser                                    // Browser type for fingerprinting
	http3                    bool                                       // Enable HTTP/3 with automatic browser detection
}

// Build sets the provided settings for the client and returns the updated client.
// It configures various settings like HTTP2, sessions, keep-alive, dial TLS, resolver,
// interface address, timeout, and redirect policy.
func (b *Builder) Build() *Client {
	// Apply HTTP/3 settings lazily if enabled
	if b.http3 {
		http3s := b.HTTP3Settings()

		switch b.browser {
		case chromeBrowser, chromeBrowserUB:
			http3s.Chrome().Set()
		case firefoxBrowser, firefoxBrowserUB:
			http3s.Firefox().Set()
		default:
			// Default to Chrome if no browser was detected
			http3s.Chrome().Set()
		}
	}

	// apply each middleware to the Client
	b.cliMWs.run(b.cli)

	return b.cli
}

// With registers middleware into the client builder with optional priority.
//
// It accepts one of the following middleware function types:
//   - func(*surf.Client) error   — client middleware, modifies or initializes the client
//   - func(*surf.Request) error  — request middleware, intercepts or transforms outgoing requests
//   - func(*surf.Response) error — response middleware, intercepts or transforms incoming responses
//
// Parameters:
//   - middleware: A function matching one of the supported middleware types.
//   - priority (optional): Integer priority level. Lower values run earlier. Defaults to 0.
//
// Middleware with the same priority are executed in order of insertion (FIFO).
// If the middleware type is not recognized, With panics with an informative error.
//
// Example:
//
//	// Adding client middleware to modify client settings.
//	.With(func(client *surf.Client) error {
//	    // Custom logic to modify the client settings.
//	    return nil
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
func (b *Builder) With(middleware any, priority ...int) *Builder {
	p := g.Int(g.Slice[int](priority).Get(0).UnwrapOrDefault())

	switch v := middleware.(type) {
	case func(*Client) error:
		b.addCliMW(v, p)
	case func(*Request) error:
		b.addReqMW(v, p)
	case func(*Response) error:
		b.addRespMW(v, p)
	default:
		panic(fmt.Sprintf("invalid middleware type: %T", v))
	}

	return b
}

// addCliMW adds a client middleware to the ClientBuilder.
func (b *Builder) addCliMW(m func(*Client) error, priority g.Int) *Builder {
	b.cliMWs.add(priority, m)
	return b
}

// addReqMW adds a request middleware to the ClientBuilder.
func (b *Builder) addReqMW(m func(*Request) error, priority g.Int) *Builder {
	b.cli.reqMWs.add(priority, m)
	return b
}

// addRespMW adds a response middleware to the ClientBuilder.
func (b *Builder) addRespMW(m func(*Response) error, priority g.Int) *Builder {
	b.cli.respMWs.add(priority, m)
	return b
}

func (b *Builder) Boundary(boundary func() g.String) *Builder {
	return b.addCliMW(func(client *Client) error { return boundaryMW(client, boundary) }, 999)
}

// Singleton configures the client to use a singleton instance, ensuring there's only one client instance.
// This is needed specifically for JA or Impersonate functionalities.
//
//	cli := surf.NewClient().
//		Builder().
//		Singleton(). // for reuse client
//		Impersonate().
//		FireFox().
//		Build()
//
//	defer cli.CloseIdleConnections()
func (b *Builder) Singleton() *Builder {
	b.singleton = true
	return b
}

// H2C configures the client to handle HTTP/2 Cleartext (h2c).
func (b *Builder) H2C() *Builder { return b.addCliMW(h2cMW, 999) }

// HTTP2Settings configures settings related to HTTP/2 and returns an http2s struct.
func (b *Builder) HTTP2Settings() *HTTP2Settings {
	h2 := &HTTP2Settings{builder: b}
	b.http2settings = h2

	return h2
}

// HTTP3Settings configures settings related to HTTP/3 and returns an http3s struct.
func (b *Builder) HTTP3Settings() *HTTP3Settings {
	h3 := &HTTP3Settings{builder: b}
	b.http3settings = h3
	b.http3 = false

	return h3
}

// HTTP3 enables HTTP/3 with automatic browser detection.
// Settings are applied lazily in Build() based on the impersonated browser.
// Usage: surf.NewClient().Builder().Impersonate().Chrome().HTTP3().Build()
func (b *Builder) HTTP3() *Builder {
	b.http3 = true
	return b
}

// Impersonate configures something related to impersonation and returns an impersonate struct.
func (b *Builder) Impersonate() *Impersonate { return &Impersonate{builder: b} }

// JA configures the client to use a specific TLS fingerprint.
func (b *Builder) JA() *JA {
	b.ja = true
	return &JA{builder: b}
}

// UnixSocket sets the path for a Unix domain socket.
// This allows the HTTP client to connect to the server using a Unix domain
// socket instead of a traditional TCP/IP connection.
func (b *Builder) UnixSocket(address g.String) *Builder {
	return b.addCliMW(func(client *Client) error { return unixSocketMW(client, address) }, 0)
}

// DNS sets the custom DNS resolver address.
func (b *Builder) DNS(dns g.String) *Builder {
	return b.addCliMW(func(client *Client) error { return dnsMW(client, dns) }, 0)
}

// DNSOverTLS configures the client to use DNS over TLS.
func (b *Builder) DNSOverTLS() *DNSOverTLS { return &DNSOverTLS{builder: b} }

// Timeout sets the timeout duration for the client.
func (b *Builder) Timeout(timeout time.Duration) *Builder {
	return b.addCliMW(func(client *Client) error { return timeoutMW(client, timeout) }, 0)
}

// InterfaceAddr sets the network interface address for the client.
func (b *Builder) InterfaceAddr(address g.String) *Builder {
	return b.addCliMW(func(client *Client) error { return interfaceAddrMW(client, address) }, 0)
}

// Proxy sets the proxy settings for the client.
// Supports both static proxy configurations and dynamic proxy provider functions.
//
// Static proxy examples:
//
//	.Proxy("socks5://127.0.0.1:9050")
//	.Proxy([]string{"socks5://proxy1", "http://proxy2"})
//
// Dynamic proxy example:
//
//	.Proxy(func() g.String {
//	  // Your proxy rotation logic here
//	  return "socks5://127.0.0.1:9050"
//	})
func (b *Builder) Proxy(proxy any) *Builder {
	b.proxy = proxy
	return b.addCliMW(func(client *Client) error { return proxyMW(client, proxy) }, 0)
}

// BasicAuth sets the basic authentication credentials for the client.
func (b *Builder) BasicAuth(authentication g.String) *Builder {
	return b.addReqMW(func(req *Request) error { return basicAuthMW(req, authentication) }, 900)
}

// BearerAuth sets the bearer token for the client.
func (b *Builder) BearerAuth(authentication g.String) *Builder {
	return b.addReqMW(func(req *Request) error { return bearerAuthMW(req, authentication) }, 901)
}

// UserAgent sets the user agent for the client.
func (b *Builder) UserAgent(userAgent any) *Builder {
	return b.addReqMW(func(req *Request) error { return userAgentMW(req, userAgent) }, 0)
}

// SetHeaders sets headers for the request, replacing existing ones with the same name.
func (b *Builder) SetHeaders(headers ...any) *Builder {
	return b.addReqMW(func(r *Request) error {
		r.SetHeaders(headers...)
		return nil
	}, 0)
}

// AddHeaders adds headers to the request, appending to any existing headers with the same name.
func (b *Builder) AddHeaders(headers ...any) *Builder {
	return b.addReqMW(func(r *Request) error {
		r.AddHeaders(headers...)
		return nil
	}, 0)
}

// AddCookies adds cookies to the request.
func (b *Builder) AddCookies(cookies ...*http.Cookie) *Builder {
	return b.addReqMW(func(r *Request) error {
		r.AddCookies(cookies...)
		return nil
	}, 0)
}

// WithContext associates the provided context with the request.
func (b *Builder) WithContext(ctx context.Context) *Builder {
	return b.addReqMW(func(r *Request) error {
		r.WithContext(ctx)
		return nil
	}, 0)
}

// ContentType sets the content type for the client.
func (b *Builder) ContentType(contentType g.String) *Builder {
	return b.addReqMW(func(req *Request) error { return contentTypeMW(req, contentType) }, 0)
}

// CacheBody configures whether the client should cache the body of the response.
func (b *Builder) CacheBody() *Builder {
	b.cacheBody = true
	return b
}

// GetRemoteAddress configures whether the client should get the remote address.
func (b *Builder) GetRemoteAddress() *Builder { return b.addReqMW(remoteAddrMW, 0) }

// DisableKeepAlive disable keep-alive connections.
func (b *Builder) DisableKeepAlive() *Builder { return b.addCliMW(disableKeepAliveMW, 0) }

// DisableCompression disables compression for the HTTP client.
func (b *Builder) DisableCompression() *Builder { return b.addCliMW(disableCompressionMW, 0) }

// Retry configures the retry behavior of the client.
//
// Parameters:
//
//	retryMax: Maximum number of retries to be attempted.
//	retryWait: Duration to wait between retries.
//	codes: Optional list of HTTP status codes that trigger retries.
//	       If no codes are provided, default codes will be used
//	       (500, 429, 503 - Internal Server Error, Too Many Requests, Service Unavailable).
func (b *Builder) Retry(retryMax int, retryWait time.Duration, codes ...int) *Builder {
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
func (b *Builder) ForceHTTP1() *Builder {
	b.forceHTTP1 = true
	return b.addCliMW(forseHTTP1MW, 0)
}

// Session configures whether the client should maintain a session.
func (b *Builder) Session() *Builder { return b.addCliMW(sessionMW, 0) }

// MaxRedirects sets the maximum number of redirects the client should follow.
func (b *Builder) MaxRedirects(maxRedirects int) *Builder {
	b.maxRedirects = maxRedirects
	return b.addCliMW(redirectPolicyMW, 0)
}

// NotFollowRedirects disables following redirects for the client.
func (b *Builder) NotFollowRedirects() *Builder {
	return b.RedirectPolicy(func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse })
}

// FollowOnlyHostRedirects configures whether the client should only follow redirects within the
// same host.
func (b *Builder) FollowOnlyHostRedirects() *Builder {
	b.followOnlyHostRedirects = true
	return b.addCliMW(redirectPolicyMW, 0)
}

// ForwardHeadersOnRedirect adds a middleware to the ClientBuilder object that ensures HTTP headers are
// forwarded during a redirect.
func (b *Builder) ForwardHeadersOnRedirect() *Builder {
	b.forwardHeadersOnRedirect = true
	return b.addCliMW(redirectPolicyMW, 0)
}

// RedirectPolicy sets a custom redirect policy for the client.
func (b *Builder) RedirectPolicy(fn func(*http.Request, []*http.Request) error) *Builder {
	b.checkRedirect = fn
	return b.addCliMW(redirectPolicyMW, 0)
}

// String generate a string representation of the ClientBuilder instance.
func (b Builder) String() string { return fmt.Sprintf("%#v", b) }
