package surf

import (
	"fmt"
	"net"
	"time"

	"gitlab.com/x0xO/g"
	"gitlab.com/x0xO/http"
)

type Options struct {
	proxy                    any                                        // Proxy configuration.
	dialer                   *net.Dialer                                // Custom network dialer.
	dnsCacheStats            *cacheDialerStats                          // DNS cache statistics.
	checkRedirect            func(*http.Request, []*http.Request) error // Redirect policy.
	retryCodes               g.Slice[int]                               // Codes for retry attemps.
	cliMW                    []clientMiddleware                         // Client-level middlewares.
	reqMW                    []requestMiddleware                        // Request-level middlewares.
	retryWait                time.Duration                              // Wait time between retries.
	retryMax                 int                                        // Maximum retry attempts.
	maxRedirects             int                                        // Maximum number of redirects to follow.
	forseHTTP1               bool                                       // Use HTTP/1.1.
	history                  bool                                       // Enable response history.
	cacheBody                bool                                       // Cache response bodies.
	followOnlyHostRedirects  bool                                       // Follow redirects only to the same host.
	forwardHeadersOnRedirect bool                                       // Forward headers on redirects.
	useJA3                   bool                                       // Use JA3.
	useHTTP2s                bool                                       // Use HTTP2 settings.
	useCacheDNS              bool                                       // Use cached DNS.
	dnsCacheTTL              time.Duration                              // DNS cache time-to-live.
	dnsCacheMaxUsage         int64                                      // Maximum usage of DNS cache.
	http2s                   *http2s
}

// NewOptions creates a new Options instance with default values.
func NewOptions() *Options { return new(Options) }

// addreqMW adds a request middleware to the Options.
func (opt *Options) addreqMW(m requestMiddleware) *Options {
	opt.reqMW = append(opt.reqMW, m)
	return opt
}

// addcliMW adds a client middleware to the Options.
func (opt *Options) addcliMW(m clientMiddleware) *Options {
	opt.cliMW = append(opt.cliMW, m)
	return opt
}

// HTTP2Settings configures settings related to HTTP/2 and returns an http2s struct.
func (opt *Options) HTTP2Settings() *http2s {
	opt.useHTTP2s = true
	h2 := &http2s{opt: opt}
	h2.opt.http2s = h2

	return h2
}

// Impersonate configures something related to impersonation and returns an impersonate struct.
func (opt *Options) Impersonate() *impersonate { return &impersonate{opt: opt} }

// JA3 configures the client to use a specific TLS fingerprint.
func (opt *Options) JA3() *ja3 {
	opt.useJA3 = true
	return &ja3{opt: opt}
}

// UnixDomainSocket sets the path for a Unix domain socket in the Options.
// This allows the HTTP client to connect to the server using a Unix domain
// socket instead of a traditional TCP/IP connection.
func (opt *Options) UnixDomainSocket(socketPath string) *Options {
	return opt.addcliMW(func(client *Client) { unixDomainSocketMW(client, socketPath) })
}

// DNSCache configures the DNS cache settings of the HTTP client.
//
// DNS caching can improve the performance of HTTP clients by caching the DNS
// lookup results for the specified Time-To-Live (TTL) duration and limiting the usage of the
// cached DNS result.
//
// Parameters:
//
// - ttl: the TTL duration for the DNS cache. After this duration, the DNS cache for a host will be
// invalidated.
//
// - maxUsage: the maximum number of times a cached DNS lookup result can be used. After this
// number is reached, the DNS cache for a host will be invalidated.
//
// Returns the same Options object, allowing for chaining of configuration calls.
//
// Example:
//
//	opt := surf.NewOptions().DNSCache(time.Second*30, 10)
//	cli := surf.NewClient().SetOptions(opt)
//
// The client will now use a DNS cache with a 30-second TTL and a maximum usage count of 10.
func (opt *Options) DNSCache(ttl time.Duration, maxUsage int64) *Options {
	opt.useCacheDNS = true
	opt.dnsCacheTTL = ttl
	opt.dnsCacheMaxUsage = maxUsage

	return opt.addcliMW(dnsCacheMW)
}

// DNS sets the custom DNS resolver address.
func (opt *Options) DNS(dns string) *Options {
	return opt.addcliMW(func(client *Client) { dnsMW(client, dns) })
}

// DNSOverTLS configures the client to use DNS over TLS.
func (opt *Options) DNSOverTLS() *dnsOverTLS { return &dnsOverTLS{opt: opt} }

// Timeout sets the timeout duration for the client.
func (opt *Options) Timeout(timeout time.Duration) *Options {
	return opt.addcliMW(func(client *Client) { timeoutMW(client, timeout) })
}

// InterfaceAddr sets the network interface address for the client.
func (opt *Options) InterfaceAddr(address string) *Options {
	return opt.addcliMW(func(client *Client) { interfaceAddrMW(client, address) })
}

// Proxy sets the proxy settings for the client.
func (opt *Options) Proxy(proxy any) *Options {
	opt.proxy = proxy
	return opt.addcliMW(func(client *Client) { proxyMW(client, proxy) })
}

// BasicAuth sets the basic authentication credentials for the client.
func (opt *Options) BasicAuth(authentication any) *Options {
	return opt.addreqMW(func(req *Request) error { return basicAuthMW(req, authentication) })
}

// BearerAuth sets the bearer token for the client.
func (opt *Options) BearerAuth(authentication string) *Options {
	return opt.addreqMW(func(req *Request) error { return bearerAuthMW(req, authentication) })
}

// UserAgent sets the user agent for the client.
func (opt *Options) UserAgent(userAgent any) *Options {
	return opt.addreqMW(func(req *Request) error { return userAgentMW(req, userAgent) })
}

// ContentType sets the content type for the client.
func (opt *Options) ContentType(contentType string) *Options {
	return opt.addreqMW(func(req *Request) error { return contentTypeMW(req, contentType) })
}

// CacheBody configures whether the client should cache the body of the response.
func (opt *Options) CacheBody(enable ...bool) *Options {
	if len(enable) != 0 {
		opt.cacheBody = enable[0]
	} else {
		opt.cacheBody = true
	}

	return opt
}

// GetRemoteAddress configures whether the client should get the remote address.
func (opt *Options) GetRemoteAddress() *Options { return opt.addreqMW(remoteAddrMW) }

// DisableKeepAlive disable keep-alive connections.
func (opt *Options) DisableKeepAlive() *Options { return opt.addcliMW(disableKeepAliveMW) }

// DisableCompression disables compression for the HTTP client.
func (opt *Options) DisableCompression() *Options { return opt.addcliMW(disableCompressionMW) }

// Retry configures the retry behavior of the client.
//
// Parameters:
//
//	retryMax: Maximum number of retries to be attempted.
//	retryWait: Duration to wait between retries.
//	codes: Optional list of HTTP status codes that trigger retries.
//	       If no codes are provided, default codes will be used
//	       (500, 429, 503 - Internal Server Error, Too Many Requests, Service Unavailable).
func (opt *Options) Retry(retryMax int, retryWait time.Duration, codes ...int) *Options {
	opt.retryMax = retryMax
	opt.retryWait = retryWait

	if len(codes) == 0 {
		opt.retryCodes = g.SliceOf(http.StatusInternalServerError, http.StatusTooManyRequests, http.StatusServiceUnavailable)
	} else {
		opt.retryCodes = g.SliceOf(codes...)
	}

	return opt
}

// History configures whether the client should keep a history of requests (for debugging purposes
// only).
// WARNING: use only for debugging, not in async mode, no concurrency safe!!!
func (opt *Options) History() *Options {
	opt.history = true
	return opt.addcliMW(redirectPolicyMW)
}

// ForceHTTP1MW configures the client to use HTTP/1.1 forcefully.
func (opt *Options) ForceHTTP1() *Options {
	opt.forseHTTP1 = true
	return opt.addcliMW(forseHTTP1MW)
}

// Session configures whether the client should maintain a session.
func (opt *Options) Session() *Options { return opt.addcliMW(sessionMW) }

// MaxRedirects sets the maximum number of redirects the client should follow.
func (opt *Options) MaxRedirects(maxRedirects int) *Options {
	opt.maxRedirects = maxRedirects
	return opt.addcliMW(redirectPolicyMW)
}

// FollowOnlyHostRedirects configures whether the client should only follow redirects within the
// same host.
func (opt *Options) FollowOnlyHostRedirects() *Options {
	opt.followOnlyHostRedirects = true
	return opt.addcliMW(redirectPolicyMW)
}

// ForwardHeadersOnRedirect adds a middleware to the Options object that ensures HTTP headers are
// forwarded during a redirect.
func (opt *Options) ForwardHeadersOnRedirect() *Options {
	opt.forwardHeadersOnRedirect = true
	return opt.addcliMW(redirectPolicyMW)
}

// RedirectPolicy sets a custom redirect policy for the client.
func (opt *Options) RedirectPolicy(f func(*http.Request, []*http.Request) error) *Options {
	opt.checkRedirect = f
	return opt.addcliMW(redirectPolicyMW)
}

// String generate a string representation of the Options instance.
func (opt Options) String() string { return fmt.Sprintf("%#v", opt) }
