package surf

import (
	"context"
	"crypto/tls"
	"fmt"
	"maps"
	"math/rand"
	"net"
	"net/url"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/http/cookiejar"
	"github.com/enetx/http2"
	"golang.org/x/net/publicsuffix"
)

// defaultDialerMW initializes the default network dialer for the surf client.
// Sets up timeout and keep-alive configuration for TCP connections.
func defaultDialerMW(client *Client) error {
	client.dialer = &net.Dialer{Timeout: _dialerTimeout, KeepAlive: _TCPKeepAlive}
	return nil
}

// defaultTLSConfigMW initializes the default TLS configuration for the surf client.
// Configures TLS settings with insecure skip verify enabled by default for flexibility.
func defaultTLSConfigMW(client *Client) error {
	client.tlsConfig = &tls.Config{InsecureSkipVerify: true}
	return nil
}

// defaultTransportMW initializes the default HTTP transport for the surf client.
// Configures connection pooling, timeouts, and enables HTTP/2 support by default.
func defaultTransportMW(client *Client) error {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = client.dialer.DialContext
	transport.TLSClientConfig = client.tlsConfig
	transport.MaxIdleConns = _maxIdleConns
	transport.MaxConnsPerHost = _maxConnsPerHost
	transport.MaxIdleConnsPerHost = _maxIdleConnsPerHost
	transport.IdleConnTimeout = _idleConnTimeout
	transport.ForceAttemptHTTP2 = true

	client.transport = transport

	return nil
}

// defaultClientMW initializes the default HTTP client for the surf client.
// Sets up the HTTP client with the configured transport and timeout settings.
func defaultClientMW(client *Client) error {
	client.cli = &http.Client{Transport: client.transport, Timeout: _clientTimeout}
	return nil
}

// boundaryMW sets a custom boundary function for multipart form data.
// The boundary function is called to generate unique boundaries for multipart requests.
func boundaryMW(client *Client, boundary func() g.String) error {
	client.boundary = boundary
	return nil
}

// forseHTTP1MW configures the client to use HTTP/1.1 forcefully.
// Disables HTTP/2 and forces the client to use only HTTP/1.1 protocol.
func forseHTTP1MW(client *Client) error {
	transport := client.GetTransport().(*http.Transport)
	transport.Protocols = new(http.Protocols)
	transport.Protocols.SetHTTP1(true)
	return nil
}

// sessionMW configures the client's cookie jar for session management.
// It initializes a new cookie jar and sets up the TLS configuration
// to manage client sessions efficiently.
func sessionMW(client *Client) error {
	client.GetClient().Jar, _ = cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	client.GetTLSConfig().ClientSessionCache = tls.NewLRUClientSessionCache(0)
	return nil
}

// disableKeepAliveMW disables the keep-alive setting for the client's transport.
func disableKeepAliveMW(client *Client) error {
	client.GetTransport().(*http.Transport).DisableKeepAlives = true
	return nil
}

// disableCompressionMW disables compression for the client's transport.
func disableCompressionMW(client *Client) error {
	client.GetTransport().(*http.Transport).DisableCompression = true
	return nil
}

// interfaceAddrMW configures the client's local network interface address for outbound connections.
// This allows binding the client to a specific network interface or IP address for dialing.
// Useful for systems with multiple network interfaces or for controlling which IP address to use.
func interfaceAddrMW(client *Client, address g.String) error {
	if address != "" {
		ip, err := net.ResolveTCPAddr("tcp", address.Std()+":0")
		if err != nil {
			return err
		}

		client.GetDialer().LocalAddr = ip
	}

	return nil
}

// timeoutMW configures the client's overall request timeout.
// This sets the maximum duration for entire HTTP requests including connection,
// request transmission, and response reading.
func timeoutMW(client *Client, timeout time.Duration) error {
	client.GetClient().Timeout = timeout
	return nil
}

// redirectPolicyMW configures the client's HTTP redirect handling behavior.
// Sets up redirect policies including maximum redirect count, host-only redirects,
// header forwarding on redirects, and custom redirect functions.
func redirectPolicyMW(client *Client) error {
	builder := client.builder
	maxRedirects := _maxRedirects

	if builder != nil {
		// Use custom redirect function if provided
		if builder.checkRedirect != nil {
			client.GetClient().CheckRedirect = builder.checkRedirect
			return nil
		}

		// Override default max redirects if specified
		if builder.maxRedirects != 0 {
			maxRedirects = builder.maxRedirects
		}
	}

	// Set up default redirect policy with configured behavior
	client.GetClient().CheckRedirect = func(req *http.Request, via []*http.Request) error {
		// Stop redirecting if maximum redirect count is exceeded
		if len(via) >= maxRedirects {
			return http.ErrUseLastResponse
		}

		if builder != nil {
			// Only follow redirects within the same host if configured
			if builder.followOnlyHostRedirects {
				newHost := req.URL.Host
				oldHost := via[0].Host

				if oldHost == "" {
					oldHost = via[0].URL.Host
				}

				if newHost != oldHost {
					return http.ErrUseLastResponse
				}
			}

			// Forward headers from original request to redirect if configured
			if builder.forwardHeadersOnRedirect {
				maps.Copy(req.Header, via[0].Header)
			}
		}

		return nil
	}

	return nil
}

// dnsMW configures a custom DNS server for the client.
// Sets up the client to use the specified DNS server address for hostname resolution
// instead of the system's default DNS configuration.
func dnsMW(client *Client, dns g.String) error {
	if dns.Empty() {
		return nil
	}

	client.GetDialer().Resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "udp", dns.Std())
		},
	}

	return nil
}

// dnsTLSMW configures DNS over TLS (DoT) for the client.
// Replaces the default DNS resolver with a secure DNS-over-TLS resolver
// to encrypt DNS queries and protect against DNS manipulation.
func dnsTLSMW(client *Client, resolver *net.Resolver) error {
	client.GetDialer().Resolver = resolver
	return nil
}

// unixDomainSocketMW configures the client to connect via Unix domain sockets.
// Replaces the standard TCP connection with Unix socket communication,
// useful for connecting to local services that expose Unix socket interfaces.
func unixDomainSocketMW(client *Client, unixDomainSocket g.String) error {
	if unixDomainSocket.Empty() {
		return nil
	}

	client.GetTransport().(*http.Transport).DialContext = func(_ context.Context, _, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}

		unixaddr, err := net.ResolveUnixAddr(host, unixDomainSocket.Std())
		if err != nil {
			return nil, err
		}

		return net.DialUnix(host, nil, unixaddr)
	}

	return nil
}

// proxyMW configures HTTP proxy settings for the client transport.
// Supports both static proxy configurations (string URLs) and dynamic proxy providers
// (functions that return proxy URLs for rotation). Handles various proxy types including
// HTTP, HTTPS, and SOCKS proxies. Skips configuration for JA3 and HTTP/3 transports
// which handle proxies differently.
func proxyMW(client *Client, proxys any) error {
	// Skip proxy configuration for JA3 transport (handled separately)
	if client.builder.ja {
		return nil
	}

	// Skip if HTTP/3 transport is being used (handled separately)
	if _, ok := client.GetTransport().(*uquicTransport); ok {
		return nil
	}

	transport := client.GetTransport().(*http.Transport)

	// Clear proxy if nil provided
	if proxys == nil {
		transport.Proxy = nil
		return nil
	}

	// Helper function to set static proxy
	setProxy := func(proxy string) {
		if proxy == "" {
			return
		}
		if proxyURL, err := url.Parse(proxy); err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		} else {
			transport.Proxy = func(*http.Request) (*url.URL, error) {
				return nil, fmt.Errorf("invalid proxy URL %q: %w", proxy, err)
			}
		}
	}

	// Handle static proxy configurations
	switch v := proxys.(type) {
	case string:
		setProxy(v)
		return nil
	case g.String:
		setProxy(v.Std())
		return nil
	}

	// Handle dynamic proxy configurations - evaluate proxy per request
	transport.Proxy = func(*http.Request) (*url.URL, error) {
		var proxy string

		switch v := proxys.(type) {
		case func() g.String:
			proxy = v().Std()
		case []string:
			if len(v) > 0 {
				proxy = v[rand.Intn(len(v))]
			}
		case g.Slice[string]:
			proxy = v.Random()
		case g.Slice[g.String]:
			proxy = v.Random().Std()
		default:
			return nil, fmt.Errorf("unsupported proxy type: %T", proxys)
		}

		if proxy == "" {
			return nil, nil
		}

		return url.Parse(proxy)
	}

	return nil
}

// h2cMW configures HTTP/2 Cleartext (H2C) support for the client.
// H2C allows HTTP/2 communication over plain text connections without TLS.
// This is useful for internal communication or development scenarios where TLS is not required.
// Skips configuration if HTTP/3 transport is being used as they are incompatible.
func h2cMW(client *Client) error {
	// H2C is incompatible with HTTP/3 transport - skip if HTTP/3 is being used
	if _, ok := client.transport.(*uquicTransport); ok {
		return nil
	}

	t2 := new(http2.Transport)

	// Configure H2C specific settings
	t2.AllowHTTP = true
	t2.DisableCompression = client.GetTransport().(*http.Transport).DisableCompression
	t2.IdleConnTimeout = client.transport.(*http.Transport).IdleConnTimeout

	// Override TLS dial to use plain text connections
	t2.DialTLSContext = func(_ context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
		return net.Dial(network, addr)
	}

	// Apply HTTP/2 settings if configured
	if client.builder.http2settings != nil {
		h := client.builder.http2settings

		// Helper function to append non-zero settings
		appendSetting := func(id http2.SettingID, val uint32) {
			if val != 0 || (id == http2.SettingEnablePush && h.usePush) {
				t2.Settings = append(t2.Settings, http2.Setting{ID: id, Val: val})
			}
		}

		// Apply all configured HTTP/2 settings
		settings := [...]struct {
			id  http2.SettingID
			val uint32
		}{
			{http2.SettingHeaderTableSize, h.headerTableSize},
			{http2.SettingEnablePush, h.enablePush},
			{http2.SettingMaxConcurrentStreams, h.maxConcurrentStreams},
			{http2.SettingInitialWindowSize, h.initialWindowSize},
			{http2.SettingMaxFrameSize, h.maxFrameSize},
			{http2.SettingMaxHeaderListSize, h.maxHeaderListSize},
		}

		for _, s := range settings {
			appendSetting(s.id, s.val)
		}

		// Apply flow control settings if configured
		if h.connectionFlow != 0 {
			t2.ConnectionFlow = h.connectionFlow
		}

		// Apply priority settings if configured
		if !h.priorityParam.IsZero() {
			t2.PriorityParam = h.priorityParam
		}

		if h.priorityFrames != nil {
			t2.PriorityFrames = h.priorityFrames
		}
	}

	client.cli.Transport = t2

	return nil
}
