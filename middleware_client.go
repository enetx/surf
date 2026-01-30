package surf

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"maps"
	"net"
	"strconv"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/http/cookiejar"
	"github.com/enetx/http2"
	"github.com/enetx/surf/pkg/connectproxy"
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
	transport := &http.Transport{
		DialContext:           client.dialer.DialContext,
		DisableCompression:    true,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
		IdleConnTimeout:       _idleConnTimeout,
		MaxConnsPerHost:       _maxConnsPerHost,
		MaxIdleConns:          _maxIdleConns,
		MaxIdleConnsPerHost:   _maxIdleConnsPerHost,
		Proxy:                 http.ProxyFromEnvironment,
		ResponseHeaderTimeout: _responseHeaderTimeout,
		TLSClientConfig:       client.tlsConfig,
		TLSHandshakeTimeout:   _tlsHandshakeTimeout,
	}

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

// forseHTTP2MW configures the client to use HTTP/2 forcefully.
// Disables HTTP/1.1 and forces the client to use only HTTP/2 protocol.
func forseHTTP2MW(client *Client) error {
	transport := client.GetTransport().(*http.Transport)
	transport.Protocols = new(http.Protocols)
	transport.Protocols.SetHTTP2(true)
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

// interfaceAddrMW configures the client's local network interface address for outbound connections.
// Accepts either an IP address (e.g., "192.168.1.100", "::1") or an interface name (e.g., "eth0").
func interfaceAddrMW(client *Client, address g.String) error {
	if address.IsEmpty() {
		return errors.New("interface address is empty")
	}

	addr := address.Std()

	// Try to parse as IP first
	if ip := net.ParseIP(addr); ip != nil {
		client.GetDialer().LocalAddr = &net.TCPAddr{IP: ip}
		return nil
	}

	iface, err := net.InterfaceByName(addr)
	if err != nil {
		return fmt.Errorf("invalid interface %q: not an IP or interface name", address)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return fmt.Errorf("get addresses for interface %q: %w", address, err)
	}

	if len(addrs) == 0 {
		return fmt.Errorf("interface %q has no addresses", address)
	}

	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.To4() != nil {
			client.GetDialer().LocalAddr = &net.TCPAddr{IP: ipnet.IP}
			return nil
		}
	}

	if ipnet, ok := addrs[0].(*net.IPNet); ok {
		client.GetDialer().LocalAddr = &net.TCPAddr{IP: ipnet.IP}
		return nil
	}

	return fmt.Errorf("no usable address for interface %q", address)
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
	if dns.IsEmpty() {
		return errors.New("DNS address is empty")
	}

	host, port, err := net.SplitHostPort(dns.Std())
	if err != nil {
		return fmt.Errorf("invalid DNS address %q: %w", dns, err)
	}

	if host == "" {
		return fmt.Errorf("invalid DNS address %q: empty host", dns)
	}

	if port == "" {
		return fmt.Errorf("invalid DNS address %q: empty port", dns)
	}

	portNum, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("invalid DNS address %q: invalid port", dns)
	}

	if portNum < 1 || portNum > 65535 {
		return fmt.Errorf("invalid DNS address %q: port out of range", dns)
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

// unixSocketMW configures the client to connect via Unix domain sockets.
// Replaces the standard TCP connection with Unix socket communication,
// useful for connecting to local services that expose Unix socket interfaces.
func unixSocketMW(client *Client, address g.String) error {
	if address.IsEmpty() {
		return errors.New("unix socket address is empty")
	}

	transport, ok := client.GetTransport().(*http.Transport)
	if !ok {
		return errors.New("transport is not *http.Transport")
	}

	transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", address.Std())
	}

	return nil
}

// proxyMW configures HTTP proxy settings for the client transport.
func proxyMW(client *Client, proxy g.String) error {
	// Skip if HTTP/3 transport is being used (handled separately)
	if _, ok := client.GetTransport().(*uquicTransport); ok {
		return nil
	}

	transport, ok := client.GetTransport().(*http.Transport)
	if !ok {
		return errors.New("transport is not *http.Transport")
	}

	if proxy.IsEmpty() {
		transport.Proxy = nil
		return nil
	}

	dialer, err := connectproxy.NewDialer(proxy.Std())
	if err != nil {
		return fmt.Errorf("create proxy dialer: %w", err)
	}

	// Pass custom DNS resolver to proxy dialer if configured.
	// This ensures DNS queries go through the custom DNS server, not through the proxy.
	// Target hostnames are pre-resolved locally before being sent to the proxy.
	if client.dialer != nil && client.dialer.Resolver != nil {
		dialer.SetResolver(client.dialer.Resolver)
	}

	transport.DialContext = dialer.DialContext

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
	t2.DialTLSContext = func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}

	// Apply HTTP/2 settings if configured
	if client.builder.http2settings != nil {
		h := client.builder.http2settings

		// Pre-allocate settings slice to avoid multiple allocations
		t2.Settings = make([]http2.Setting, 0, 7)

		// Helper function to append non-zero settings
		appendSetting := func(id http2.SettingID, val uint32) {
			if val != 0 || (id == http2.SettingEnablePush && h.usePush) {
				t2.Settings = append(t2.Settings, http2.Setting{ID: id, Val: val})
			}
		}

		appendSetting(http2.SettingHeaderTableSize, h.headerTableSize)
		appendSetting(http2.SettingEnablePush, h.enablePush)
		appendSetting(http2.SettingMaxConcurrentStreams, h.maxConcurrentStreams)
		appendSetting(http2.SettingInitialWindowSize, h.initialWindowSize)
		appendSetting(http2.SettingMaxFrameSize, h.maxFrameSize)
		appendSetting(http2.SettingMaxHeaderListSize, h.maxHeaderListSize)
		appendSetting(http2.SettingNoRFC7540Priorities, h.noRFC7540Priorities)

		if h.initialStreamID != 0 {
			t2.StreamID = h.initialStreamID
		}

		if h.connectionFlow != 0 {
			t2.ConnectionFlow = h.connectionFlow
		}

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
