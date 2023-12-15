package surf

import (
	"context"
	"crypto/tls"
	"math/rand"
	"net"
	"net/url"
	"time"

	"gitlab.com/x0xO/http"
	"gitlab.com/x0xO/http/cookiejar"
	"gitlab.com/x0xO/http2"
)

// default dialer for surf.
func defaultDialerMW(client *Client) {
	client.dialer = &net.Dialer{Timeout: _dialerTimeout, KeepAlive: _TCPKeepAlive}
}

// default tlsConfig for surf.
func defaultTLSConfigMW(client *Client) {
	client.tlsConfig = &tls.Config{InsecureSkipVerify: true}
}

// default transport for surf.
func defaultTransportMW(client *Client) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = client.dialer.DialContext
	transport.TLSClientConfig = client.tlsConfig
	transport.MaxIdleConns = _maxIdleConns
	transport.MaxConnsPerHost = _maxConnsPerHost
	transport.MaxIdleConnsPerHost = _maxIdleConnsPerHost
	transport.IdleConnTimeout = _idleConnTimeout
	transport.ForceAttemptHTTP2 = true

	client.transport = transport
}

// default client for surf.
func defaultClientMW(client *Client) {
	client.cli = &http.Client{Transport: client.transport, Timeout: _clientTimeout}
}

// forceHTTP1MW configures the client to use HTTP/1.1 forcefully.
func forseHTTP1MW(client *Client) {
	transport := client.GetTransport().(*http.Transport)
	transport.ForceAttemptHTTP2 = false
	transport.TLSClientConfig.NextProtos = []string{"http/1.1"}
}

// sessionMW configures the client's cookie jar to enable session handling.
func sessionMW(client *Client) { client.GetClient().Jar, _ = cookiejar.New(nil) }

// disableKeepAliveMW disables the keep-alive setting for the client's transport.
func disableKeepAliveMW(client *Client) {
	client.GetTransport().(*http.Transport).DisableKeepAlives = true
}

// disableCompressionMW disables compression for the client's transport.
func disableCompressionMW(client *Client) {
	client.GetTransport().(*http.Transport).DisableCompression = true
}

// interfaceAddrMW configures the client's local address for dialing based on the provided
// options.
func interfaceAddrMW(client *Client, address string) error {
	if address != "" {
		ip, err := net.ResolveTCPAddr("tcp", address+":0")
		if err != nil {
			return err
		}

		client.GetDialer().LocalAddr = ip
	}

	return nil
}

// timeoutMW configures the client's timeout setting based on the provided options.
func timeoutMW(client *Client, timeout time.Duration) error {
	client.GetClient().Timeout = timeout
	return nil
}

// redirectPolicyMW configures the client's redirect policy based on the
// provided options.
func redirectPolicyMW(client *Client) {
	opt := client.opt
	maxRedirects := _maxRedirects

	if opt != nil {
		if opt.checkRedirect != nil {
			client.GetClient().CheckRedirect = opt.checkRedirect
			return
		}

		if opt.maxRedirects != 0 {
			maxRedirects = opt.maxRedirects
		}
	}

	client.GetClient().CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return http.ErrUseLastResponse
		}

		if opt != nil {
			if opt.followOnlyHostRedirects {
				newHost := req.URL.Host
				oldHost := via[0].Host

				if oldHost == "" {
					oldHost = via[0].URL.Host
				}

				if newHost != oldHost {
					return http.ErrUseLastResponse
				}
			}

			if opt.forwardHeadersOnRedirect {
				for key, val := range via[0].Header {
					req.Header[key] = val
				}
			}
		}

		return nil
	}
}

// dnsMW sets the DNS for client.
func dnsMW(client *Client, dns string) {
	client.GetDialer().Resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "udp", dns)
		},
	}
}

// dnsTLSMW sets up a DNS over TLS for client.
func dnsTLSMW(client *Client, resolver *net.Resolver) { client.GetDialer().Resolver = resolver }

// configureUnixSocket sets the DialContext function for the client's HTTP transport to use
// a Unix domain socket if the unixDomainSocket option is set.
func unixDomainSocketMW(client *Client, unixDomainSocket string) {
	if unixDomainSocket == "" {
		return
	}

	client.GetTransport().(*http.Transport).DialContext = func(_ context.Context, _, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}

		unixaddr, err := net.ResolveUnixAddr(host, unixDomainSocket)
		if err != nil {
			return nil, err
		}

		return net.DialUnix(host, nil, unixaddr)
	}
}

// proxyMW configures the request's proxy settings based on the provided
// proxy options. It supports single or multiple proxy options.
func proxyMW(client *Client, proxys any) {
	if client.opt.ja3 {
		return
	}

	var proxy string

	switch pr := proxys.(type) {
	case string:
		if pr == "" {
			client.GetTransport().(*http.Transport).Proxy = func(*http.Request) (*url.URL, error) { return nil, nil }
			return
		}
		proxy = pr
	case []string:
		proxy = pr[rand.Intn(len(pr))]
	}

	proxyURL, _ := url.Parse(proxy)
	client.GetTransport().(*http.Transport).Proxy = http.ProxyURL(proxyURL)
}

func h2cMW(client *Client) {
	t2 := new(http2.Transport)

	t2.AllowHTTP = true
	t2.DisableCompression = client.GetTransport().(*http.Transport).DisableCompression
	t2.IdleConnTimeout = client.transport.(*http.Transport).IdleConnTimeout

	t2.DialTLSContext = func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
		return net.Dial(network, addr)
	}

	if client.opt.http2s != nil {
		h := client.opt.http2s

		appendSetting := func(id http2.SettingID, val uint32) {
			if val != 0 || (id == http2.SettingEnablePush && h.usePush) {
				t2.Settings = append(t2.Settings, http2.Setting{ID: id, Val: val})
			}
		}

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
}
