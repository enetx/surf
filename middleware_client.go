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
	client.GetTransport().(*http.Transport).TLSNextProto = make(map[string]func(string, *tls.Conn) http.RoundTripper)
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

			if opt.history {
				client.history = append(client.history, req.Response)
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

// dnsCacheMW sets up a DNS cache for client.
func dnsCacheMW(client *Client) { client.cacheDialer() }

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
	if client.opt.useJA3 {
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
