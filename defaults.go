package surf

import "time"

// Default configuration constants for the surf HTTP client.
// These values provide sensible defaults for connection management, timeouts, and client behavior.
const (
	// _userAgent is the default User-Agent header for HTTP requests.
	// Uses a modern Chrome browser signature to ensure compatibility with most web services.
	_userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"

	// _maxRedirects is the default maximum number of redirects to follow.
	// Prevents infinite redirect loops while allowing reasonable redirect chains.
	_maxRedirects = 10

	// HTTP/1.1 Transport timeouts

	// _dialerTimeout is the default timeout for establishing network connections.
	// Prevents hanging on unresponsive servers during connection establishment.
	_dialerTimeout = 10 * time.Second

	// _tlsHandshakeTimeout is the default timeout for completing TLS handshakes.
	// Prevents hanging during SSL/TLS negotiation with slow or unresponsive servers.
	_tlsHandshakeTimeout = 10 * time.Second

	// _responseHeaderTimeout is the default timeout for reading response headers.
	// Prevents hanging while waiting for server to send response headers after request is sent.
	_responseHeaderTimeout = 10 * time.Second

	// _clientTimeout is the default overall timeout for complete HTTP requests.
	// Includes connection time, request transmission, and response reading.
	_clientTimeout = 30 * time.Second

	// HTTP/1.1 Connection pooling

	// _TCPKeepAlive is the default TCP keep-alive interval for established connections.
	// Maintains connection health and detects broken connections.
	_TCPKeepAlive = 15 * time.Second

	// _idleConnTimeout is the default timeout for idle connections in the pool.
	// Prevents resource leaks by closing stale connections.
	_idleConnTimeout = 20 * time.Second

	// _maxIdleConns is the default maximum number of idle connections across all hosts.
	// Controls overall connection pool size and memory usage.
	_maxIdleConns = 512

	// _maxConnsPerHost is the default maximum number of connections per individual host.
	// Prevents overwhelming any single server with too many concurrent connections.
	_maxConnsPerHost = 128

	// _maxIdleConnsPerHost is the default maximum number of idle connections per host.
	// Maintains connection efficiency while controlling per-host resource usage.
	_maxIdleConnsPerHost = 128

	// HTTP/2 Transport timeouts

	// _http2ReadIdleTimeout is the timeout for idle reads in HTTP/2 connections.
	// If no data is received within this time, the connection may be considered stale.
	// This prevents hanging on servers that stop sending data without closing the connection.
	_http2ReadIdleTimeout = 10 * time.Second

	// _http2PingTimeout is the timeout for HTTP/2 PING frame responses.
	// HTTP/2 uses PING frames to verify connection liveness.
	// If server doesn't respond to PING within this time, connection is considered dead.
	_http2PingTimeout = 10 * time.Second

	// _http2WriteByteTimeout is the timeout for writing individual bytes in HTTP/2 streams.
	// Prevents hanging on slow or stalled write operations.
	// Set to 0 to disable (no timeout for writes).
	_http2WriteByteTimeout = 10 * time.Second

	// Port defaults

	// defaultHTTPPort is the implicit port for plain HTTP URLs without an explicit port.
	defaultHTTPPort = "80"

	// defaultHTTPSPort is the implicit port for HTTPS (TLS) URLs without an explicit port.
	defaultHTTPSPort = "443"
)
