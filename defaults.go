package surf

import "time"

// Default configuration constants for the surf HTTP client.
// These values provide sensible defaults for connection management, timeouts, and client behavior.
const (
	// _userAgent is the default User-Agent header for HTTP requests.
	// Identifies requests made by the surf HTTP client library.
	// Can be overridden using Builder.UserAgent() or Impersonate().
	_userAgent = "surf/1.0 (https://github.com/enetx/surf)"

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

	// HTTP/3 (QUIC) Transport timeouts
	// _quicHandshakeTimeout is the timeout for QUIC handshake completion.
	// Similar to TLS handshake timeout but for QUIC protocol.
	_quicHandshakeTimeout = 10 * time.Second

	// _quicMaxIdleTimeout is the maximum time a QUIC connection can remain idle.
	// After this timeout, the connection is closed.
	_quicMaxIdleTimeout = 30 * time.Second

	// _quicKeepAlivePeriod is the interval for QUIC keep-alive pings.
	// Helps maintain connections through NAT and detect dead connections.
	_quicKeepAlivePeriod = 15 * time.Second

	// _maxResponseHeaderBytes is the maximum size of response headers in HTTP/3.
	// Limits memory usage when receiving large headers. Default 10MB.
	_maxResponseHeaderBytes = 10 << 20
)
