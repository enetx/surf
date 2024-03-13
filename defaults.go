package surf

import "time"

const (
	_userAgent           = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36" // User agent string for the HTTP client.
	_maxRedirects        = 10                                                                                                                // Maximum number of redirects allowed for requests.
	_maxWorkers          = 10                                                                                                                // Maximum number of workers for concurrent requests.
	_dialerTimeout       = 30 * time.Second                                                                                                  // Timeout duration for the dialer when establishing connections.
	_clientTimeout       = 30 * time.Second                                                                                                  // Timeout duration for the HTTP client.
	_TCPKeepAlive        = 15 * time.Second                                                                                                  // TCP keep-alive duration for established connections.
	_idleConnTimeout     = 20 * time.Second                                                                                                  // Idle connection timeout duration.
	_maxIdleConns        = 512                                                                                                               // Maximum number of idle connections.
	_maxConnsPerHost     = 128                                                                                                               // Maximum number of connections per host.
	_maxIdleConnsPerHost = 128                                                                                                               // Maximum number of idle connections per host.
)
