package surf

import "time"

const (
	_userAgent           = "surf-http-client/6.6.6 (+https://gitlab.com/x0xO/surf)" // User agent string for the HTTP client.
	_maxRedirects        = 10                                                       // Maximum number of redirects allowed for requests.
	_maxWorkers          = 10                                                       // Maximum number of workers for concurrent requests.
	_dialerTimeout       = 30 * time.Second                                         // Timeout duration for the dialer when establishing connections.
	_clientTimeout       = 30 * time.Second                                         // Timeout duration for the HTTP client.
	_TCPKeepAlive        = 15 * time.Second                                         // TCP keep-alive duration for established connections.
	_idleConnTimeout     = 20 * time.Second                                         // Idle connection timeout duration.
	_maxIdleConns        = 512                                                      // Maximum number of idle connections.
	_maxConnsPerHost     = 128                                                      // Maximum number of connections per host.
	_maxIdleConnsPerHost = 128                                                      // Maximum number of idle connections per host.
)
