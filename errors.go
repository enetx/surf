package surf

import "fmt"

// Custom error types for surf HTTP client operations.
// These errors provide specific information about different failure scenarios
// that can occur during HTTP requests and responses.

type (
	// ErrWebSocketUpgrade indicates that a request received a WebSocket upgrade response.
	// This error is returned when the server responds with HTTP 101 Switching Protocols
	// for WebSocket connections, which require special handling.
	ErrWebSocketUpgrade struct{ Msg string }

	// ErrUserAgentType indicates an invalid user agent type was provided.
	// This error is returned when the user agent parameter is not of a supported type
	// (string, g.String, slices, etc.).
	ErrUserAgentType struct{ Msg string }

	// Err101ResponseCode indicates a 101 Switching Protocols response was received.
	// This error is used to handle HTTP 101 responses that require protocol upgrades.
	Err101ResponseCode struct{ Msg string }

	// ErrHTTP2Fallback indicates that an HTTPS request attempted HTTP/2 first,
	// then tried to fall back to HTTP/1.1, but both attempts failed.
	//
	// The wrapped (Unwrap) error is the original HTTP/2 failure so callers don't
	// accidentally treat the overall failure as a timeout coming from the fallback.
	ErrHTTP2Fallback struct {
		HTTP2 error
		HTTP1 error
	}
)

func (e *ErrWebSocketUpgrade) Error() string {
	return fmt.Sprintf("%s received an unexpected response, switching protocols to WebSocket", e.Msg)
}

func (e *ErrUserAgentType) Error() string {
	return fmt.Sprintf("unsupported user agent type: %s", e.Msg)
}

func (e *Err101ResponseCode) Error() string {
	return fmt.Sprintf("%s received a 101 response status code", e.Msg)
}

func (e *ErrHTTP2Fallback) Error() string {
	return fmt.Sprintf("surf: HTTP/2 request failed: %v; HTTP/1.1 fallback failed: %v", e.HTTP2, e.HTTP1)
}

func (e *ErrHTTP2Fallback) Unwrap() error { return e.HTTP2 }
