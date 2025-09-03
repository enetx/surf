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
