package surf

import (
	"fmt"

	"gitlab.com/x0xO/http"
)

func closeIdleConnectionsMW(r *Response) error { r.cli.CloseIdleConnections(); return nil }

func webSocketUpgradeErrorMW(r *Response) error {
	if r.StatusCode == http.StatusSwitchingProtocols && r.Headers.Get("Upgrade") == "websocket" {
		return fmt.Errorf(
			"%s \"%s\" error: received unexpected response, switching protocols to WebSocket",
			r.request.request.Method,
			r.URL.String(),
		)
	}

	return nil
}
