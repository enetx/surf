package surf

import (
	"errors"

	"gitlab.com/x0xO/http"
)

func clearCachedTransportsMW(_ *Response) error {
	cachedTransports.Range(func(key, _ any) bool { cachedTransports.Delete(key); return true })
	return nil
}

func webSocketUpgradeErrorMW(r *Response) error {
	if r.StatusCode == http.StatusSwitchingProtocols && r.Headers.Get("Upgrade") == "websocket" {
		return errors.New("received unexpected response: switching protocols to WebSocket")
	}

	return nil
}
