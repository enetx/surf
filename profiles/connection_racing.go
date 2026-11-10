package profiles

import "time"

// ConnectionRacingInfo describes this client's observations for one origin.
// It is not the browser's persistent Alt-Svc, DNS or network-history database.
type ConnectionRacingInfo struct {
	Origin        string
	QUICWorked    bool
	SmoothedRTT   time.Duration
	LastQUICError error
}

// ConnectionRacingPolicy selects the TCP backup delay. It must return a
// nonnegative duration promptly and be safe for concurrent calls.
type ConnectionRacingPolicy func(ConnectionRacingInfo) time.Duration
