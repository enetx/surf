package profiles

import "time"

// ConnectionRacingInfo describes the current origin and its client's transport
// session. It does not include persisted browser history or OS network changes.
type ConnectionRacingInfo struct {
	// Origin is the HTTPS origin whose connections are being prepared.
	Origin string
	// QUICWorked reports a confirmed QUIC handshake for this origin.
	QUICWorked bool
	// QUICWorkedInClient reports a confirmed QUIC handshake to any origin in
	// this client's HTTP/3 transport. Independent clients do not share it;
	// closing idle connections retains it. It is not an OS network probe.
	QUICWorkedInClient bool
	// SmoothedRTT is the measured QUIC RTT for this origin, when available.
	SmoothedRTT time.Duration
	// LastQUICError is the most recent non-cancellation preparation failure
	// for this origin. A later confirmed preparation clears it.
	LastQUICError error
}

// ConnectionRacingPolicy selects the TCP backup delay. It must return a
// nonnegative duration promptly and be safe for concurrent calls.
type ConnectionRacingPolicy func(ConnectionRacingInfo) time.Duration
