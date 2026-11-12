package quictls

import (
	"crypto/tls"
	"time"

	"github.com/enetx/surf/internal/tlsstate"
)

// SessionLifetime uses the public serialization bridge and requires TLS 1.3:
// QUIC session selection must not consume a TCP TLS 1.2 ticket.
func SessionLifetime(session *tls.ClientSessionState) (time.Time, time.Time, bool) {
	version, from, until, _, ok := tlsstate.SessionInfo(session)
	return from, until, ok && version == tls.VersionTLS13
}
