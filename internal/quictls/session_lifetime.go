package quictls

import (
	"crypto/tls"
	"time"

	utls "github.com/enetx/utls"
)

// SessionLifetime uses the same public Go/uTLS serialization bridge as the
// session cache. It never inspects crypto/tls's private memory or encoding.
func SessionLifetime(session *tls.ClientSessionState) (time.Time, time.Time, bool) {
	if session == nil {
		return time.Time{}, time.Time{}, false
	}
	ticket, state, err := session.ResumptionState()
	if err != nil || state == nil || len(ticket) == 0 {
		return time.Time{}, time.Time{}, false
	}
	encoded, err := state.Bytes()
	if err != nil {
		return time.Time{}, time.Time{}, false
	}
	decoded, err := utls.ParseSessionState(encoded)
	if err != nil {
		return time.Time{}, time.Time{}, false
	}
	converted, err := utls.NewResumptionState(ticket, decoded)
	if err != nil || converted.UseBy() == 0 || converted.UseBy() > 1<<63-1 {
		return time.Time{}, time.Time{}, false
	}
	certificates := converted.ServerCertificates()
	if len(certificates) == 0 {
		return time.Time{}, time.Time{}, false
	}
	return certificates[0].NotBefore,
		minTime(certificates[0].NotAfter, time.Unix(int64(converted.UseBy()), 0)), true
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
