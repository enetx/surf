package tlsstate

import (
	"crypto/sha256"
	"crypto/tls"
	"time"

	utls "github.com/enetx/utls"
)

// SessionInfo reads metadata through the public Go/uTLS serialization bridge.
// TLS retains validation of the ticket, certificates, ALPN and cryptography.
func SessionInfo(session *tls.ClientSessionState) (uint16, time.Time, time.Time, [32]byte, bool) {
	if session == nil {
		return 0, time.Time{}, time.Time{}, [32]byte{}, false
	}
	ticket, state, err := session.ResumptionState()
	if err != nil || state == nil || len(ticket) == 0 {
		return 0, time.Time{}, time.Time{}, [32]byte{}, false
	}
	data, err := state.Bytes()
	if err != nil {
		return 0, time.Time{}, time.Time{}, [32]byte{}, false
	}
	decoded, err := utls.ParseSessionState(data)
	if err != nil {
		return 0, time.Time{}, time.Time{}, [32]byte{}, false
	}
	converted, err := utls.NewResumptionState(ticket, decoded)
	if err != nil || len(converted.ServerCertificates()) == 0 {
		return 0, time.Time{}, time.Time{}, [32]byte{}, false
	}
	certificate := converted.ServerCertificates()[0]
	until := certificate.NotAfter
	if converted.Vers() == tls.VersionTLS13 {
		if converted.UseBy() == 0 || converted.UseBy() > 1<<63-1 {
			return 0, time.Time{}, time.Time{}, [32]byte{}, false
		}
		if expiry := time.Unix(int64(converted.UseBy()), 0); expiry.Before(until) {
			until = expiry
		}
	}
	return converted.Vers(), certificate.NotBefore, until, sha256.Sum256(ticket), true
}
