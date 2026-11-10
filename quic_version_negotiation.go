package surf

// CompatibleVersionNegotiation enables authenticated v1/v2 switching within a
// handshake (RFC 9368/9369). Versions lists the permitted versions; a custom
// transport-parameter layout can select their preference and GREASE ordering.
// Firefox enables this mechanism by default. Native clients keep it disabled.
func (q *QUICSettings) CompatibleVersionNegotiation(enabled bool) *QUICSettings {
	q.handshake().CompatibleVersionNegotiation = enabled
	return q
}
