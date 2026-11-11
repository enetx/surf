package android

import (
	"github.com/enetx/surf/profiles"
	"github.com/enetx/surf/profiles/chrome/common"
	"github.com/enetx/surf/profiles/chrome/quic"
)

// ConfigureH3 applies Chrome Android HTTP/3 settings.
func ConfigureH3(h profiles.H3Config) {
	// A session can win at early encryption readiness.
	// https://github.com/chromium/chromium/blob/157.0.8103.51/net/quic/quic_chromium_client_session.cc#L1644
	h.EarlyDataBackup(false)

	h.Discovery(true).HTTPSRecordsWait(common.HTTPSRecordsWait).
		AlternativeServiceBackoff(common.AlternativeServiceBackoff).ExpireFailedAlternatives(false)
	h.QpackMaxTableCapacity(65536).
		ConnectionRacingPolicy(common.ConnectionRacingAndroid).
		MaxFieldSectionSize(262144).
		QpackBlockedStreams(100).
		SettingsH3Datagram(1).
		GreaseFactory(quic.NewSettingsGrease)
}
