package desktop

import (
	"github.com/enetx/surf/profiles"
	"github.com/enetx/surf/profiles/firefox/common"
)

// ConfigureH3 applies Firefox desktop HTTP/3 settings.
func ConfigureH3(h profiles.H3Config) {
	// Keep the backup timer active while a transaction sends 0-RTT.
	// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/netwerk/protocol/http/nsHttpTransaction.cpp#L3935
	h.EarlyDataBackup(true).
		// Neqo resets protocol streams and Firefox requeues transactions on
		// the existing connection after verified TLS completes.
		// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/netwerk/protocol/http/Http3Session.cpp
		EarlyDataRestart(true)

	// Firefox waits for HTTPS RR when ECH is enabled, without Chromium's
	// supplemental timer after address resolution.
	// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/netwerk/protocol/http/nsHttpConnectionMgr.cpp#L1760
	h.Discovery(true).HTTPSRecordsWait(nil).
		AlternativeServiceBackoff(common.AlternativeServiceBackoff).ExpireFailedAlternatives(true)
	h.AltUsed(true).
		ConnectionRacingPolicy(common.ConnectionRacing).
		QpackMaxTableCapacity(65536).
		QpackBlockedStreams(20).
		EnableWebtransport(0).
		H3Datagram(1).
		SettingsH3Datagram(1).
		EnableConnectProtocol(1)
}
