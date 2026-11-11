package common

import (
	"time"

	"github.com/enetx/surf/profiles"
)

// ConnectionRacing follows GetTimeDelayForWaitingJob's RTT component. Surf's
// observations are per origin/client; persistent network state, experiment flags
// and browser Alt-Svc brokenness/backoff are not reproduced by this callback.
// https://github.com/chromium/chromium/blob/157.0.8103.51/net/quic/quic_session_pool.cc
func ConnectionRacing(info profiles.ConnectionRacingInfo) time.Duration {
	if !info.QUICWorked || info.LastQUICError != nil {
		return 0
	}
	if info.SmoothedRTT <= 0 {
		return 300 * time.Millisecond
	}
	return info.SmoothedRTT + info.SmoothedRTT/2
}

// ConnectionRacingAndroid includes the Android default additional main-job delay.
// https://github.com/chromium/chromium/blob/157.0.8103.51/net/base/features.cc
func ConnectionRacingAndroid(info profiles.ConnectionRacingInfo) time.Duration {
	if !info.QUICWorked || info.LastQUICError != nil {
		return 0
	}
	return ConnectionRacing(info) + 100*time.Millisecond
}
