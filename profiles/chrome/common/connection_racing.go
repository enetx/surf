package common

import (
	"time"

	"github.com/enetx/surf/profiles"
)

// ConnectionRacing follows GetTimeDelayForWaitingJob's session-wide support gate
// and per-server RTT, with the reference Chromium desktop trial's 50ms addition
// and MaybeSetWaitTimeForMainJob's total cap. Surf retains support within one
// client; persisted local addresses, OS network changes and browser job scheduling
// remain outside this callback.
// https://github.com/chromium/chromium/blob/158.0.8127.18/net/quic/quic_session_pool.cc
// https://github.com/chromium/chromium/blob/158.0.8127.18/net/http/http_stream_factory_job_controller.cc
// https://github.com/chromium/chromium/blob/158.0.8127.18/testing/variations/fieldtrial_testing_config.json
func ConnectionRacing(info profiles.ConnectionRacingInfo) time.Duration {
	return connectionRacingDelay(info, 50*time.Millisecond)
}

// ConnectionRacingAndroid includes the Android default additional main-job delay.
// https://github.com/chromium/chromium/blob/158.0.8127.18/net/base/features.cc
func ConnectionRacingAndroid(info profiles.ConnectionRacingInfo) time.Duration {
	return connectionRacingDelay(info, 100*time.Millisecond)
}

func connectionRacingDelay(info profiles.ConnectionRacingInfo, additional time.Duration) time.Duration {
	if (!info.QUICWorked && !info.QUICWorkedInClient) || info.LastQUICError != nil {
		return 0
	}

	// Check before multiplying, including durations near the time.Duration
	// limit. Chromium's controller caps the total, including Android's delay.
	if info.SmoothedRTT >= 2*time.Second {
		return 3 * time.Second
	}

	delay := 300 * time.Millisecond
	if info.SmoothedRTT > 0 {
		micros := info.SmoothedRTT.Microseconds()
		delay = time.Duration(micros+micros/2) * time.Microsecond
		if delay == 0 {
			delay = 300 * time.Millisecond
		}
	}

	return min(delay+additional, 3*time.Second)
}
