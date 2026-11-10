package common

import "time"

// AlternativeServiceBackoff follows the default, non-experimental broken-service
// schedule. The first two failures wait five minutes; subsequent ones double.
// https://github.com/chromium/chromium/blob/156.0.8078.79/net/http/broken_alternative_services.cc
// https://github.com/chromium/chromium/blob/156.0.8078.79/net/base/features.cc
func AlternativeServiceBackoff(failures uint32) time.Duration {
	shift := uint32(0)
	if failures > 2 {
		shift = min(failures-2, 18)
	}
	return min(5*time.Minute*time.Duration(uint64(1)<<shift), 48*time.Hour)
}
