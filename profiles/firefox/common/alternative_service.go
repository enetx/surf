package common

import "time"

// AlternativeServiceBackoff follows failed AltSvcMappingValidator validation.
// ExpireFailedAlternatives requires a new advertisement after this interval.
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/netwerk/protocol/http/AlternateServices.cpp
func AlternativeServiceBackoff(uint32) time.Duration { return 2 * time.Second }
