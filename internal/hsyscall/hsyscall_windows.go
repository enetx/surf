package hsyscall

// RlimitStack is used to adjust the maximum number of worker goroutines, taking into account the
// system's file descriptor limit.
func RlimitStack(_ int) int { return 0 }
