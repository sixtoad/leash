package lsm

import "sync/atomic"

// layer1Degraded records that at least one eBPF LSM program failed to attach
// and leash continued without it (only possible with proxy-only explicitly
// allowed, issue #117).
var layer1Degraded atomic.Bool

// Layer1Degraded reports whether any eBPF LSM attach has failed so far. It is
// set before the attach is reported as settled, so the enforcement-settled hook
// observes it.
func Layer1Degraded() bool { return layer1Degraded.Load() }

func markLayer1Degraded() { layer1Degraded.Store(true) }
