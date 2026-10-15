package lsm

import "sync/atomic"

// layer1Degraded records that at least one eBPF LSM program failed to attach
// and leash continued without it (only possible with proxy-only explicitly
// allowed and the L7 proxy active, issue #117).
var layer1Degraded atomic.Bool

// layer1Attached counts eBPF LSM programs that attached successfully.
var layer1Attached atomic.Int32

// Layer1Degraded reports whether any eBPF LSM attach has failed so far. It is
// set before the attach is reported as settled, so the enforcement-settled hook
// observes it.
func Layer1Degraded() bool { return layer1Degraded.Load() }

// Layer1AttachedPrograms reports how many eBPF LSM programs attached. Like
// Layer1Degraded it is updated before the attempt is reported settled. Zero
// means no kernel enforcement is in place even if nothing failed (e.g. a
// policy that created no LSM modules), so Layer 1 must not be reported active.
func Layer1AttachedPrograms() int { return int(layer1Attached.Load()) }

func markLayer1Degraded() { layer1Degraded.Store(true) }

func markLayer1Attached() { layer1Attached.Add(1) }
