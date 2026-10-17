//go:build linux

package runner

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

// NativeHolderMain implements the internal `leash --native-holder <pid>
// <start>`: the main process of the native box's holder unit. It replaces the
// former `sleep infinity` so the box is bound to the owning leash's lifetime:
// it returns (and the unit stops, systemd killing everything left in the box's
// cgroup and running the reap ExecStopPost) as soon as that leash exits —
// including on SIGKILL, where no teardown code in leash can run (#158).
//
// It waits on a pidfd (no PID-reuse race once opened); the owner's start time
// is checked after opening so a PID already reused before the holder started is
// not mistaken for the owner. Kernels without pidfd_open fall back to polling.
func NativeHolderMain(args []string) int {
	if len(args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: leash --native-holder <owner-pid> <owner-start>")
		return 2
	}
	pid, err1 := strconv.Atoi(args[0])
	start, err2 := strconv.ParseUint(args[1], 10, 64)
	if err1 != nil || err2 != nil || pid <= 0 {
		fmt.Fprintln(os.Stderr, "leash --native-holder: invalid owner")
		return 2
	}
	fd, err := unix.PidfdOpen(pid, 0)
	if err == nil {
		defer unix.Close(fd)
	}
	if got, serr := procStartTime(pid); serr != nil || got != start {
		return 0 // owner already gone
	}
	if err != nil {
		if !errors.Is(err, unix.ENOSYS) && !errors.Is(err, unix.EINVAL) {
			return 0 // ESRCH: owner already gone
		}
		for {
			time.Sleep(500 * time.Millisecond)
			if got, serr := procStartTime(pid); serr != nil || got != start {
				return 0
			}
		}
	}
	fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	for {
		n, perr := unix.Poll(fds, -1)
		if perr != nil {
			if errors.Is(perr, unix.EINTR) {
				continue
			}
			return 0
		}
		if n > 0 {
			return 0 // the pidfd is readable once the owner has exited
		}
	}
}
