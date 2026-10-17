//go:build linux

package lsm

// io_uring case for the container overlay validation (#186/#125). One
// io_uring_enter submits two openat SQEs; both run inline in the submitting
// task. After the first (a permitted overlay write) installs the copy-up
// correlation, the second (a default-deny overlay write) must still be
// decided by policy: the correlation only covers the opens overlayfs makes
// itself, under its mounter's credentials.

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"unsafe"
)

const overlayURingHelperEnv = "LEASH_OVERLAY_URING_HELPER"

// TestOverlayURingHelper is the helper process the overlay validation starts
// inside the scoped cgroup; it is skipped in every ordinary run.
func TestOverlayURingHelper(t *testing.T) {
	paths := os.Getenv(overlayURingHelperEnv)
	if paths == "" {
		t.Skip("helper process for the overlay io_uring validation case")
	}
	results, err := uringOpenWriteBatch(strings.Split(paths, ":"))
	if err != nil {
		fmt.Printf("uring-unavailable: %v\n", err)
		return
	}
	for i, res := range results {
		fmt.Printf("uring[%d]=%d\n", i, res)
	}
}

// verifyURing runs the helper (a copy of this test binary under /usr/, which
// the validation policy lets the box execute) inside the scoped cgroup.
func (o overlayRootCases) verifyURing(t *testing.T, cgroupFD int) {
	t.Helper()
	cmd := exec.Command(o.uringHelper, "-test.run=^TestOverlayURingHelper$")
	cmd.Env = append(os.Environ(), overlayURingHelperEnv+"="+o.uringPermitted+":"+o.defaultDenyFile)
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: cgroupFD}
	out, err := cmd.CombinedOutput()
	text := string(out)
	if strings.Contains(text, "uring-unavailable") {
		t.Logf("NOT EXERCISED overlay io_uring case: %s", strings.TrimSpace(text))
		return
	}
	results := map[string]int{}
	for _, line := range strings.Split(text, "\n") {
		if key, value, ok := strings.Cut(strings.TrimSpace(line), "="); ok && strings.HasPrefix(key, "uring[") {
			if n, perr := strconv.Atoi(value); perr == nil {
				results[key] = n
			}
		}
	}
	first, ok1 := results["uring[0]"]
	second, ok2 := results["uring[1]"]
	switch {
	case err != nil || !ok1 || !ok2:
		t.Errorf("FAIL overlay io_uring helper: %v (%s)", err, strings.TrimSpace(text))
	case first < 0:
		t.Errorf("FAIL overlay io_uring: permitted overlay write %s refused: %s", o.uringPermitted, syscall.Errno(-first))
	case second >= 0:
		t.Errorf("FAIL overlay io_uring: default-deny overlay write %s in the same io_uring_enter was ALLOWED", o.defaultDenyFile)
	case syscall.Errno(-second) != syscall.EACCES:
		t.Errorf("FAIL overlay io_uring: default-deny overlay write refused with %s, want EACCES", syscall.Errno(-second))
	default:
		t.Logf("PASS overlay io_uring: permitted write opened, default-deny write in the same io_uring_enter denied")
	}
}

type uringSQOffsets struct {
	Head, Tail, RingMask, RingEntries, Flags, Dropped, Array, Resv1 uint32
	UserAddr                                                        uint64
}

type uringCQOffsets struct {
	Head, Tail, RingMask, RingEntries, Overflow, Cqes, Flags, Resv1 uint32
	UserAddr                                                        uint64
}

type uringParams struct {
	SQEntries, CQEntries, Flags, SQThreadCPU, SQThreadIdle, Features, WQFd uint32
	Resv                                                                   [3]uint32
	SQOff                                                                  uringSQOffsets
	CQOff                                                                  uringCQOffsets
}

type uringSQE struct {
	Opcode, Flags uint8
	IoPrio        uint16
	Fd            int32
	Off, Addr     uint64
	Len           uint32
	OpenFlags     uint32
	UserData      uint64
	Pad           [3]uint64
}

type uringCQE struct {
	UserData uint64
	Res      int32
	Flags    uint32
}

// uringOpenWriteBatch submits one O_WRONLY|O_APPEND openat SQE per path in a
// single io_uring_enter and returns each result (an fd, or -errno).
func uringOpenWriteBatch(paths []string) ([]int, error) {
	const (
		sysSetup, sysEnter = 425, 426
		opOpenat           = 18
		enterGetEvents     = 1
		offCQRing, offSQEs = 0x8000000, 0x10000000
	)
	var p uringParams
	fd, _, errno := syscall.Syscall(sysSetup, 8, uintptr(unsafe.Pointer(&p)), 0)
	if errno != 0 {
		return nil, fmt.Errorf("io_uring_setup: %w", errno)
	}
	defer syscall.Close(int(fd))
	mmap := func(size int, off int64) ([]byte, error) {
		return syscall.Mmap(int(fd), off, size, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED|syscall.MAP_POPULATE)
	}
	sq, err := mmap(int(p.SQOff.Array+p.SQEntries*4), 0)
	if err != nil {
		return nil, err
	}
	cq, err := mmap(int(p.CQOff.Cqes+p.CQEntries*uint32(unsafe.Sizeof(uringCQE{}))), offCQRing)
	if err != nil {
		return nil, err
	}
	sqes, err := mmap(int(p.SQEntries)*int(unsafe.Sizeof(uringSQE{})), offSQEs)
	if err != nil {
		return nil, err
	}
	word := func(b []byte, off uint32) *uint32 { return (*uint32)(unsafe.Pointer(&b[off])) }

	names := make([][]byte, len(paths))
	tail, mask := *word(sq, p.SQOff.Tail), *word(sq, p.SQOff.RingMask)
	for i, path := range paths {
		names[i] = append([]byte(path), 0)
		idx := (tail + uint32(i)) & mask
		sqe := (*uringSQE)(unsafe.Pointer(&sqes[uintptr(idx)*unsafe.Sizeof(uringSQE{})]))
		*sqe = uringSQE{Opcode: opOpenat, Fd: -100, Addr: uint64(uintptr(unsafe.Pointer(&names[i][0]))),
			OpenFlags: uint32(syscall.O_WRONLY | syscall.O_APPEND), UserData: uint64(i)}
		*word(sq, p.SQOff.Array+idx*4) = idx
	}
	*word(sq, p.SQOff.Tail) = tail + uint32(len(paths))
	if _, _, errno := syscall.Syscall6(sysEnter, fd, uintptr(len(paths)), uintptr(len(paths)), enterGetEvents, 0, 0); errno != 0 {
		return nil, fmt.Errorf("io_uring_enter: %w", errno)
	}
	results := make([]int, len(paths))
	head, ctail, cmask := *word(cq, p.CQOff.Head), *word(cq, p.CQOff.Tail), *word(cq, p.CQOff.RingMask)
	for ; head != ctail; head++ {
		cqe := (*uringCQE)(unsafe.Pointer(&cq[p.CQOff.Cqes+(head&cmask)*uint32(unsafe.Sizeof(uringCQE{}))]))
		if cqe.UserData < uint64(len(results)) {
			results[cqe.UserData] = int(cqe.Res)
			if cqe.Res >= 0 {
				syscall.Close(int(cqe.Res))
			}
		}
	}
	return results, nil
}
