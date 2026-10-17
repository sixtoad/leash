package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Native boxes outlive a leash that is SIGKILLed or force-exits (a second
// Ctrl-C calls os.Exit): the holder unit, the named netns with its egress, and
// the per-run work dir stay behind (#158). Every native run therefore records
// what it created in a small state file keyed by the box name, together with
// the owning leash's PID, its start time and the boot ID, so that:
//
//   - the holder unit can exit (and systemd tear the box down) the moment the
//     owner dies — see nativeHolderMain;
//   - the holder's ExecStopPost, the next native run and `leash doctor --reap`
//     can reap a box whose owner is provably gone, without ever touching a
//     box that belongs to a live leash.

// nativeBoxState is the on-disk record of one native box.
type nativeBoxState struct {
	Name        string `json:"name"`
	Unit        string `json:"unit"`
	UserManager bool   `json:"user_manager,omitempty"`
	// Netns is the named network namespace (and egress) this run created; ""
	// when the run had no Layer-2 netns (rootless).
	Netns string `json:"netns,omitempty"`
	// OwnerPID/OwnerStart identify the leash process that owns the box; the
	// start time (clock ticks since boot, /proc/<pid>/stat field 22) guards
	// against PID reuse, BootID against a reboot.
	OwnerPID   int    `json:"owner_pid"`
	OwnerStart uint64 `json:"owner_start"`
	BootID     string `json:"boot_id"`
	// LeashdPID/LeashdStart identify the run's leashd once it started, so a
	// reaper can wait for (or stop) an orphaned leashd before touching the netns.
	LeashdPID   int    `json:"leashd_pid,omitempty"`
	LeashdStart uint64 `json:"leashd_start,omitempty"`
	// WorkDir is the per-run temporary work dir (only recorded when leash
	// created it, so a user-provided LEASH_WORK_DIR is never removed).
	WorkDir string `json:"work_dir,omitempty"`
	// Files are per-run files outside WorkDir (leashd log, exported CA copy).
	Files []string `json:"files,omitempty"`
}

// nativeStateDirOverride lets tests point the state dir at a temp dir.
var nativeStateDirOverride string

// nativeStateDir is where box records live: /run/leash/native for root (tmpfs,
// root-only), $XDG_RUNTIME_DIR/leash/native for a rootless run. "" when there
// is no suitable private runtime dir.
func nativeStateDir(userManager bool) string {
	if nativeStateDirOverride != "" {
		return nativeStateDirOverride
	}
	if !userManager {
		return "/run/leash/native"
	}
	if xdg := strings.TrimSpace(os.Getenv("XDG_RUNTIME_DIR")); xdg != "" && filepath.IsAbs(xdg) {
		return filepath.Join(xdg, "leash", "native")
	}
	return ""
}

func nativeStatePath(dir, name string) string {
	return filepath.Join(dir, name+".json")
}

// writeNativeBoxState atomically (re)writes a box record (0600 in a 0700 dir).
func writeNativeBoxState(dir string, st nativeBoxState) error {
	if dir == "" {
		return errors.New("no native state dir")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-"+st.Name+"-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), nativeStatePath(dir, st.Name)); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	return nil
}

func readNativeBoxState(path string) (nativeBoxState, error) {
	var st nativeBoxState
	data, err := os.ReadFile(path)
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(data, &st); err != nil {
		return st, err
	}
	if st.Name == "" || !strings.HasPrefix(st.Name, "leash-native-") || strings.ContainsAny(st.Name, "/ ") {
		return st, fmt.Errorf("invalid native box record %s", path)
	}
	return st, nil
}

// procStartTime returns a process's start time (field 22 of /proc/<pid>/stat).
// Variable so tests can model dead/reused PIDs.
var procStartTime = func(pid int) (uint64, error) {
	if pid <= 0 {
		return 0, errors.New("invalid pid")
	}
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0, err
	}
	// comm (field 2) may contain spaces/parens: parse after the last ')'.
	i := bytes.LastIndexByte(data, ')')
	if i < 0 {
		return 0, errors.New("malformed stat")
	}
	fields := strings.Fields(string(data[i+1:]))
	// fields[0] is field 3 (state); start time is field 22 -> index 19.
	if len(fields) < 20 {
		return 0, errors.New("short stat")
	}
	return strconv.ParseUint(fields[19], 10, 64)
}

// currentBootID identifies this boot. Variable for tests.
var currentBootID = func() string {
	data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// procIdentityAlive reports whether pid is still the process that started at
// start in this boot.
func procIdentityAlive(pid int, start uint64, bootID string) bool {
	if pid <= 0 {
		return false
	}
	if bootID != "" && bootID != currentBootID() {
		return false
	}
	got, err := procStartTime(pid)
	if err != nil {
		return false
	}
	return start == 0 || got == start
}

// ownerAlive reports whether the box's owning leash is still running. Any doubt
// about a record (unreadable /proc of a live PID is not "dead") is resolved by
// the start-time comparison: a PID that exists with the same start time in the
// same boot is the owner.
func (st nativeBoxState) ownerAlive() bool {
	return procIdentityAlive(st.OwnerPID, st.OwnerStart, st.BootID)
}

// signalProc is a seam for tests (kill(2)).
var signalProc = func(pid int, sig syscall.Signal) error { return syscall.Kill(pid, sig) }

// reapNativeBox removes everything a dead owner's box left behind: an orphaned
// leashd (it should already have died with its parent), the holder unit, the
// netns with its egress (veth, NAT/filter rules, /etc/netns), per-run files and
// the temp work dir, and finally the record itself. Best-effort and bounded by
// ctx; every step tolerates the resource already being gone.
func reapNativeBox(ctx context.Context, dir string, st nativeBoxState, leashdWait time.Duration) {
	if st.LeashdPID > 0 && procIdentityAlive(st.LeashdPID, st.LeashdStart, st.BootID) {
		deadline := time.Now().Add(leashdWait)
		for time.Now().Before(deadline) && procIdentityAlive(st.LeashdPID, st.LeashdStart, st.BootID) {
			time.Sleep(100 * time.Millisecond)
		}
		if procIdentityAlive(st.LeashdPID, st.LeashdStart, st.BootID) {
			_ = signalProc(-st.LeashdPID, syscall.SIGKILL) // its own process group
			_ = signalProc(st.LeashdPID, syscall.SIGKILL)
		}
	}
	userFlag := []string(nil)
	if st.UserManager {
		userFlag = []string{"--user"}
	}
	if st.Netns != "" {
		teardownEgressFor(ctx, egressFor(st.Netns))
		_, _ = hostOutput(ctx, "ip", "netns", "del", st.Netns)
	}
	if st.Unit != "" {
		_, _ = hostOutput(ctx, "systemctl", append(append([]string{}, userFlag...), "stop", "--no-block", st.Unit)...)
		_, _ = hostOutput(ctx, "systemctl", append(append([]string{}, userFlag...), "reset-failed", st.Unit)...)
	}
	for _, f := range st.Files {
		if safeReapPath(f) {
			_ = os.Remove(f)
		}
	}
	if st.WorkDir != "" && safeReapPath(st.WorkDir) {
		_ = os.RemoveAll(st.WorkDir)
	}
	_ = os.Remove(nativeStatePath(dir, st.Name))
}

// safeReapPath refuses to remove anything that is not an absolute, clean path
// at least two levels deep (never "/", "/tmp", "/home").
func safeReapPath(p string) bool {
	if p == "" || !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return false
	}
	return strings.Count(p, string(os.PathSeparator)) >= 2
}

// staleNativeBoxes lists the records in dir whose owner is dead. Unreadable or
// malformed records are skipped (never reaped blindly).
func staleNativeBoxes(dir string) []nativeBoxState {
	if dir == "" {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []nativeBoxState
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		st, err := readNativeBoxState(filepath.Join(dir, e.Name()))
		if err != nil || st.ownerAlive() {
			continue
		}
		out = append(out, st)
	}
	return out
}

// reapStaleNativeBoxesIn reaps every box in dir whose owner is dead and returns
// their names.
func reapStaleNativeBoxesIn(ctx context.Context, dir string) []string {
	var names []string
	for _, st := range staleNativeBoxes(dir) {
		reapNativeBox(ctx, dir, st, 2*time.Second)
		names = append(names, st.Name)
	}
	return names
}

// StaleNativeBoxes reports the native boxes left behind by dead leash runs
// (for `leash doctor`), for the current privilege level.
func StaleNativeBoxes() []string {
	var names []string
	for _, st := range staleNativeBoxes(nativeStateDir(os.Geteuid() != 0)) {
		names = append(names, st.Name)
	}
	return names
}

// ReapStaleNativeBoxes reaps the native boxes left behind by dead leash runs
// (`leash doctor --reap`) and returns their names. Only boxes whose owning
// leash is provably gone are touched.
func ReapStaleNativeBoxes(ctx context.Context) []string {
	return reapStaleNativeBoxesIn(ctx, nativeStateDir(os.Geteuid() != 0))
}

// NativeReapBoxMain implements the internal `leash --native-reap-box <name>`
// that the holder unit's ExecStopPost launches (in its own transient unit, off
// the box's LSM-scoped cgroup): it reaps that one box if — and only if — its
// owner is dead. A normal teardown (owner alive, stopping the unit itself) is a
// no-op here.
func NativeReapBoxMain(args []string) int {
	if len(args) != 1 || !strings.HasPrefix(args[0], "leash-native-") || strings.ContainsAny(args[0], "/ ") {
		fmt.Fprintln(os.Stderr, "usage: leash --native-reap-box <box-name>")
		return 2
	}
	dir := nativeStateDir(os.Geteuid() != 0)
	st, err := readNativeBoxState(nativeStatePath(dir, args[0]))
	if err != nil {
		return 0 // already reaped, or never recorded
	}
	if st.ownerAlive() {
		return 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	reapNativeBox(ctx, dir, st, 10*time.Second)
	return 0
}
