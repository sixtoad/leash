//go:build linux

package hardening

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// The tests below re-run this test binary as a child that hardens itself
// (Apply changes the process for good) and then runs a command, the way
// `leash --harden-exec` does. envChild selects the child mode.
const envChild = "LEASH_HARDENING_TEST_CHILD"

func TestMain(m *testing.M) {
	switch os.Getenv(envChild) {
	case "":
		os.Exit(m.Run())
	case "unprivileged":
		// Without CAP_SETPCAP the bounding set cannot be emptied: Apply must
		// fail rather than hand over a workload with a full CapBnd (#203).
		if err := Apply(nil); err != nil {
			fmt.Println("refused:", err)
			os.Exit(0)
		}
		fmt.Println("Apply succeeded without privilege")
		os.Exit(3)
	default: // "drop:<user>" or "root": harden, then run os.Args[1:]
		var drop *Identity
		if name, ok := strings.CutPrefix(os.Getenv(envChild), "drop:"); ok {
			id, err := LookupIdentity(name)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(2)
			}
			drop = id
		}
		if err := Apply(drop); err != nil {
			fmt.Fprintln(os.Stderr, "apply:", err)
			os.Exit(2)
		}
		code, err := Run(os.Args[1:], os.Environ())
		if err != nil {
			fmt.Fprintln(os.Stderr, "run:", err)
			os.Exit(2)
		}
		os.Exit(code)
	}
}

func child(t *testing.T, mode string, argv ...string) *exec.Cmd {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(self, argv...)
	cmd.Env = append(os.Environ(), envChild+"="+mode)
	return cmd
}

// procStatus parses the capability and no_new_privs lines of /proc/<pid>/status.
func procStatus(t *testing.T, text string) map[string]string {
	t.Helper()
	got := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		switch k {
		case "Uid", "Gid", "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs", "Seccomp":
			got[k] = strings.Join(strings.Fields(v), " ")
		}
	}
	return got
}

func assertHardened(t *testing.T, what, status string, uid int) {
	t.Helper()
	st := procStatus(t, status)
	for _, k := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
		if st[k] != "0000000000000000" {
			t.Errorf("%s: %s = %q, want 0000000000000000", what, k, st[k])
		}
	}
	if st["NoNewPrivs"] != "1" {
		t.Errorf("%s: NoNewPrivs = %q, want 1", what, st["NoNewPrivs"])
	}
	if st["Seccomp"] != "2" {
		t.Errorf("%s: Seccomp = %q, want 2 (filter)", what, st["Seccomp"])
	}
	u := strconv.Itoa(uid)
	if want := strings.Join([]string{u, u, u, u}, " "); st["Uid"] != want {
		t.Errorf("%s: Uid = %q, want %q (real, effective, saved, fs)", what, st["Uid"], want)
	}
}

func TestApplyRefusesWithoutPrivilege(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("needs an unprivileged user")
	}
	out, err := child(t, "unprivileged").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "refused:") || !strings.Contains(string(out), "bounding set") {
		t.Fatalf("unprivileged Apply: %v: %s", err, out)
	}
}

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root (run the test binary with sudo)")
	}
}

// nobody resolves the user the root tests drop to.
func nobody(t *testing.T) *Identity {
	t.Helper()
	id, err := LookupIdentity("nobody")
	if err != nil {
		t.Skipf("no nobody user: %v", err)
	}
	return id
}

// The workload a hardened launch runs, and anything it execs, has no
// capability left in any set (bounding included), no_new_privs and the seccomp
// filter, as the dropped user (#203).
func TestHardenedWorkloadStatus(t *testing.T) {
	requireRoot(t)
	id := nobody(t)
	out, err := child(t, "drop:nobody", "/bin/cat", "/proc/self/status").CombinedOutput()
	if err != nil {
		t.Fatalf("hardened cat: %v: %s", err, out)
	}
	assertHardened(t, "dropped workload", string(out), id.UID)

	out, err = child(t, "root", "/bin/cat", "/proc/self/status").CombinedOutput()
	if err != nil {
		t.Fatalf("hardened root cat: %v: %s", err, out)
	}
	assertHardened(t, "--user root workload", string(out), 0)
}

// Neither a setuid-root binary nor a file-capability binary (iputils ping
// carries cap_net_raw+ep) raises privilege inside the box.
func TestHardenedWorkloadCannotRegainPrivilege(t *testing.T) {
	requireRoot(t)
	id := nobody(t)
	dir := t.TempDir()
	for d := dir; strings.HasPrefix(d, os.TempDir()+"/"); d = filepath.Dir(d) {
		_ = os.Chmod(d, 0o755) // let nobody reach the copies
	}
	src, err := os.ReadFile("/bin/cat")
	if err != nil {
		t.Fatal(err)
	}
	suid := filepath.Join(dir, "suid-cat")
	fcap := filepath.Join(dir, "fcap-cat")
	for _, p := range []string{suid, fcap} {
		if err := os.WriteFile(p, src, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(suid, os.ModeSetuid|0o755); err != nil {
		t.Fatal(err)
	}
	// security.capability v2: effective flag, permitted = CAP_NET_RAW, as
	// `setcap cap_net_raw+ep` writes it.
	vfs := make([]byte, 20)
	binary.LittleEndian.PutUint32(vfs[0:], 0x02000000|0x1)
	binary.LittleEndian.PutUint32(vfs[4:], 1<<unix.CAP_NET_RAW)
	if err := unix.Setxattr(fcap, "security.capability", vfs, 0); err != nil {
		t.Skipf("cannot set a file capability on %s: %v", dir, err)
	}

	// Without the hardening the binaries do raise privilege, so the check below
	// can fail.
	if out, err := exec.Command("runuser", "-u", "nobody", "--", suid, "/proc/self/status").CombinedOutput(); err == nil {
		if st := procStatus(t, string(out)); !strings.HasPrefix(st["Uid"], strconv.Itoa(id.UID)+" 0 ") {
			ls, _ := exec.Command("ls", "-la", dir).CombinedOutput()
			t.Skipf("control: the setuid copy did not raise euid without hardening (Uid %q; nosuid %s?), so the check would prove nothing\n%s", st["Uid"], dir, ls)
		}
	}

	// The setuid copy runs, but as nobody with nothing raised.
	out, err := child(t, "drop:nobody", suid, "/proc/self/status").CombinedOutput()
	if err != nil {
		t.Fatalf("setuid copy: %v: %s", err, out)
	}
	assertHardened(t, "setuid copy", string(out), id.UID)

	// The file-capability copy has the effective bit set, so the kernel refuses
	// to exec it at all when the bounding set withholds its capability (as
	// iputils ping fails: "Operation not permitted"); if a kernel ran it
	// anyway, it must run with nothing raised.
	out, err = child(t, "drop:nobody", fcap, "/proc/self/status").CombinedOutput()
	switch {
	case err != nil && strings.Contains(string(out), "operation not permitted"):
	case err != nil:
		t.Fatalf("file-capability copy: %v: %s", err, out)
	default:
		assertHardened(t, "file-capability copy", string(out), id.UID)
	}
}

// As PID 1 of a PID namespace (the native box's `unshare --pid --fork`),
// harden-exec stays as init and returns the workload's exit status.
func TestHardenedRunAsPIDNamespaceInit(t *testing.T) {
	requireRoot(t)
	nobody(t)
	if _, err := exec.LookPath("unshare"); err != nil {
		t.Skip("no unshare")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("unshare", "--pid", "--fork", "--mount-proc", "--", self,
		"/bin/sh", "-c", `grep -E '^(CapBnd|NoNewPrivs):' /proc/self/status; echo "init=$(cat /proc/1/comm)"; (sleep 0 &); exit 7`)
	cmd.Env = append(os.Environ(), envChild+"=drop:nobody")
	out, err := cmd.CombinedOutput()
	ee, ok := err.(*exec.ExitError)
	if !ok || ee.ExitCode() != 7 {
		t.Fatalf("exit = %v, want status 7: %s", err, out)
	}
	for _, want := range []string{"CapBnd:\t0000000000000000", "NoNewPrivs:\t1", "init=hardening.test"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("missing %q in: %s", want, out)
		}
	}
}
