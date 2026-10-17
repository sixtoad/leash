//go:build linux

package enforcerd

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/strongdm/leash/internal/authz"
	"github.com/strongdm/leash/internal/enforcement"
)

// AuditLogPath is the daemon's audit log (systemd LogsDirectory).
const AuditLogPath = "/var/log/leash-enforcerd/audit.log"

func peerCredLinux(conn net.Conn) (int, int, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, 0, errors.New("not a unix connection")
	}
	cred, err := authz.PeerCredentials(uc)
	if err != nil {
		return 0, 0, err
	}
	return cred.UID, cred.PID, nil
}

func readProcCgroup(pid int) ([]byte, error) {
	return os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cgroup"))
}

func resolveOwner(uid int) (int, error) {
	data, err := os.ReadFile("/etc/subuid")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return 0, err
	}
	isAccount := func(id int) bool {
		_, err := user.LookupId(strconv.Itoa(id))
		return err == nil
	}
	lookup := func(name string) (int, error) {
		u, err := user.Lookup(name)
		if err != nil {
			return 0, err
		}
		return strconv.Atoi(u.Uid)
	}
	return SubIDOwner(data, uid, isAccount, lookup)
}

func inLeashGroup(uid int) (bool, error) {
	g, err := user.LookupGroup(GroupName)
	if err != nil {
		return false, fmt.Errorf("group %q: %v", GroupName, err)
	}
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return false, err
	}
	if u.Gid == g.Gid {
		return true, nil
	}
	gids, err := u.GroupIds()
	if err != nil {
		return false, err
	}
	for _, id := range gids {
		if id == g.Gid {
			return true, nil
		}
	}
	return false, nil
}

func lsmStatus() (string, string) {
	state, reason := enforcement.ClassifyLSMList(os.ReadFile(enforcement.ActiveLSMPath))
	switch state {
	case enforcement.LSMListActive:
		return "active", ""
	case enforcement.LSMListInactive:
		return "inactive", reason
	default:
		return "unknown", reason
	}
}

// procWorker is a worker child process connected by a socketpair.
type procWorker struct {
	*os.File
	cmd      *exec.Cmd
	waitOnce sync.Once
	waitErr  error
}

func (w *procWorker) Kill() {
	if w.cmd.Process != nil {
		_ = w.cmd.Process.Signal(syscall.SIGTERM)
	}
}

func (w *procWorker) Wait() error {
	w.waitOnce.Do(func() { w.waitErr = w.cmd.Wait() })
	return w.waitErr
}

func spawnWorker(self string) func(string) (Worker, error) {
	return func(session string) (Worker, error) {
		fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}
		parent := os.NewFile(uintptr(fds[0]), "worker-"+session)
		child := os.NewFile(uintptr(fds[1]), "worker-control")
		cmd := exec.Command(self, "daemon", "worker")
		cmd.ExtraFiles = []*os.File{child} // fd 3
		cmd.Env = []string{"LEASH_ENFORCERD_SESSION=" + session}
		cmd.Stdout = prefixWriter{"session " + session + ": "}
		cmd.Stderr = prefixWriter{"session " + session + ": "}
		// The worker must not outlive the daemon.
		cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
		if err := cmd.Start(); err != nil {
			_ = parent.Close()
			_ = child.Close()
			return nil, err
		}
		_ = child.Close()
		return &procWorker{File: parent, cmd: cmd}, nil
	}
}

type prefixWriter struct{ prefix string }

func (p prefixWriter) Write(b []byte) (int, error) {
	log.Printf("%s%s", p.prefix, b)
	return len(b), nil
}

// listener returns the systemd-activated socket (LISTEN_FDS), or, when socket
// is set (manual runs and tests), listens there with mode 0660 and group
// GroupName.
func listener(socket string) (net.Listener, error) {
	if socket == "" {
		if pid, _ := strconv.Atoi(os.Getenv("LISTEN_PID")); pid == os.Getpid() {
			if n, _ := strconv.Atoi(os.Getenv("LISTEN_FDS")); n >= 1 {
				f := os.NewFile(3, "leash-enforcerd.socket")
				ln, err := net.FileListener(f)
				_ = f.Close()
				return ln, err
			}
		}
		return nil, errors.New("not started by systemd socket activation (no LISTEN_FDS); pass --socket <path> to listen directly")
	}
	_ = os.Remove(socket)
	ln, err := net.Listen("unix", socket)
	if err != nil {
		return nil, err
	}
	if g, err := user.LookupGroup(GroupName); err == nil {
		if gid, err := strconv.Atoi(g.Gid); err == nil {
			_ = os.Chown(socket, -1, gid)
		}
	}
	if err := os.Chmod(socket, 0o660); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

// Run is `leash daemon run`: serve until SIGTERM, then stop every session.
func Run(version, socket string) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	ln, err := listener(socket)
	if err != nil {
		return err
	}
	var audit io.Writer = io.Discard
	if f, err := os.OpenFile(AuditLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640); err == nil {
		defer f.Close()
		audit = f
	} else {
		log.Printf("audit log %s unavailable (%v); auditing to the journal only", AuditLogPath, err)
	}
	srv, err := NewServer(Config{
		Version:      version,
		CgroupRoot:   CgroupRoot,
		PeerCred:     peerCredLinux,
		ProcCgroup:   readProcCgroup,
		ResolveOwner: resolveOwner,
		InGroup:      inLeashGroup,
		SpawnWorker:  spawnWorker(self),
		LSMStatus:    lsmStatus,
		Audit:        audit,
	})
	if err != nil {
		return err
	}
	state, reason := lsmStatus()
	log.Printf("leash enforcer daemon %s listening (bpf LSM %s%s)", version, state, reasonSuffix(reason))
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sig
		log.Printf("shutting down: detaching %d session(s)", srv.Sessions())
		_ = ln.Close()
	}()
	err = srv.Serve(ln)
	srv.KillAll()
	return err
}

func reasonSuffix(r string) string {
	if r == "" {
		return ""
	}
	return ": " + r
}

// RunWorkerMain is `leash daemon worker`: serve the session on fd 3.
func RunWorkerMain() error {
	f := os.NewFile(3, "worker-control")
	if f == nil {
		return errors.New("no control descriptor")
	}
	defer f.Close()
	return RunWorker(f, WorkerHooks{})
}
