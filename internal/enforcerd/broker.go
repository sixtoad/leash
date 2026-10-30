//go:build unix

package enforcerd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/strongdm/leash/internal/authz"
)

// The broker hands leashd a connection to the daemon that the leash client
// opened (rootless Docker, #207).
//
// Rootless Docker's containers cannot keep the caller's supplementary groups
// (Docker has no `--group-add keep-groups`), so leashd in the leash container
// cannot open the daemon's root:leash 0660 socket itself. The leash client
// can: it is a host process of the calling user, in the user's session, with
// the leash group. It listens on a single-use socket in a private directory
// mounted only into the leash container. When leashd connects, the client
// dials the daemon and passes the connected socket to leashd (SCM_RIGHTS),
// then stops listening. leashd speaks the normal protocol on it.
//
// The daemon's checks are unchanged and apply to the client: SO_PEERCRED of
// the passed connection is the client's (uid, pid), resolved and checked for
// the leash group as for any caller; the client's cgroup is outside every
// governed cgroup, and the target cgroup must be inside the user's delegated
// subtree and owned by the user or one of its subordinate uids, which is
// where rootless Docker puts its containers. The broker adds the daemon's
// "never from inside a governed workload" rule on its own side: a peer whose
// cgroup is the workload's cgroup or below it gets nothing.

const (
	// EnvBroker names the broker socket for leashd (inside the leash
	// container). When set, leashd obtains its daemon connection from the
	// broker instead of dialing EnvSocket.
	EnvBroker = "LEASH_ENFORCER_BROKER"
	// BrokerSocketName is the broker socket's file name in its directory.
	BrokerSocketName = "broker.sock"
)

// BrokerConfig configures StartBroker; the function fields are replaceable
// for tests.
type BrokerConfig struct {
	// Dir is the private directory (mode 0700, created by the caller) the
	// broker socket is created in.
	Dir string
	// DaemonSocket is the daemon's socket.
	DaemonSocket string
	// Workload is the governed cgroup (absolute cgroupfs path): a peer in it
	// or below it is refused.
	Workload string
	// CgroupRoot is the cgroup v2 mount (default CgroupRoot).
	CgroupRoot string
	// PeerCred returns the connecting process's uid and pid.
	PeerCred func(*net.UnixConn) (uid, pid int, err error)
	// ProcCgroup reads /proc/<pid>/cgroup.
	ProcCgroup func(pid int) ([]byte, error)
	// DialDaemon connects to the daemon.
	DialDaemon func(ctx context.Context, socket string) (*net.UnixConn, error)
	// UID is the uid a peer must have (default os.Getuid()).
	UID int
	// Logf receives diagnostics (may be nil).
	Logf func(format string, args ...any)
}

// Broker is a running single-use broker.
type Broker struct {
	cfg    BrokerConfig
	ln     *net.UnixListener
	socket string
	done   chan struct{}
	once   sync.Once
	served bool
	mu     sync.Mutex
}

// StartBroker listens on Dir/broker.sock (mode 0600) and serves until one
// connection has been handed over or Close is called.
func StartBroker(cfg BrokerConfig) (*Broker, error) {
	if cfg.Dir == "" || cfg.DaemonSocket == "" || cfg.Workload == "" {
		return nil, errors.New("enforcer broker: incomplete configuration")
	}
	if cfg.CgroupRoot == "" {
		cfg.CgroupRoot = CgroupRoot
	}
	if cfg.PeerCred == nil {
		cfg.PeerCred = func(c *net.UnixConn) (int, int, error) {
			cred, err := authz.PeerCredentials(c)
			if err != nil {
				return 0, 0, err
			}
			return cred.UID, cred.PID, nil
		}
	}
	if cfg.ProcCgroup == nil {
		cfg.ProcCgroup = func(pid int) ([]byte, error) {
			return os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cgroup"))
		}
	}
	if cfg.DialDaemon == nil {
		cfg.DialDaemon = func(ctx context.Context, socket string) (*net.UnixConn, error) {
			var d net.Dialer
			c, err := d.DialContext(ctx, "unix", socket)
			if err != nil {
				return nil, err
			}
			return c.(*net.UnixConn), nil
		}
	}
	if cfg.UID == 0 {
		cfg.UID = os.Getuid()
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	st, err := os.Lstat(cfg.Dir)
	if err != nil {
		return nil, fmt.Errorf("enforcer broker: %w", err)
	}
	if !st.IsDir() || st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("enforcer broker: %s must be a private directory (mode 0700)", cfg.Dir)
	}
	socket := filepath.Join(cfg.Dir, BrokerSocketName)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("enforcer broker: %w", err)
	}
	ln.SetUnlinkOnClose(true)
	if err := os.Chmod(socket, 0o600); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("enforcer broker: %w", err)
	}
	b := &Broker{cfg: cfg, ln: ln, socket: socket, done: make(chan struct{})}
	go b.serve()
	return b, nil
}

// Socket is the broker socket's host path.
func (b *Broker) Socket() string { return b.socket }

// Served reports whether a connection was handed over.
func (b *Broker) Served() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.served
}

// Close stops listening and removes the socket.
func (b *Broker) Close() error {
	var err error
	b.once.Do(func() {
		close(b.done)
		err = b.ln.Close()
	})
	return err
}

func (b *Broker) serve() {
	for {
		conn, err := b.ln.AcceptUnix()
		if err != nil {
			select {
			case <-b.done:
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		if b.handle(conn) {
			// Single use: leashd needs exactly one connection.
			_ = b.Close()
			return
		}
	}
}

// handle serves one peer and reports whether it handed a connection over.
func (b *Broker) handle(conn *net.UnixConn) bool {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	if err := b.authorize(conn); err != nil {
		b.cfg.Logf("enforcer broker: refused: %v", err)
		_, _ = conn.Write([]byte("enforcer broker: " + err.Error() + "\n"))
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	daemon, err := b.cfg.DialDaemon(ctx, b.cfg.DaemonSocket)
	if err != nil {
		msg := fmt.Sprintf("cannot reach the leash enforcer daemon at %s: %v (%s)", b.cfg.DaemonSocket, err, RemedyFor(err))
		b.cfg.Logf("enforcer broker: %s", msg)
		_, _ = conn.Write([]byte("enforcer broker: " + msg + "\n"))
		return false
	}
	defer daemon.Close()
	raw, err := daemon.SyscallConn()
	if err != nil {
		_, _ = conn.Write([]byte("enforcer broker: " + err.Error() + "\n"))
		return false
	}
	var sendErr error
	if err := raw.Control(func(fd uintptr) {
		_, _, sendErr = conn.WriteMsgUnix([]byte{0}, syscall.UnixRights(int(fd)), nil)
	}); err != nil {
		sendErr = err
	}
	if sendErr != nil {
		b.cfg.Logf("enforcer broker: pass connection: %v", sendErr)
		return false
	}
	b.mu.Lock()
	b.served = true
	b.mu.Unlock()
	// Keep this end open until the peer has taken the connection (it closes
	// the broker connection), so the handover never races our close.
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _ = conn.Read(make([]byte, 1))
	return true
}

func (b *Broker) authorize(conn *net.UnixConn) error {
	uid, pid, err := b.cfg.PeerCred(conn)
	if err != nil {
		return fmt.Errorf("cannot read peer credentials: %v", err)
	}
	if uid != b.cfg.UID {
		return fmt.Errorf("peer uid %d is not the leash client's uid %d", uid, b.cfg.UID)
	}
	if pid <= 0 {
		return errors.New("peer pid unknown")
	}
	data, err := b.cfg.ProcCgroup(pid)
	if err != nil {
		return fmt.Errorf("cgroup of peer pid %d: %v", pid, err)
	}
	rel, err := procCgroupPath(data)
	if err != nil {
		return fmt.Errorf("cgroup of peer pid %d: %v", pid, err)
	}
	cg := filepath.Join(b.cfg.CgroupRoot, rel)
	if within(cg, filepath.Clean(b.cfg.Workload)) {
		return fmt.Errorf("connection from inside the governed workload (cgroup %s) refused", cg)
	}
	return nil
}

// DialBroker obtains a daemon connection from the broker at path and wraps
// it in a Client. onEvent may be nil.
func DialBroker(ctx context.Context, path string, onEvent func(line string)) (*Client, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	uc := c.(*net.UnixConn)
	defer uc.Close()
	stop := context.AfterFunc(ctx, func() { _ = uc.Close() })
	defer stop()
	buf := make([]byte, 4096)
	oob := make([]byte, syscall.CmsgSpace(4))
	n, oobn, _, _, err := uc.ReadMsgUnix(buf, oob)
	if err != nil {
		return nil, fmt.Errorf("enforcer broker: %w", err)
	}
	var fds []int
	if oobn > 0 {
		msgs, perr := syscall.ParseSocketControlMessage(oob[:oobn])
		if perr == nil {
			for _, m := range msgs {
				if got, err := syscall.ParseUnixRights(&m); err == nil {
					fds = append(fds, got...)
				}
			}
		}
	}
	if len(fds) == 0 {
		msg := string(buf[:n])
		for len(msg) > 0 && (msg[len(msg)-1] == '\n' || msg[len(msg)-1] == 0) {
			msg = msg[:len(msg)-1]
		}
		if msg == "" {
			msg = "enforcer broker: no connection received"
		}
		return nil, errors.New(msg)
	}
	for _, extra := range fds[1:] {
		_ = syscall.Close(extra)
	}
	f := os.NewFile(uintptr(fds[0]), "leash-enforcerd")
	defer f.Close()
	conn, err := net.FileConn(f)
	if err != nil {
		return nil, fmt.Errorf("enforcer broker: %w", err)
	}
	return NewClient(conn, onEvent), nil
}
