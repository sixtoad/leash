//go:build darwin

package darwind

import (
	"context"
	"errors"
	"log"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Control-plane isolation (the macOS analog of Linux's netfilter REJECT of
// the leash ports). The Network Extension content filter never sees
// loopback flows, so it cannot keep a leashed workload away from the
// daemon's own listeners: the Control UI/API (which can rewrite the policy),
// the websocket hub (where the extensions report tracked PIDs) and the MITM
// proxy. Instead, the daemon refuses every loopback connection whose client
// is a leashed process, identified from the tracked PID set the Endpoint
// Security extension reports.

// lsofPath is the tool used to map a connection to its client process. A
// var so tests can substitute it.
var lsofPath = "/usr/sbin/lsof"

// parentPID returns pid's parent. A var so tests can substitute it.
var parentPID = func(pid int) (int, error) {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return 0, err
	}
	return int(kp.Eproc.Ppid), nil
}

// leashedPeer reports whether the client end of c belongs to a leashed
// process: one in pids or a descendant of one. The descendant check closes
// the race between a leashed process starting (exec or fork) and its PID
// reaching the daemon's tracked set.
func leashedPeer(c net.Conn, pids []int) (bool, error) {
	if len(pids) == 0 {
		return false, nil
	}
	owner, err := clientPID(c)
	if err != nil || owner <= 0 {
		// Not found: lsof lists every process of this user, and a leashed
		// workload runs as this user, so an invisible client is not one.
		return false, err
	}
	tracked := make(map[int]bool, len(pids))
	for _, p := range pids {
		tracked[p] = true
	}
	for pid, hops := owner, 0; pid > 1 && hops < 128; hops++ {
		if tracked[pid] {
			return true, nil
		}
		next, err := parentPID(pid)
		if err != nil || next == pid {
			break
		}
		pid = next
	}
	return false, nil
}

// clientPID finds the process whose TCP socket is the client end of c, or 0.
func clientPID(c net.Conn) (int, error) {
	remote, ok := c.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return 0, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	port := strconv.Itoa(remote.Port)
	out, err := exec.CommandContext(ctx, lsofPath, "-nP", "-iTCP:"+port, "-Fpn").Output()
	if err != nil {
		var exitErr *exec.ExitError
		// lsof exits 1 when it finds nothing; its output is still authoritative.
		if !errors.As(err, &exitErr) {
			return 0, err
		}
	}
	host := remote.IP.String()
	if remote.IP.To4() == nil {
		host = "[" + host + "]"
	}
	clientEnd := host + ":" + port + "->"
	pid := 0
	for _, line := range strings.Split(string(out), "\n") {
		switch {
		case strings.HasPrefix(line, "p"):
			pid, _ = strconv.Atoi(line[1:])
		case strings.HasPrefix(line, "n") && strings.HasPrefix(line[1:], clientEnd):
			return pid, nil
		}
	}
	return 0, nil
}

// guardedListener drops connections from leashed processes.
type guardedListener struct {
	net.Listener
	name    string
	tracked func() []int
}

func (l *guardedListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if allowControlConn(l.name, c, l.tracked) {
			return c, nil
		}
		_ = c.Close()
	}
}

// allowControlConn is the check itself, shared by the daemon's listeners. A
// failure to identify the client while a workload is leashed refuses the
// connection: the guard fails closed.
func allowControlConn(name string, c net.Conn, tracked func() []int) bool {
	if tracked == nil {
		return true
	}
	leashed, err := leashedPeer(c, tracked())
	if err != nil {
		logPolicyEvent("control.refused", map[string]any{"listener": name, "peer": c.RemoteAddr().String(), "error": err.Error()})
		log.Printf("leash: refusing %s connection from %s: cannot identify the client: %v", name, c.RemoteAddr(), err)
		return false
	}
	if leashed {
		logPolicyEvent("control.refused", map[string]any{"listener": name, "peer": c.RemoteAddr().String(), "reason": "leashed process"})
		return false
	}
	return true
}
