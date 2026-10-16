//go:build darwin

package authz

import (
	"net"

	"golang.org/x/sys/unix"
)

func peerCredentials(conn *net.UnixConn) (Credentials, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return Credentials{}, err
	}
	var cred *unix.Xucred
	var pid int
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if credErr == nil {
			pid, credErr = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
		}
	}); err != nil {
		return Credentials{}, err
	}
	if credErr != nil {
		return Credentials{}, credErr
	}
	return Credentials{UID: int(cred.Uid), PID: pid}, nil
}
