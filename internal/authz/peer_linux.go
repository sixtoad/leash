//go:build linux

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
	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return Credentials{}, err
	}
	if credErr != nil {
		return Credentials{}, credErr
	}
	return Credentials{UID: int(cred.Uid), PID: int(cred.Pid)}, nil
}
