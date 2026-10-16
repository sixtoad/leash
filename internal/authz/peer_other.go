//go:build !linux && !darwin

package authz

import (
	"errors"
	"net"
)

// Without a way to identify the peer the socket refuses every connection.
func peerCredentials(*net.UnixConn) (Credentials, error) {
	return Credentials{}, errors.New("peer credentials are not supported on this platform")
}
