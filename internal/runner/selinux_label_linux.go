//go:build linux

package runner

import (
	"errors"

	"golang.org/x/sys/unix"
)

// getSELinuxLabel reads path's security.selinux extended attribute, following
// symlinks: the engine binds (and the container reads) the link's target.
func getSELinuxLabel(path string) (string, error) {
	buf := make([]byte, 256)
	for {
		n, err := unix.Getxattr(path, "security.selinux", buf)
		if errors.Is(err, unix.ERANGE) && len(buf) < 64*1024 {
			buf = make([]byte, len(buf)*4)
			continue
		}
		if err != nil {
			return "", err
		}
		return string(buf[:n]), nil
	}
}
