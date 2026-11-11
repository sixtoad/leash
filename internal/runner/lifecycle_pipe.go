package runner

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// Walk creates this host-only FIFO outside the workspace. A separate transport
// prevents optional output from filling or locking ordinary stderr, including
// when a later cleanup diagnostic is required. Never fall back to stdio.
func openLifecycleOutput(path string) (*os.File, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("optional telemetry pipe unavailable")
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || parent.Mode().Perm()&0077 != 0 {
		return nil, errors.New("optional telemetry pipe parent unsafe")
	}
	snapshot, err := os.Lstat(path)
	if err != nil || snapshot.Mode()&os.ModeNamedPipe == 0 || snapshot.Mode().Perm()&0077 != 0 {
		return nil, errors.New("optional telemetry pipe unsafe")
	}
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err // ENXIO (no reader) is optional and cannot block startup
	}
	f := os.NewFile(uintptr(fd), path)
	opened, err := f.Stat()
	var stat unix.Stat_t
	statErr := unix.Fstat(fd, &stat)
	if err != nil || statErr != nil || opened.Mode()&os.ModeNamedPipe == 0 || stat.Nlink != 1 ||
		opened.Mode().Perm()&0077 != 0 || !os.SameFile(snapshot, opened) {
		_ = f.Close()
		return nil, errors.New("optional telemetry pipe replaced or unsafe")
	}
	for _, stdio := range []*os.File{os.Stdin, os.Stdout, os.Stderr} {
		info, err := stdio.Stat()
		if err == nil && os.SameFile(opened, info) {
			_ = f.Close()
			return nil, errors.New("optional telemetry pipe aliases stdio")
		}
	}
	return f, nil
}
