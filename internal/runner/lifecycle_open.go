package runner

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// Open cannot block if the snapshotted audit file was replaced by a FIFO.
// No-follow and the inode check reject replacements before any bytes are read.
func openLifecycleAudit(path string, snapshot os.FileInfo) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	opened, err := f.Stat()
	var stat unix.Stat_t
	statErr := unix.Fstat(fd, &stat)
	if err != nil || statErr != nil || !opened.Mode().IsRegular() || stat.Nlink != 1 ||
		!os.SameFile(snapshot, opened) {
		_ = f.Close()
		return nil, errors.New("audit source changed or unsafe")
	}
	return f, nil
}
