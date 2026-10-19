//go:build !linux

package runner

import "errors"

func getSELinuxLabel(string) (string, error) {
	return "", errors.New("SELinux labels are only read on Linux")
}
