//go:build linux

package idmap

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

func Apply(specs []Spec) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("idmapped mounts require the privileged Leash manager")
	}
	payload, err := Encode(specs)
	if err != nil {
		return fmt.Errorf("encode mount helper payload: %w", err)
	}
	managerExe := fmt.Sprintf("/proc/%d/exe", os.Getpid())
	cmd := exec.Command("nsenter", "--mount=/proc/1/ns/mnt", "--", managerExe, "--idmap-mount-helper")
	cmd.Env = append(os.Environ(), Env+"="+payload)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("run mount helper in target namespace: %w", err)
	}
	return nil
}

// ApplyCurrent applies specs in the caller's mount namespace. It is invoked
// only by the private single-purpose process entered through nsenter; keeping
// setns out of the multithreaded Go manager avoids CLONE_FS rejection.
func ApplyCurrent(specs []Spec) error {
	for _, spec := range specs {
		if err := applyOne(spec); err != nil {
			return fmt.Errorf("idmap volume %q: %w", spec.Target, err)
		}
	}
	return nil
}

func applyOne(spec Spec) error {
	if !filepath.IsAbs(spec.Target) || filepath.Clean(spec.Target) != spec.Target {
		return fmt.Errorf("target must be a clean absolute path")
	}
	if spec.HostUID == 0 || spec.HostGID == 0 || spec.ContainerUID == 0 || spec.ContainerGID == 0 {
		return fmt.Errorf("root identity mappings are not allowed")
	}

	userns, stop, err := mappedUserNamespace(spec)
	if err != nil {
		return err
	}
	defer stop()
	defer unix.Close(userns)

	tree, err := unix.OpenTree(unix.AT_FDCWD, spec.Target, unix.OPEN_TREE_CLONE|unix.OPEN_TREE_CLOEXEC)
	if err != nil {
		return fmt.Errorf("clone bind mount (kernel/filesystem may not support idmapped mounts): %w", err)
	}
	defer unix.Close(tree)
	attr := &unix.MountAttr{Attr_set: unix.MOUNT_ATTR_IDMAP, Userns_fd: uint64(userns)}
	if err := unix.MountSetattr(tree, "", unix.AT_EMPTY_PATH, attr); err != nil {
		return fmt.Errorf("apply MOUNT_ATTR_IDMAP (kernel/filesystem may not support it): %w", err)
	}
	if err := unix.MoveMount(tree, "", unix.AT_FDCWD, spec.Target, unix.MOVE_MOUNT_F_EMPTY_PATH); err != nil {
		return fmt.Errorf("install idmapped mount: %w", err)
	}
	return nil
}

func mappedUserNamespace(spec Spec) (int, func(), error) {
	r, w, err := os.Pipe()
	if err != nil {
		return -1, nil, fmt.Errorf("create user namespace hold pipe: %w", err)
	}
	cmd := exec.Command("/proc/self/exe", "--idmap-userns-holder")
	cmd.Stdin = r
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	uidMappings, gidMappings := userNamespaceMappings(spec)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:                 unix.CLONE_NEWUSER,
		UidMappings:                uidMappings,
		GidMappings:                gidMappings,
		GidMappingsEnableSetgroups: false,
	}
	if err := cmd.Start(); err != nil {
		r.Close()
		w.Close()
		return -1, nil, fmt.Errorf("create mapped user namespace: %w", err)
	}
	r.Close()
	fd, err := unix.Open(fmt.Sprintf("/proc/%d/ns/user", cmd.Process.Pid), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		w.Close()
		_ = cmd.Wait()
		return -1, nil, fmt.Errorf("open mapped user namespace: %w", err)
	}
	stop := func() { w.Close(); _ = cmd.Wait() }
	return fd, stop, nil
}

func userNamespaceMappings(spec Spec) ([]syscall.SysProcIDMap, []syscall.SysProcIDMap) {
	// An idmapped mount mapping is expressed as on-disk userspace ID ->
	// VFS/kernel ID. This makes host-owned 1000 appear as target 1001 and maps
	// target-created 1001 back to on-disk 1000. Reversing these fields makes
	// creation fail with EOVERFLOW.
	return []syscall.SysProcIDMap{{ContainerID: int(spec.HostUID), HostID: int(spec.ContainerUID), Size: 1}},
		[]syscall.SysProcIDMap{{ContainerID: int(spec.HostGID), HostID: int(spec.ContainerGID), Size: 1}}
}
