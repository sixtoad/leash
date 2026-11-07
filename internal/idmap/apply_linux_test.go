//go:build linux

package idmap

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestUserNamespaceMappingsTranslateHostOwnerToTargetIdentity(t *testing.T) {
	uids, gids := userNamespaceMappings(Spec{
		HostUID: 1000, HostGID: 1000, ContainerUID: 1001, ContainerGID: 1001,
	})
	if got := uids[0]; got.ContainerID != 1000 || got.HostID != 1001 || got.Size != 1 {
		t.Fatalf("uid mapping = %+v, want on-disk 1000 -> VFS 1001", got)
	}
	if got := gids[0]; got.ContainerID != 1000 || got.HostID != 1001 || got.Size != 1 {
		t.Fatalf("gid mapping = %+v, want on-disk 1000 -> VFS 1001", got)
	}
}

// The idmapped clone replaces the target: it must carry the submounts, or a
// volume nested in an idmapped volume vanishes from the workload's view.
func TestCloneTreeKeepsSubmounts(t *testing.T) {
	if cloneTreeFlags&unix.AT_RECURSIVE == 0 {
		t.Fatal("open_tree clone is not recursive: nested mounts would be hidden by the idmapped mount")
	}
	if cloneTreeFlags&unix.OPEN_TREE_CLONE == 0 || cloneTreeFlags&unix.OPEN_TREE_CLOEXEC == 0 {
		t.Fatalf("cloneTreeFlags = %#x", cloneTreeFlags)
	}
}
