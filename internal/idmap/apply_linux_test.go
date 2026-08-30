//go:build linux

package idmap

import "testing"

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
