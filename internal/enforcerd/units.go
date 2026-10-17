package enforcerd

import (
	"fmt"
	"path"
)

// Installed layout. The daemon's binary is a root-owned copy, never the
// (possibly user-writable) binary `leash daemon install` was run from.
const (
	InstallDir      = "/usr/local/lib/leash-enforcerd"
	InstallBin      = InstallDir + "/leash"
	UnitDir         = "/etc/systemd/system"
	SocketUnit      = "leash-enforcerd.socket"
	ServiceUnit     = "leash-enforcerd.service"
	ServiceUser     = "leash-enforcer"
	AuditLogDirName = "leash-enforcerd"
)

// Capabilities are the only privileges the daemon holds: loading and
// attaching BPF_PROG_TYPE_LSM programs and their maps (CAP_BPF), and the
// tracing-class program type and its kernel-memory read helpers
// (CAP_PERFMON). Nothing else: no CAP_SYS_ADMIN, no CAP_NET_ADMIN, no
// CAP_DAC_*; memlock accounting is per-cgroup since Linux 5.11, and
// LimitMEMLOCK=infinity covers older accounting without CAP_SYS_RESOURCE.
var Capabilities = []string{"CAP_BPF", "CAP_PERFMON"}

// SocketUnitText is the systemd socket unit: the socket is created by
// systemd, owned by root, group GroupName, mode 0660, so only members of the
// group can connect at all.
func SocketUnitText() string {
	return fmt.Sprintf(`# Installed by "leash daemon install". Remove with "sudo leash daemon uninstall".
[Unit]
Description=Leash enforcer daemon socket (eBPF LSM enforcement for rootless containers)
Documentation=https://github.com/sixtoad/leash/blob/main/docs/ROOTLESS.md

[Socket]
ListenStream=%s
SocketUser=root
SocketGroup=%s
SocketMode=0660
DirectoryMode=0755
RemoveOnStop=yes
Accept=no

[Install]
WantedBy=sockets.target
`, DefaultSocketPath, GroupName)
}

// ServiceUnitText is the systemd service unit. The daemon runs as a dedicated
// system user with CAP_BPF and CAP_PERFMON only, no network, a read-only view
// of the system and a narrow syscall filter.
func ServiceUnitText(bin string) string {
	caps := ""
	for i, c := range Capabilities {
		if i > 0 {
			caps += " "
		}
		caps += c
	}
	return fmt.Sprintf(`# Installed by "leash daemon install". Remove with "sudo leash daemon uninstall".
[Unit]
Description=Leash enforcer daemon (eBPF LSM enforcement for rootless containers)
Documentation=https://github.com/sixtoad/leash/blob/main/docs/ROOTLESS.md
Requires=%[1]s
After=%[1]s

[Service]
Type=simple
ExecStart=%[2]s daemon run
User=%[3]s
Group=%[3]s
AmbientCapabilities=%[4]s
CapabilityBoundingSet=%[4]s
NoNewPrivileges=yes
LimitMEMLOCK=infinity
UMask=0077
LogsDirectory=%[5]s
LogsDirectoryMode=0750
Restart=on-failure
RestartSec=2s
KillMode=control-group

ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
PrivateNetwork=yes
PrivateIPC=yes
ProtectHostname=yes
ProtectClock=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RemoveIPC=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service bpf
SystemCallFilter=~@mount @swap @reboot @module @raw-io @clock @cpu-emulation @obsolete
SystemCallErrorNumber=EPERM
`, SocketUnit, bin, ServiceUser, caps, AuditLogDirName)
}

// UnitPaths returns the installed unit file paths.
func UnitPaths() (socket, service string) {
	return path.Join(UnitDir, SocketUnit), path.Join(UnitDir, ServiceUnit)
}
