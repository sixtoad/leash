package runner

import "testing"

// --user gives native runs an explicit drop-user so a root process that invokes
// leash directly (no sudo -> no $SUDO_USER) never runs the workload as root by
// accident. Precedence: --user > $SUDO_USER > refuse (not silent root).

func TestParseArgsUserFlag(t *testing.T) {
	t.Parallel()
	opts, err := parseArgs([]string{"--user", "alice", "claude"})
	if err != nil {
		t.Fatalf("parseArgs returned error: %v", err)
	}
	if opts.dropUser != "alice" {
		t.Fatalf("dropUser = %q, want %q", opts.dropUser, "alice")
	}
	if opts.subcommand != "claude" {
		t.Fatalf("subcommand = %q, want %q", opts.subcommand, "claude")
	}
}

func TestParseArgsUserEquals(t *testing.T) {
	t.Parallel()
	opts, err := parseArgs([]string{"--user=alice"})
	if err != nil {
		t.Fatalf("parseArgs returned error: %v", err)
	}
	if opts.dropUser != "alice" {
		t.Fatalf("dropUser = %q, want %q", opts.dropUser, "alice")
	}
}

func TestParseArgsUserMissingValue(t *testing.T) {
	t.Parallel()
	if _, err := parseArgs([]string{"--user"}); err == nil {
		t.Fatalf("parseArgs(--user with no value) = nil error, want error")
	}
}

func TestResolveWorkloadUser(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		euid         int
		dropUser     string
		sudoUser     string
		wantUser     string
		wantExplicit bool
	}{
		{"unprivileged runs as self", 1000, "", "", "", false},
		{"unprivileged ignores flags", 1000, "alice", "bob", "", false},
		{"root + --user drops to it", 0, "alice", "", "alice", false},
		{"--user overrides SUDO_USER", 0, "alice", "bob", "alice", false},
		{"root + SUDO_USER drops to it", 0, "", "bob", "bob", false},
		{"--user root is explicit root", 0, "root", "bob", "", true},
		{"root, no flag, no sudo -> no target", 0, "", "", "", false},
		{"root, SUDO_USER=root -> no target", 0, "", "root", "", false},
		{"whitespace flag trimmed", 0, "  alice  ", "", "alice", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, explicit := resolveWorkloadUser(tt.euid, tt.dropUser, tt.sudoUser)
			if user != tt.wantUser || explicit != tt.wantExplicit {
				t.Fatalf("resolveWorkloadUser(%d, %q, %q) = (%q, %v), want (%q, %v)",
					tt.euid, tt.dropUser, tt.sudoUser, user, explicit, tt.wantUser, tt.wantExplicit)
			}
		})
	}
}

func TestNativeRootWithoutDropTarget(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		euid     int
		dropUser string
		sudoUser string
		want     bool // true => Preflight must refuse
	}{
		{"unprivileged never refused", 1000, "", "", false},
		{"root with --user ok", 0, "alice", "", false},
		{"root with SUDO_USER ok", 0, "", "bob", false},
		{"root with --user root ok (explicit)", 0, "root", "", false},
		{"root, no flag, no sudo -> REFUSE", 0, "", "", true},
		{"root, SUDO_USER=root -> REFUSE", 0, "", "root", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := nativeRootWithoutDropTarget(tt.euid, tt.dropUser, tt.sudoUser); got != tt.want {
				t.Fatalf("nativeRootWithoutDropTarget(%d, %q, %q) = %v, want %v",
					tt.euid, tt.dropUser, tt.sudoUser, got, tt.want)
			}
		})
	}
}
