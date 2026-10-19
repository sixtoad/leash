package hardening

import (
	"reflect"
	"testing"
)

func TestParsePasswd(t *testing.T) {
	id, err := parsePasswd("alice:x:1000:1001:Alice,,,:/home/alice:/bin/bash")
	if err != nil {
		t.Fatal(err)
	}
	want := &Identity{Name: "alice", UID: 1000, GID: 1001, Home: "/home/alice", Shell: "/bin/bash"}
	if !reflect.DeepEqual(id, want) {
		t.Fatalf("parsePasswd = %+v, want %+v", id, want)
	}
	for _, bad := range []string{"", "alice:x:1000:1001", "alice:x:one:1001::/h:/s", "alice:x:1000:g::/h:/s"} {
		if _, err := parsePasswd(bad); err == nil {
			t.Errorf("parsePasswd(%q) accepted a malformed entry", bad)
		}
	}
}

// UserEnv mirrors runuser -u for a non-root target: HOME, SHELL, USER and
// LOGNAME follow the target user (root's, from sudo, must not leak through);
// everything else is kept.
func TestUserEnv(t *testing.T) {
	env := []string{"HOME=/root", "PATH=/usr/bin", "USER=root", "LOGNAME=root", "SHELL=/bin/zsh", "TERM=xterm", "SUDO_USER=alice"}
	got := UserEnv(env, &Identity{Name: "alice", Home: "/home/alice", Shell: "/bin/bash"})
	want := []string{"PATH=/usr/bin", "TERM=xterm", "SUDO_USER=alice", "HOME=/home/alice", "SHELL=/bin/bash", "USER=alice", "LOGNAME=alice"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("UserEnv = %q, want %q", got, want)
	}
	if got := UserEnv(nil, &Identity{Name: "svc", Home: "/"}); !reflect.DeepEqual(got, []string{"HOME=/", "SHELL=/bin/sh", "USER=svc", "LOGNAME=svc"}) {
		t.Fatalf("UserEnv with no shell = %q", got)
	}
}
